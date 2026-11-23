package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// maxConfigBytes 是 sshd_config 注入文本的上限，避免超长请求占内存。
const maxConfigBytes = 64 << 10

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	Status     string `json:"status"`
	UptimeS    int64  `json:"uptime_s"`
	Goroutines int    `json:"goroutines"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
// cfg 用指针以支持 ssh.config.set 的进程内改写（lazy 生命周期内生效，不落盘）。
func dispatch(request *pluginapi.Request, cfg *config, logger *slog.Logger) (*pluginapi.Response, bool) {
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID}
	switch request.Method {
	case "kore.shutdown":
		response.Result = json.RawMessage(`{"ok":true}`)
		logger.Info("收到 kore.shutdown，优雅退出")
		return response, true
	case "kore.ping":
		response.Result = encode(pingResult(*cfg))
		return response, false
	case "kore.reload":
		response.Result = json.RawMessage(`{"ok":true,"config_digest":""}`)
		return response, false
	}
	verb, ok := businessVerb(request.Method, cfg.id)
	if !ok {
		response.Error = notFound(request.Method)
		return response, false
	}
	var perr *pluginapi.Error
	switch verb {
	case "status":
		perr = handleStatus(request.Params, cfg, response)
	case "attempts":
		perr = handleAttempts(request.Params, cfg, response)
	case "bans":
		perr = handleBans(request.Params, cfg, response)
	case "config.get":
		perr = handleConfigGet(cfg, response)
	case "config.set":
		perr = handleConfigSet(request.Params, cfg, response)
	case "ban.list":
		perr = handleBanList(request.Params, response)
	case "ban.add", "ban.remove":
		perr = handleBanWrite(request.Params, verb, response)
	default:
		perr = notFound(verb)
	}
	if perr != nil {
		response.Error = perr
		response.Result = nil
	}
	return response, false
}

// businessVerb 把 <id>.<verb> 或裸 <verb> 归一为动词名。
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	switch verb {
	case "status", "attempts", "bans", "config.get", "config.set", "ban.list", "ban.add", "ban.remove":
		return verb, true
	default:
		return "", false
	}
}

// handleStatus 返回只读审计结果 + 防护源检测：配置文本来自请求或宿主注入，不读不写真实 sshd_config；
// 防护源检测只读日志与探测 fail2ban 客户端，不执行任何封禁动作。
func handleStatus(raw json.RawMessage, cfg *config, response *pluginapi.Response) *pluginapi.Error {
	text, perr := parseConfigText(raw, *cfg)
	if perr != nil {
		return perr
	}
	checks := auditConfig(text)
	issues := 0
	for _, c := range checks {
		if !c.Compliant {
			issues++
		}
	}
	response.Result = encode(statusAuditResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
		Checks:     checks,
		Total:      len(checks),
		Issues:     issues,
		Applied:    false,
		Protection: protectionPtr(detectProtection(cfg.guard, guardRootAction)),
	})
	return nil
}

// parseConfigText 校验 ssh.status 入参并取出审计文本：优先请求内联，其次宿主注入。
func parseConfigText(raw json.RawMessage, cfg config) (string, *pluginapi.Error) {
	p := struct {
		SSHDConfig *string `json:"sshd_config"`
	}{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return "", invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", invalidParam("params 解析失败: " + err.Error())
		}
	}
	text := cfg.sshdConfig
	if p.SSHDConfig != nil {
		text = *p.SSHDConfig
	}
	if len(text) > maxConfigBytes {
		return "", invalidParam("sshd_config 超过 64 KiB 上限")
	}
	return text, nil
}

// handleBanList 返回结构化封禁清单；basic 骨架不含真实封禁执行器，恒为空且 applied=false。
func handleBanList(raw json.RawMessage, response *pluginapi.Response) *pluginapi.Error {
	p, perr := parseBanParams(raw)
	if perr != nil {
		return perr
	}
	response.Result = encode(banListResult{
		Bans:    []banEntry{},
		Count:   0,
		Limit:   p.Limit,
		Offset:  p.Offset,
		Applied: false,
	})
	return nil
}

// parseBanParams 校验 ssh.ban.list 入参：limit 1..100、offset ≥0、address 为合法 IP。
func parseBanParams(raw json.RawMessage) (banParams, *pluginapi.Error) {
	p := banParams{Limit: 20}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return p, invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return p, invalidParam("params 解析失败: " + err.Error())
		}
		if p.limitSet() && (p.Limit < 1 || p.Limit > 100) {
			return p, invalidParam("limit 必须在 1..100")
		}
	}
	if p.Offset < 0 {
		return p, invalidParam("offset 不能为负")
	}
	if p.Address != "" && net.ParseIP(p.Address) == nil {
		return p, invalidParam("address 不是合法 IP 地址")
	}
	return p, nil
}

// attempts 窗口与参数边界。
const (
	attemptsMaxWindow   = 7 * 24 * time.Hour
	attemptsDefaultTTL  = 24 * time.Hour
	attemptsDefaultTopN = 10
)

// parseAttemptsParams 校验 ssh.attempts 入参：since RFC3339（≤7 天前，不许未来时间）、
// source 枚举、raw_limit 0..500（未设置取 200）。
func parseAttemptsParams(raw json.RawMessage, now time.Time) (attemptsParams, *pluginapi.Error) {
	p := attemptsParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return p, invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return p, invalidParam("params 解析失败: " + err.Error())
		}
	}
	if p.Since != "" {
		ts, err := time.Parse(time.RFC3339, p.Since)
		if err != nil {
			return p, invalidParam("since 不是合法 RFC3339 时间：" + p.Since)
		}
		if ts.After(now) {
			return p, invalidParam("since 不能晚于当前时间")
		}
		if now.Sub(ts) > attemptsMaxWindow {
			return p, invalidParam("since 最早支持 7 天前（当前时间往前 168 小时）")
		}
	}
	if p.Source != "" && p.Source != "auto" && p.Source != "auth" && p.Source != "journal" {
		return p, invalidParam("source 只支持 auto/auth/journal")
	}
	if p.RawLimit != nil && (*p.RawLimit < 0 || *p.RawLimit > maxRawTailLimit) {
		return p, invalidParam("raw_limit 必须在 0..500")
	}
	return p, nil
}

// resolveAttemptsWindow 解析统计窗口：缺省最近 24h。
func resolveAttemptsWindow(p attemptsParams, now time.Time) (since, until time.Time) {
	until = now
	if p.Since == "" {
		return now.Add(-attemptsDefaultTTL), until
	}
	since, _ = time.Parse(time.RFC3339, p.Since)
	return since, until
}

// handleAttempts 返回 SSH 攻击尝试统计：只读日志解析 + 聚合 + 脱敏原始行尾部。
func handleAttempts(raw json.RawMessage, cfg *config, response *pluginapi.Response) *pluginapi.Error {
	p, perr := parseAttemptsParams(raw, time.Now())
	if perr != nil {
		return perr
	}
	now := time.Now()
	since, until := resolveAttemptsWindow(p, now)
	source := cfg.guard.LogSource
	if p.Source != "" {
		source = p.Source
	}
	g := cfg.guard
	g.LogSource = source
	lines, usedSource, truncated, note := collectLogLines(g, since)
	events := parseEvents(lines)
	stats := aggregateEvents(events, since, until, attemptsDefaultTopN)
	rawLimit := cfg.guard.RawTailLimit
	if p.RawLimit != nil {
		rawLimit = *p.RawLimit
	}
	if usedSource == "auth" && stats.Total == 0 && note == "" {
		note = "日志源 auth（" + g.LogPath + "）未解析出 sshd 记录（可能已轮转）；跨启动历史可用 ssh-guard.config.set 将 log_source 切换为 journal"
	}
	if truncated {
		note = joinNote(note, "日志超过 1 MiB 尾部限读，仅统计最后 1 MiB")
	}
	result := attemptsResult{
		Source:            usedSource,
		Since:             since.Local().Format(time.RFC3339),
		Until:             until.Local().Format(time.RFC3339),
		Total:             stats.Total,
		Failed:            stats.Failed,
		InvalidUsers:      stats.InvalidUsers,
		SuccessfulLogins:  stats.SuccessfulLogins,
		UniqueIPs:         stats.UniqueIPs,
		EventsWithoutTime: stats.EventsWithoutTime,
		TopIPs:            stats.IPStats,
		TimelineHourly:    stats.Timeline,
		RawLines:          len(lines),
		Truncated:         truncated,
		Note:              note,
	}
	if stats.IPStats == nil {
		result.TopIPs = []ipCount{}
	}
	if stats.Timeline == nil {
		result.TimelineHourly = []hourCount{}
	}
	if rawLimit > 0 && len(lines) > 0 {
		tail := lines
		if len(tail) > rawLimit {
			tail = tail[len(tail)-rawLimit:]
		}
		sanitized := make([]string, 0, len(tail))
		for _, line := range tail {
			sanitized = append(sanitized, sanitizeLogLine(line))
		}
		result.RawTail = sanitized
	} else {
		result.RawTail = []string{}
	}
	response.Result = encode(result)
	return nil
}

// joinNote 拼接备注（分号连接）。
func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "；" + b
}

// handleBans 返回当前封禁/可疑 IP 清单：fail2ban 活跃时读其 sshd jail，
// 否则按可疑阈值从 sshd 日志推断（失败 ≥ 阈值/小时）。只读，不执行封禁。
func handleBans(raw json.RawMessage, cfg *config, response *pluginapi.Response) *pluginapi.Error {
	p, perr := parseBansParams(raw)
	if perr != nil {
		return perr
	}
	st := probeFail2ban(guardRootAction)
	if st.Active {
		bans := make([]banItem, 0, len(st.BannedIPs))
		for _, ip := range st.BannedIPs {
			bans = append(bans, banItem{Address: ip, Reason: "fail2ban sshd jail 当前封禁中"})
		}
		response.Result = encode(bansResult{
			Available: true,
			Engine:    "fail2ban",
			Source:    "fail2ban",
			Threshold: cfg.guard.SuspiciousThreshold,
			Bans:      bans,
			Count:     len(bans),
			Applied:   false,
		})
		return nil
	}
	// 降级：从日志推断可疑 IP（最近 24h 窗口内按小时分桶取最大值）。
	source := cfg.guard.LogSource
	if p.Source != "" {
		source = p.Source
	}
	g := cfg.guard
	g.LogSource = source
	lines, usedSource, _, note := collectLogLines(g, time.Now().Add(-24*time.Hour))
	events := parseEvents(lines)
	bans := suspiciousIPs(events, cfg.guard.SuspiciousThreshold)
	if st.Installed && !st.Active {
		note = joinNote(note, "fail2ban 已安装但不可用（需 root/adm 权限访问 socket），清单来自日志推断")
	}
	if usedSource == "none" {
		note = joinNote(note, "无可用日志源，无法推断可疑 IP")
	}
	result := bansResult{
		Available: usedSource != "none",
		Engine:    "sshd",
		Source:    usedSource,
		Threshold: cfg.guard.SuspiciousThreshold,
		Bans:      bans,
		Count:     len(bans),
		Applied:   false,
		Note:      note,
	}
	if result.Bans == nil {
		result.Bans = []banItem{}
	}
	response.Result = encode(result)
	return nil
}

// bansParams 是 ssh.bans 的入参（source 覆盖）。
type bansParams struct {
	Source string `json:"source"`
}

// parseBansParams 校验 ssh.bans 入参。
func parseBansParams(raw json.RawMessage) (bansParams, *pluginapi.Error) {
	p := bansParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return p, invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return p, invalidParam("params 解析失败: " + err.Error())
		}
	}
	if p.Source != "" && p.Source != "auto" && p.Source != "auth" && p.Source != "journal" {
		return p, invalidParam("source 只支持 auto/auth/journal")
	}
	return p, nil
}

// handleConfigGet 返回当前生效配置（含进程内改写后的值）。
func handleConfigGet(cfg *config, response *pluginapi.Response) *pluginapi.Error {
	response.Result = encode(configResult{
		LogPath:             cfg.guard.LogPath,
		LogSource:           cfg.guard.LogSource,
		SuspiciousThreshold: cfg.guard.SuspiciousThreshold,
		RawTailLimit:        cfg.guard.RawTailLimit,
		Persisted:           false,
		Note:                "配置仅当前插件进程会话内生效（lifecycle=lazy 不落盘；进程退出后回到环境变量/缺省值）",
	})
	return nil
}

// handleConfigSet 校验并改写运行期配置（进程内生效，不落盘）；返回改写后的生效配置。
func handleConfigSet(raw json.RawMessage, cfg *config, response *pluginapi.Response) *pluginapi.Error {
	p := configSetParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	if p.LogPath != nil {
		if *p.LogPath == "" {
			return invalidParam("log_path 不能为空")
		}
		if !filepath.IsAbs(*p.LogPath) {
			return invalidParam("log_path 必须是绝对路径")
		}
		cfg.guard.LogPath = *p.LogPath
	}
	if p.LogSource != nil {
		if *p.LogSource != "auto" && *p.LogSource != "auth" && *p.LogSource != "journal" {
			return invalidParam("log_source 只支持 auto/auth/journal")
		}
		cfg.guard.LogSource = *p.LogSource
	}
	if p.SuspiciousThreshold != nil {
		if *p.SuspiciousThreshold < 1 || *p.SuspiciousThreshold > 10000 {
			return invalidParam("suspicious_threshold 必须在 1..10000")
		}
		cfg.guard.SuspiciousThreshold = *p.SuspiciousThreshold
	}
	if p.RawTailLimit != nil {
		if *p.RawTailLimit < 0 || *p.RawTailLimit > maxRawTailLimit {
			return invalidParam("raw_tail_limit 必须在 0..500")
		}
		cfg.guard.RawTailLimit = *p.RawTailLimit
	}
	return handleConfigGet(cfg, response)
}

// needRootCode 是 ADR-0018 的机器可读错误码。
// 用字符串字面量而非 pluginapi 常量：已发布的 pluginapi v0.1.1 尚未包含 E_NEED_ROOT，
// 插件须可对 v0.1.1 构建（GOWORK=off）；内核按 code 字符串匹配，语义一致。
const needRootCode = "E_NEED_ROOT"

// protectionPtr 返回防护结果指针（空引擎也如实返回）。
func protectionPtr(info protectionInfo) *protectionInfo { return &info }

// handleBanWrite 处理 ssh.ban.add / ssh.ban.remove：写操作需要宿主 root 权限，
// 插件以非 root 运行（ADR-0018：插件永不提权），按降级口径返回 E_NEED_ROOT + hint。
// 真实执行走 info.json 声明的 root_actions 经内核代理（systemd transient unit），
// 本轮只声明、不验证成功路径（诚实：不假装执行成功）。
func handleBanWrite(raw json.RawMessage, verb string, response *pluginapi.Response) *pluginapi.Error {
	p := banWriteParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	if net.ParseIP(p.IP) == nil {
		return invalidParam("ip 不是合法 IP 地址")
	}
	action := rootActionFail2banBanIP
	if verb == "ban.remove" {
		action = rootActionFail2banUnbanIP
	}
	detail, _ := json.Marshal(rootHintDetail{
		Hint:       "解封/加封需宿主 root 权限（" + action + " 经内核提权通道以固定 argv 执行 fail2ban-client）。两条路径：① 用 sudo 启动 kored，让内核经 systemd 提权代理执行；② 按 docs/RUNBOOK.md 为插件配置 systemd 提权。fail2ban-banip 为不可逆动作（需一次性 confirm 令牌），fail2ban-unbanip 为恢复性动作（可再次封禁回滚，无需令牌）。声明的 root_actions 见 info.json（需启用时逐条确认）",
		RootAction: action,
	})
	return &pluginapi.Error{
		Code:    needRootCode,
		Message: verb + " 需要宿主 root 权限：插件以非 root 运行，已按 ADR-0018 声明 root_actions 交内核代理，本轮不执行",
		Detail:  detail,
	}
}

// invalidParam 构造 E_INVALID 错误体（§9）。
func invalidParam(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

// notFound 构造 E_NOTFOUND 错误体（§9）。
func notFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
}

// pingResult 组装 kore.ping 结果。
func pingResult(cfg config) statusResult {
	return statusResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
	}
}
