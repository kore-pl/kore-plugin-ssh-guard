package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
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
		perr = handleBanList(request.Params, *cfg, response)
	case "suggest":
		perr = handleSuggest(request.Params, response)
	case "whitelist":
		perr = handleWhitelist(*cfg, response)
	case "whitelist.add", "whitelist.remove":
		perr = handleWhitelistWrite(request.Params, verb, *cfg, response)
	case "ban.add", "ban.remove":
		perr = handleBanWrite(request.Params, verb, guardRootAction, *cfg, response)
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
	case "status", "attempts", "bans", "config.get", "config.set", "ban.list", "ban.add", "ban.remove", "suggest",
		"whitelist", "whitelist.add", "whitelist.remove":
		return verb, true
	default:
		return "", false
	}
}

// handleStatus 返回只读审计结果 + 防护源检测：配置文本来自请求或宿主注入，不读不写真实 sshd_config；
// 防护源检测只读日志与探测 fail2ban 客户端，不执行任何封禁动作。
func handleStatus(raw json.RawMessage, cfg *config, response *pluginapi.Response) *pluginapi.Error {
	text, source, perr := parseConfigText(raw, *cfg)
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
	result := statusAuditResult{
		Status:       "ready",
		UptimeS:      int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines:   runtime.NumGoroutine(),
		Checks:       checks,
		Total:        len(checks),
		Issues:       issues,
		Applied:      false,
		Protection:   protectionPtr(detectProtection(cfg.guard, guardRootAction)),
		ConfigSource: source,
	}
	if source == configSourceNone {
		result.Note = "未拿到 sshd_config 文本（config_source=none）：插件以非 root 运行，读不了 /etc/ssh/sshd_config" +
			"（通常 0600 root:root），提权通道的命令白名单也没有 cat/sshd 形状；" +
			"上面 \"(未设置)\" 只代表本次没有文本，不代表宿主配置不合规。" +
			"请用 params.sshd_config 注入文本，或由启动方经 KORE_SSHD_CONFIG 注入后再审计"
	}
	response.Result = encode(result)
	return nil
}

// 审计文本来源口径（config_source）：请求内联 > 宿主注入 > 无。
const (
	configSourceRequest = "request"
	configSourceHost    = "host"
	configSourceNone    = "none"
)

// parseConfigText 校验 ssh.status 入参并取出审计文本与来源：优先请求内联，其次宿主注入。
// 本函数**从不打开** /etc/ssh/sshd_config（降权后进程读不到，见 statusAuditResult.ConfigSource）。
func parseConfigText(raw json.RawMessage, cfg config) (string, string, *pluginapi.Error) {
	p := struct {
		SSHDConfig *string `json:"sshd_config"`
	}{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return "", "", invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", "", invalidParam("params 解析失败: " + err.Error())
		}
	}
	text := cfg.sshdConfig
	source := configSourceHost
	if p.SSHDConfig != nil {
		text = *p.SSHDConfig
		source = configSourceRequest
	}
	if len(text) > maxConfigBytes {
		return "", "", invalidParam("sshd_config 超过 64 KiB 上限")
	}
	if text == "" {
		source = configSourceNone
	}
	return text, source, nil
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
		return p, invalidParam("address 不是合法 IP 地址（例：203.0.113.7）")
	}
	if p.Source != "" && p.Source != "auto" && p.Source != "auth" && p.Source != "journal" {
		return p, invalidParam("source 只支持 auto/auth/journal")
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
		Kinds:             stats.Kinds,
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
	// 与 ban.list 共用同一套组装逻辑（同一份事实、同一套来源/触发规则口径），
	// 差别只在形状：bans 是旧契约（阈值 + 引擎摘要），ban.list 是可分页的详细清单。
	items, source, engine, available, note := collectBanItems(*cfg, p.Source)
	response.Result = encode(bansResult{
		Available: available,
		Engine:    engine,
		Source:    source,
		Threshold: cfg.guard.SuspiciousThreshold,
		Bans:      items,
		Count:     len(items),
		Applied:   false,
		Note:      note,
	})
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
		BantimeS:            cfg.guard.BantimeS,
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
	if p.BantimeS != nil {
		if *p.BantimeS < 0 || *p.BantimeS > maxBantimeS {
			return invalidParam("bantime_s 必须在 0..31536000（0 表示未知，不推算剩余时长）")
		}
		cfg.guard.BantimeS = *p.BantimeS
	}
	return handleConfigGet(cfg, response)
}

// needRootCode 是 ADR-0018 的机器可读错误码。
// 用字符串字面量而非 pluginapi 常量：已发布的 pluginapi v0.1.1 尚未包含 E_NEED_ROOT，
// 插件须可对 v0.1.1 构建（GOWORK=off）；内核按 code 字符串匹配，语义一致。
const needRootCode = "E_NEED_ROOT"

// protectionPtr 返回防护结果指针（空引擎也如实返回）。
func protectionPtr(info protectionInfo) *protectionInfo { return &info }

// handleBanWrite 处理 ssh.ban.add / ssh.ban.remove：**真实经内核提权通道执行**
// `fail2ban-client set sshd banip|unbanip <ip>`（argv 由 info.json 的 root_actions 固定，
// IP 只能作为追加参数；内核还会按协议 shapeIPOrCIDR 复核）。
//
// 降权口径（ADR-0018）：插件以非 root 运行且永不提权，命令一律由内核经 systemd-run 代理。
// 通道三要素（KORE_KERNEL_SOCK / KORE_PLUGIN_TOKEN / KORE_PLUGIN_ID）缺一时返回 E_NEED_ROOT +
// 可操作 hint，不假装成功；执行后必须回读封禁清单证明生效（Verified），回读不可用则显式说明。
func handleBanWrite(raw json.RawMessage, verb string, call rootActionFunc, cfg config, response *pluginapi.Response) *pluginapi.Error {
	p := banWriteParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	// IP 校验是注入防线：net.ParseIP 只接受纯 IP 字面量（分号 / 空格 / $() / 换行 / CIDR 一律拒绝），
	// 通过后再归一化成规范写法，作为**唯一**追加参数交给内核。
	parsed := net.ParseIP(strings.TrimSpace(p.IP))
	if parsed == nil {
		return invalidParam("ip 不是合法 IP 地址")
	}
	address := parsed.String()
	action := rootActionFail2banBanIP
	if verb == "ban.remove" {
		action = rootActionFail2banUnbanIP
	}
	// 白名单前置门（fail-closed）：要封的 IP 在白名单里 → 直接拒绝，命令根本不下发。
	// 放在提权通道检查之前，是为了让"防误封"在**任何环境**（包括没 root 的调试实例）都成立，
	// 且错误原因指向用户真正该改的地方（白名单），而不是"没权限"。
	if verb == "ban.add" && cfg.whitelist.Contains(address) {
		return whitelistRefusal(verb, address)
	}
	if call == nil {
		detail, _ := json.Marshal(rootHintDetail{
			Hint: "封禁/解封需宿主 root 权限（" + action + " 经内核提权通道以固定 argv 执行 fail2ban-client）。" +
				"两条路径：① 用 sudo 启动 kored，让内核经 systemd 提权代理执行；② 按 docs/RUNBOOK.md 为插件配置 systemd 提权。" +
				"当前进程未拿到提权通道三要素（KORE_KERNEL_SOCK / KORE_PLUGIN_TOKEN / KORE_PLUGIN_ID 缺一），插件不会进程内提权",
			RootAction: action,
		})
		return &pluginapi.Error{
			Code:    needRootCode,
			Message: verb + " 需要宿主 root 权限：内核未注入 root-action 通道，未执行任何命令",
			Detail:  detail,
		}
	}
	// 不可回滚动作（fail2ban-banip）必须携带一次性 confirm 令牌：由管理员会话向内核
	// confirm-token 端点申请，插件只转发、不自行签发（与内核 ConfirmStore 同错误码）。
	confirm := ""
	if action == rootActionFail2banBanIP {
		confirm = strings.TrimSpace(p.Confirm)
		if confirm == "" {
			return confirmRequiredError(action)
		}
	}
	out, err := call(action, []string{address}, confirm)
	if err != nil {
		return rootChannelError(action, err)
	}
	if out.ExitCode != 0 {
		return banExecFailed(action, address, out)
	}
	// 封禁成功才记账：账本只服务「封禁时间/剩余时长」展示，失败的动作不记。
	if verb == "ban.add" {
		cfg.banledger.Record(address, time.Now(), "")
	} else {
		cfg.banledger.Forget(address)
	}
	banned, count, verified, note := verifyBan(call, address, verb)
	response.Result = encode(banWriteResult{
		IP:          address,
		Action:      action,
		Applied:     true,
		ExitCode:    out.ExitCode,
		Stdout:      firstLine(out.Stdout),
		Stderr:      firstLine(out.Stderr),
		Banned:      banned,
		BannedCount: count,
		Verified:    verified,
		Note:        note,
	})
	return nil
}

// confirmRequiredError 是「不可回滚动作缺一次性令牌」的显式拒绝（与内核 ConfirmStore 同错误码）。
func confirmRequiredError(action string) *pluginapi.Error {
	detail, _ := json.Marshal(rootHintDetail{
		Hint: "先在管理员会话调用 GET /api/v1/plugins/ssh-guard/root-action/" + action +
			"/confirm-token 取一次性令牌（5 分钟有效、一次即废），再把它放进本方法的 params.confirm；" +
			"插件只转发、不自行签发。ban.remove（unbanip）是恢复性动作，无需令牌",
		RootAction: action,
	})
	return &pluginapi.Error{
		Code:    pluginapi.E_UNAUTHORIZED,
		Message: "ban.add 是不可回滚动作（" + action + "），缺少 confirm 一次性令牌，未执行",
		Detail:  detail,
	}
}

// rootChannelError 把提权通道错误映射为协议错误码：保留内核错误码（E_NEED_ROOT /
// E_NO_SYSTEMD / E_UNAUTHORIZED），其余归 E_INTERNAL；错误文本原样保留供排障（不吞错）。
func rootChannelError(action string, err error) *pluginapi.Error {
	message := err.Error()
	for _, code := range []string{needRootCode, pluginapi.E_NO_SYSTEMD, pluginapi.E_UNAUTHORIZED} {
		if strings.Contains(message, code) {
			return &pluginapi.Error{
				Code:    code,
				Message: "经内核提权通道执行 " + action + " 被拒绝：" + message,
			}
		}
	}
	return &pluginapi.Error{
		Code:    pluginapi.E_INTERNAL,
		Message: "经内核提权通道执行 " + action + " 失败：" + message,
	}
}

// banExecFailed 是「命令执行了但退出码非 0」的显式失败（绝不返回 applied=true）。
func banExecFailed(action, address string, out rootActionOutput) *pluginapi.Error {
	reason := firstLine(out.Stderr)
	if reason == "" {
		reason = firstLine(out.Stdout)
	}
	message := "经内核提权通道执行 " + action + "（" + address + "）失败：退出码 " + strconv.Itoa(out.ExitCode)
	if reason != "" {
		message += "：" + reason
	}
	detail, _ := json.Marshal(banExecErrorDetail{
		ExitCode: out.ExitCode,
		Stdout:   firstLine(out.Stdout),
		Stderr:   firstLine(out.Stderr),
	})
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: message, Detail: detail}
}

// verifyBan 在执行后用 fail2ban-status 动作回读封禁清单，判断状态是否按预期变化。
// 返回 (清单, 封禁数, 是否与预期一致, 说明)；回读不可用时 verified=false 并给出原因。
func verifyBan(call rootActionFunc, address, verb string) (banned []string, count int, verified bool, note string) {
	st := probeFail2ban(call)
	banned = st.BannedIPs
	if banned == nil {
		banned = []string{}
	}
	count = st.CurrentlyBanned
	if !st.Active {
		reason := st.ProbeErr
		if reason == "" {
			reason = "fail2ban 状态不可读（未安装，或提权通道不可用）"
		}
		return banned, 0, false, "命令已执行，但回读失败、无法确认是否生效：" + reason +
			"；请用 fail2ban-client status sshd 在宿主人工核对"
	}
	found := containsIP(banned, address)
	wantBanned := verb == "ban.add"
	if found != wantBanned {
		state := "已不在封禁列表"
		if found {
			state = "仍在封禁列表"
		}
		return banned, count, false, "回读与预期不符：执行后该 IP " + state +
			"（fail2ban sshd jail 当前 " + strconv.Itoa(count) + " 条）"
	}
	return banned, count, true, ""
}

// containsIP 报告清单里是否有与 address 等价的 IP：按解析后语义比较，
// 兼容 IPv4-mapped IPv6 与不同写法（如 203.0.113.7 与 ::ffff:203.0.113.7）。
func containsIP(list []string, address string) bool {
	target := net.ParseIP(address)
	if target == nil {
		return false
	}
	for _, item := range list {
		if ip := net.ParseIP(item); ip != nil && ip.Equal(target) {
			return true
		}
	}
	return false
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
