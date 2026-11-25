package main

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// 封禁清单的事实来源。
const (
	// banSourceFail2ban 表示这条记录是 fail2ban 真的封着的 IP（可解封）。
	banSourceFail2ban = "fail2ban"
	// banSourceLog 表示这条记录只是从日志推断的"可疑 IP"，并没有被真封。
	banSourceLog = "log"
)

// 封禁可视化 / 白名单的窗口与上限口径。
const (
	// banEnrichWindow 是"触发规则/封禁时刻"富化用的日志窗口（与 24h 统计口径一致）。
	banEnrichWindow = 24 * time.Hour
	// whitelistLogWindow 是"最近成功登录 IP"候选的日志窗口（7 天：够认出长期运维的出口 IP）。
	whitelistLogWindow = 7 * 24 * time.Hour
	// whitelistCandidateLimit 是候选 IP 条数上限（只收最近的几条，避免一屏罗列历史来源）。
	whitelistCandidateLimit = 5
	// whitelistNoteMax 是白名单备注的长度上限（备注进 UI，挡住超长文本灌页）。
	whitelistNoteMax = 80
)

// collectBanItems 组装封禁清单：fail2ban 活跃时取 jail 当前封禁（真实封禁），
// 否则按可疑阈值从 sshd 日志推断，两者都做同一套"来源/触发规则/封禁时刻"富化。
//
// 末尾固定做三件事：① 白名单标注（whitelisted）② 有界排序（失败数 desc → 地址 asc，
// 保证分页稳定）③ 如实给 note（日志不可读、回读失败等降级原因，不静默）。
func collectBanItems(cfg config, sourceOverride string) (items []banItem, usedSource, engine string, available bool, note string) {
	st := probeFail2ban(guardRootAction)
	g := cfg.guard
	if sourceOverride != "" {
		g.LogSource = sourceOverride
	}
	since := time.Now().Add(-banEnrichWindow)
	lines, logSource, _, logNote := collectLogLines(g, since)
	events := parseEvents(lines)
	facts := indexIPFacts(events)

	items = make([]banItem, 0, 8)
	if st.Active {
		usedSource, engine, available = banSourceFail2ban, "fail2ban", true
		// fail2ban 的 sshd jail 没有 per-IP 触发规则/时刻可读（`get <jail> ...` 不在
		// 内核提权形状表内），所以用日志里该 IP 的失败次数与最后失败时刻做**可解释**富化，
		// 并在 banned_at_source 里标明是"推断"，不把推断写成事实。
		facts0 := facts
		for _, ip := range st.BannedIPs {
			items = append(items, buildBanItem(cfg, ip, banSourceFail2ban,
				"fail2ban sshd jail 命中（"+strconv.Itoa(cfg.guard.SuspiciousThreshold)+" 次/小时以上的失败会触发，实际阈值由宿主 jail 配置决定）",
				facts0[ip]))
		}
		if logSource == "none" {
			note = "读不到 SSH 日志，封禁原因只能显示 fail2ban jail 口径（触发规则/失败次数为空）"
		}
	} else {
		usedSource, engine = logSource, "sshd"
		available = logSource != "none"
		note = logNote
		facts0 := facts
		for _, suspicious := range suspiciousIPs(events, cfg.guard.SuspiciousThreshold) {
			item := buildBanItem(cfg, suspicious.Address, banSourceLog, suspicious.Reason, facts0[suspicious.Address])
			item.Failures = suspicious.Failures
			if suspicious.LastSeen != "" {
				item.LastSeen = suspicious.LastSeen
			}
			// 推断条目没有真封禁，也就不存在"剩余时长"（留空，不编造到期时间）。
			items = append(items, item)
		}
		if st.Installed && !st.Active {
			note = joinNote(note, "fail2ban 已安装但不可用（需 root/adm 权限访问 socket），清单来自日志推断")
		}
		if logSource == "none" {
			note = joinNote(note, "无可用日志源，无法推断可疑 IP")
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Failures != items[j].Failures {
			return items[i].Failures > items[j].Failures
		}
		return items[i].Address < items[j].Address
	})
	return items, usedSource, engine, available, note
}

// buildBanItem 组装单条封禁记录（来源 / 触发规则 / 封禁时刻 / 剩余时长 / 白名单标注）。
func buildBanItem(cfg config, ip, source, rule string, facts *ipFacts) banItem {
	item := banItem{
		Address:     ip,
		Source:      source,
		Rule:        rule,
		Whitelisted: cfg.whitelist.Contains(ip),
	}
	if facts != nil {
		item.Failures = facts.Failures
		if facts.HasFail {
			item.LastSeen = facts.LastFail.Local().Format(time.RFC3339)
		}
	}
	switch source {
	case banSourceFail2ban:
		item.Reason = "fail2ban sshd jail 当前封禁中"
		item.BannedAtSource = "unknown"
		// 封禁时刻：本插件自己封的（observed，精确）优先；否则用日志里该 IP 的最后一次
		// 失败（log，推断——fail2ban 正好在失败阈值处触发封禁）。
		if at, ok := cfg.banledger.At(ip); ok {
			item.BannedAt = at.Local().Format(time.RFC3339)
			item.BannedAtSource = "observed"
			item.applyRemaining(cfg, at, time.Now())
		} else if facts != nil && facts.HasFail {
			item.BannedAt = facts.LastFail.Local().Format(time.RFC3339)
			item.BannedAtSource = "log"
			item.applyRemaining(cfg, facts.LastFail, time.Now())
		}
	default:
		item.Reason = rule
		if facts != nil && facts.HasFail {
			item.BannedAt = facts.LastFail.Local().Format(time.RFC3339)
			item.BannedAtSource = "log"
		}
	}
	if item.BannedAt == "" {
		item.BannedAtSource = "unknown"
	}
	return item
}

// applyRemaining 在「已知封禁时刻 + 已知 fail2ban bantime」时推算剩余秒数。
// 两个前提缺一就留空（RemainingS=nil）：宁可显示"未知"，也不编一个到期时间。
func (item *banItem) applyRemaining(cfg config, bannedAt, now time.Time) {
	bantime := cfg.guard.BantimeS
	if bantime <= 0 || bannedAt.IsZero() {
		return
	}
	left := int64(bantime) - int64(now.Sub(bannedAt).Seconds())
	if left < 0 {
		left = 0
	}
	item.RemainingS = &left
}

// handleBanList 返回可分页的封禁清单（ban.list）：真实来源 + 触发规则 + 封禁时刻 +
// 剩余时长 + 白名单标注，支持按地址精确过滤。
func handleBanList(raw json.RawMessage, cfg config, response *pluginapi.Response) *pluginapi.Error {
	p, perr := parseBanParams(raw)
	if perr != nil {
		return perr
	}
	items, source, engine, available, note := collectBanItems(cfg, p.Source)
	total := len(items)
	if p.Address != "" {
		if target, ok := canonicalIP(p.Address); ok {
			filtered := make([]banItem, 0, 1)
			for _, item := range items {
				if item.Address == target {
					filtered = append(filtered, item)
				}
			}
			items = filtered
		}
	}
	whitelisted := 0
	for _, item := range items {
		if item.Whitelisted {
			whitelisted++
		}
	}
	page := items
	if p.Offset > 0 {
		if p.Offset >= len(page) {
			page = []banItem{}
		} else {
			page = page[p.Offset:]
		}
	}
	if len(page) > p.Limit {
		page = page[:p.Limit]
	}
	if page == nil {
		page = []banItem{}
	}
	response.Result = encode(banListResult{
		Bans:        page,
		Count:       len(items),
		Total:       total,
		Limit:       p.Limit,
		Offset:      p.Offset,
		Engine:      engine,
		Source:      source,
		Available:   available,
		Applied:     false,
		Whitelisted: whitelisted,
		Note:        note,
	})
	return nil
}

// handleWhitelist 返回白名单现状 + 「你的 IP」候选 + 自锁告警（ssh.whitelist，只读）。
func handleWhitelist(cfg config, response *pluginapi.Response) *pluginapi.Error {
	entries := cfg.whitelist.Entries()
	g := cfg.guard
	lines, logSource, _, _ := collectLogLines(g, time.Now().Add(-whitelistLogWindow))
	candidates := loginCandidates(indexIPFacts(parseEvents(lines)), whitelistCandidateLimit)
	current := ""
	if len(candidates) > 0 {
		current = candidates[0].IP
	}
	banned := []string{}
	if st := probeFail2ban(guardRootAction); st.Active {
		for _, ip := range st.BannedIPs {
			if cfg.whitelist.Contains(ip) {
				banned = append(banned, ip)
			}
		}
	}
	sort.Strings(banned)
	response.Result = encode(whitelistResult{
		Entries:            entries,
		Count:              len(entries),
		Persisted:          cfg.whitelist.Persisted(),
		Path:               cfg.whitelist.Path(),
		Note:               cfg.whitelist.Note(),
		Candidates:         candidates,
		CurrentIP:          current,
		CurrentWhitelisted: current != "" && cfg.whitelist.Contains(current),
		BannedWhitelisted:  banned,
		LogSource:          logSource,
	})
	return nil
}

// whitelistWriteResult 是白名单写操作的显式结果：动作 + 一次回读的完整现状。
type whitelistWriteResult struct {
	IP        string          `json:"ip"`
	Added     bool            `json:"added"`
	Removed   bool            `json:"removed"`
	Whitelist whitelistResult `json:"whitelist"`
	Note      string          `json:"note,omitempty"`
}

// handleWhitelistWrite 处理 ssh.whitelist.add / ssh.whitelist.remove。
//
// 白名单是**保护性**配置（把某个 IP 从封禁范围里摘出去，降低误封风险），不是破坏性
// 动作：因此不要求一次性 confirm 令牌，改由页面做"明确提示 + 二次确认"（前端责任）。
// 服务端只做三件必须做的事：IP 规范化校验、幂等写、写盘失败如实回报。
func handleWhitelistWrite(raw json.RawMessage, verb string, cfg config, response *pluginapi.Response) *pluginapi.Error {
	params := whitelistWriteParams{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &params); err != nil {
			return invalidParam("params 解析失败：" + err.Error())
		}
	}
	address, ok := canonicalIP(params.IP)
	if !ok {
		return invalidParam("ip 不是合法 IP 地址（例：203.0.113.7；白名单不接受网段）")
	}
	result := whitelistWriteResult{IP: address}
	switch verb {
	case "whitelist.add":
		note := sanitizeNote(params.Note)
		entry, added, err := cfg.whitelist.Add(address, note, time.Now())
		result.Added = added
		if err != nil {
			// 内存已生效、写盘失败：如实说明"本次运行内有效"，不假装已持久化。
			result.Note = "白名单已在本次运行内生效，但保存到磁盘失败：" + err.Error() +
				"；插件重启后会丢失，请检查插件数据目录权限"
		}
		if !added {
			result.Note = "该 IP 早在白名单里（加入时间 " + entry.AddedAt + "），未重复添加"
		}
	case "whitelist.remove":
		if cfg.whitelist.Remove(address) {
			result.Removed = true
		} else {
			result.Note = "该 IP 不在白名单里，无需移除"
		}
	}
	if perr := handleWhitelist(cfg, response); perr != nil {
		return perr
	}
	var current whitelistResult
	if err := json.Unmarshal(response.Result, &current); err != nil {
		return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: "白名单回读失败：" + err.Error()}
	}
	result.Whitelist = current
	response.Result = encode(result)
	return nil
}

// sanitizeNote 清洗白名单备注：去控制字符、裁到上限（备注只用于展示，不参与判断）。
func sanitizeNote(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, raw)
	cleaned = strings.TrimSpace(cleaned)
	if len([]rune(cleaned)) > whitelistNoteMax {
		cleaned = string([]rune(cleaned)[:whitelistNoteMax])
	}
	return cleaned
}

// whitelistRefusal 是"要封的 IP 在白名单里"的显式拒绝（E_CONFLICT，fail-closed）。
//
// 为什么在插件侧硬拦：白名单的全部价值就是"防误封自己"。若只靠页面判断，一次
// 手写 API 调用 / 旧页面 / 另一个标签页就能绕过；这里拒绝后命令根本不下发到内核
// 提权通道，fail2ban 也就不会被调用。
func whitelistRefusal(verb, address string) *pluginapi.Error {
	detail, _ := json.Marshal(struct {
		IP          string `json:"ip"`
		Whitelisted bool   `json:"whitelisted"`
		Hint        string `json:"hint"`
	}{
		IP:          address,
		Whitelisted: true,
		Hint: "这个 IP 在白名单里，说明它是你自己（或受信运维）的来源地址；" +
			"要封它请先在「白名单」里移除，再重新封禁。插件不会替你绕过白名单。",
	})
	return &pluginapi.Error{
		Code:    pluginapi.E_CONFLICT,
		Message: verb + " 被拒绝：" + address + " 在白名单里（防误封），未执行任何命令",
		Detail:  detail,
	}
}

// parseWhitelistIP 是白名单入参的 IP 归一化入口（供测试与 handler 共用）。
func parseWhitelistIP(raw string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}
