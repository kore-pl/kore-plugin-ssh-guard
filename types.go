package main

import "encoding/json"

// statusAuditResult 是 ssh.status 的结构化结果。
// 只给审计建议，不落盘、不改 sshd_config（Applied 恒为 false）。
type statusAuditResult struct {
	Status     string       `json:"status"`
	UptimeS    int64        `json:"uptime_s"`
	Goroutines int          `json:"goroutines"`
	Checks     []auditCheck `json:"checks"`
	Total      int          `json:"total"`
	Issues     int          `json:"issues"`
	Applied    bool         `json:"applied"`
	// Protection 是防护源检测结果（fail2ban / sshd 日志降级）；0.2.0 新增。
	Protection *protectionInfo `json:"protection,omitempty"`
	// ConfigSource 是本次审计文本的来源，取值 request（params.sshd_config）/
	// host（supervisor 注入的 KORE_SSHD_CONFIG）/ none（未提供）；0.2.2 新增。
	//
	// 为什么需要它：降权后插件进程（非 root）读不了真实 /etc/ssh/sshd_config（通常 0600 root:root），
	// 而 root_actions 的命令白名单里没有 cat/sshd 形状（协议 §3.1.4），所以"没拿到文本"必须
	// 显式暴露成 none + note，而不是让调用方把 5 条"(未设置)"误读成"宿主配置不合规"。
	ConfigSource string `json:"config_source"`
	// Note 是可操作说明（仅在配置文本缺失等降级场景非空）。
	Note string `json:"note,omitempty"`
}

// auditCheck 是单条配置审计项：指令名、当前值、是否合规、修复建议。
type auditCheck struct {
	Directive   string `json:"directive"`
	Current     string `json:"current"`
	Compliant   bool   `json:"compliant"`
	Recommended string `json:"recommended"`
	Advice      string `json:"advice"`
}

// banListResult 是 ssh.ban.list 的结构化结果：真实封禁清单（fail2ban jail 当前封禁）
// 或降级态的日志推断候选，两者共用 banItem 形状，source 字段区分事实来源。
type banListResult struct {
	Bans      []banItem `json:"bans"`
	Count     int       `json:"count"`
	Total     int       `json:"total"`
	Limit     int       `json:"limit"`
	Offset    int       `json:"offset"`
	Engine    string    `json:"engine"` // fail2ban | sshd | none
	Source    string    `json:"source"` // fail2ban | auth | journal | none
	Available bool      `json:"available"`
	Applied   bool      `json:"applied"`
	// Whitelisted 是清单里落在白名单的条数：>0 说明"白名单 IP 仍被封着"（自锁风险），
	// 页面要给出醒目的一键解封入口。
	Whitelisted int    `json:"whitelisted"`
	Note        string `json:"note,omitempty"`
}

// banParams 是 ssh.ban.list 的入参；Limit 有默认值，用一个指针区分"未设置"与"显式 0"。
type banParams struct {
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	Address string `json:"address"`
	// Source 覆盖日志源（auto|auth|journal），与 ssh.bans 同口径。
	Source string `json:"source"`
	limit  *int   `json:"-"`
}

// limitSet 报告 limit 是否被显式设置（显式 0 也必须判为越界）。
func (p banParams) limitSet() bool { return p.limit != nil }

// UnmarshalJSON 让 banParams 记录 limit 是否出现在请求里。
func (p *banParams) UnmarshalJSON(raw []byte) error {
	type alias struct {
		Limit   *int   `json:"limit"`
		Offset  int    `json:"offset"`
		Address string `json:"address"`
		Source  string `json:"source"`
	}
	var a alias
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	p.Offset = a.Offset
	p.Address = a.Address
	p.Source = a.Source
	p.limit = a.Limit
	if a.Limit != nil {
		p.Limit = *a.Limit
	} else {
		p.Limit = 20
	}
	return nil
}

// protectionInfo 是 ssh.status 里 protection 字段的防护源检测结果（ADR-0018 降级口径）。
//
// EngineVersion（JSON 名 version）：0.2.1 起状态读取统一经 root 通道的
// `fail2ban-client status sshd` 固定 argv，其输出不含版本号；不为展示字段新增提权动作，
// 故该字段保留为空串（schema 兼容，不编造版本）。需要版本时由运维在宿主执行
// `fail2ban-client --version` 查看。
type protectionInfo struct {
	Available         bool   `json:"available"`
	Engine            string `json:"engine"` // "fail2ban" | "sshd" | "none"
	EngineVersion     string `json:"version,omitempty"`
	Fail2banInstalled bool   `json:"fail2ban_installed"`
	Fail2banActive    bool   `json:"fail2ban_active"`
	BannedCount       int    `json:"banned_count"`
	Failed24h         int    `json:"failed_24h"`
	LogSource         string `json:"log_source"` // "auth" | "journal" | "none"
	Hint              string `json:"hint,omitempty"`
}

// attemptsParams 是 ssh.attempts 的入参；RawLimit 用指针区分"未设置"与显式 0。
type attemptsParams struct {
	Since    string `json:"since"`  // RFC3339；缺省最近 24h，最早支持 7 天前
	Source   string `json:"source"` // auto | auth | journal；缺省取运行配置
	RawLimit *int   `json:"raw_limit"`
}

// ipCount 是 top_ips 的单条来源 IP 统计。
type ipCount struct {
	IP      string `json:"ip"`
	Failed  int    `json:"failed"`
	Success int    `json:"success"`
	Total   int    `json:"total"`
}

// hourCount 是 timeline_hourly 的单小时桶（本地时间）。
type hourCount struct {
	Hour    string `json:"hour"`
	Failed  int    `json:"failed"`
	Success int    `json:"success"`
}

// failureKindCount 是失败类型的聚合条目（"谁在怎么试"）。
//
// 类型只来自日志里真实存在的文本族，不自造分类：密码认证失败（Failed password）、
// 用户名探测（Invalid user）、重复认证超限（maximum authentication attempts exceeded）。
type failureKindCount struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Count int    `json:"count"`
	// Ratio 是占 failed 的整数百分比（0–100）。
	Ratio int `json:"ratio"`
}

// attemptsResult 是 ssh.attempts 的结构化结果；raw_tail 已做用户名脱敏。
type attemptsResult struct {
	Source            string      `json:"source"`
	Since             string      `json:"since"`
	Until             string      `json:"until"`
	Total             int         `json:"total"`
	Failed            int         `json:"failed"`
	InvalidUsers      int         `json:"invalid_users"`
	SuccessfulLogins  int         `json:"successful_logins"`
	UniqueIPs         int         `json:"unique_ips"`
	EventsWithoutTime int         `json:"events_without_time"`
	TopIPs            []ipCount   `json:"top_ips"`
	TimelineHourly    []hourCount `json:"timeline_hourly"`
	// Kinds 是按失败类型聚合的分布（按次数降序）；没有失败时为 null。
	Kinds     []failureKindCount `json:"kinds,omitempty"`
	RawLines  int                `json:"raw_lines"`
	RawTail   []string           `json:"raw_tail"`
	Truncated bool               `json:"truncated"`
	Note      string             `json:"note,omitempty"`
}

// banItem 是封禁/可疑 IP 清单的单条记录（fail2ban 实封或日志推断）。
//
// "封禁可视化"的口径（0.4.0）：一条记录要能回答运维最常问的五件事——谁被拦了
// （address）、凭什么被拦（rule/reason）、封了多久（banned_at）、还剩多久
// （remaining_s，读不到时为 null，不做假值）、我在名单里吗（whitelisted）。
type banItem struct {
	Address  string `json:"address"`
	Failures int    `json:"failures"`
	LastSeen string `json:"last_seen,omitempty"`
	Reason   string `json:"reason"`
	// Source 是事实来源："fail2ban"（jail 当前封禁）| "log"（日志推断的可疑 IP，没有真封）。
	Source string `json:"source"`
	// Rule 是触发规则（一句人话，含阈值/窗口/jail 名）。
	Rule string `json:"rule,omitempty"`
	// BannedAt 是封禁时刻（本地 RFC3339）；BannedAtSource 说明来源：
	// "observed"=本插件执行封禁时自己记下的时刻、"log"=该 IP 在日志里的最后一次失败
	// （fail2ban 正好在失败阈值处封禁，属推断）、"unknown"=读不到。
	BannedAt       string `json:"banned_at,omitempty"`
	BannedAtSource string `json:"banned_at_source,omitempty"`
	// RemainingS 是剩余封禁秒数；nil 表示读不到（fail2ban 的 bantime 不在内核提权
	// 形状表内，插件不做没有依据的推测）。运维在页面填入 bantime 后才可推算。
	RemainingS *int64 `json:"remaining_s,omitempty"`
	// Whitelisted 表示该 IP 在白名单里（此时它本不该被封；页面提示一键解封）。
	Whitelisted bool `json:"whitelisted"`
}

// bansResult 是 ssh.bans 的结构化结果；applied 恒为 false（本插件不执行封禁）。
type bansResult struct {
	Available bool      `json:"available"`
	Engine    string    `json:"engine"`
	Source    string    `json:"source"` // "fail2ban" | "auth" | "journal" | "none"
	Threshold int       `json:"threshold"`
	Bans      []banItem `json:"bans"`
	Count     int       `json:"count"`
	Applied   bool      `json:"applied"`
	Note      string    `json:"note,omitempty"`
}

// configResult 是 ssh.config.get / ssh.config.set 的结果。
type configResult struct {
	LogPath             string `json:"log_path"`
	LogSource           string `json:"log_source"`
	SuspiciousThreshold int    `json:"suspicious_threshold"`
	RawTailLimit        int    `json:"raw_tail_limit"`
	// BantimeS 是 fail2ban 的封禁时长（秒；0 = 未知/不自动到期）。插件读不到宿主
	// fail2ban 的 bantime（不在提权形状表内），由运维在页面填写后用于推算剩余时长。
	BantimeS  int    `json:"bantime_s"`
	Persisted bool   `json:"persisted"`
	Note      string `json:"note"`
}

// configSetParams 是 ssh.config.set 的入参；全指针字段，未设置 = 不修改。
type configSetParams struct {
	LogPath             *string `json:"log_path"`
	LogSource           *string `json:"log_source"`
	SuspiciousThreshold *int    `json:"suspicious_threshold"`
	RawTailLimit        *int    `json:"raw_tail_limit"`
	BantimeS            *int    `json:"bantime_s"`
}

// whitelistEntry 是白名单里的单条记录。
type whitelistEntry struct {
	IP      string `json:"ip"`
	AddedAt string `json:"added_at"`
	// Note 是加入时的语境（例："最近一次成功 SSH 登录的 IP" / "手动填写"）。
	Note string `json:"note,omitempty"`
}

// loginCandidate 是"可能是你自己"的来源 IP 候选：来自成功登录日志。
//
// 为什么用登录日志当"当前 IP"：面板拿不到浏览器出口 IP（内核不透出客户端 IP，
// 见 internal/core/httpapi/audit_http.go 的 maskedClientIP 只给脱敏值），而 fail2ban
// 封的正是 SSH 来源 IP——管理员自己的 SSH 出口 IP 恰好就写在 sshd 的 Accepted 行里。
// 因此用"最近成功登录的来源 IP"作为「你的 IP」候选，并在页面上明确标注口径。
type loginCandidate struct {
	IP       string `json:"ip"`
	LastSeen string `json:"last_seen"`
	Success  int    `json:"success"`
}

// whitelistResult 是 ssh.whitelist 的结果：白名单现状 + 「你的 IP」候选 + 自锁告警。
type whitelistResult struct {
	Entries []whitelistEntry `json:"entries"`
	Count   int              `json:"count"`
	// Persisted / Path / Note 说明白名单是否真的落盘（不落盘时只在本次运行内生效）。
	Persisted bool   `json:"persisted"`
	Path      string `json:"path,omitempty"`
	Note      string `json:"note,omitempty"`
	// Candidates 是最近成功 SSH 登录的来源 IP（最新在前，最多 5 条）。
	Candidates []loginCandidate `json:"candidates"`
	// CurrentIP 是候选里最新的那条，即「你最近一次 SSH 登录用的 IP」；读不到为空。
	CurrentIP string `json:"current_ip,omitempty"`
	// CurrentWhitelisted 回答"当前 IP 是否在白名单"。
	CurrentWhitelisted bool `json:"current_whitelisted"`
	// BannedWhitelisted 是「在白名单却被封着」的 IP：自锁风险，页面提供一键解封。
	BannedWhitelisted []string `json:"banned_whitelisted"`
	// LogSource 是候选来源（auth | journal | none）。
	LogSource string `json:"log_source"`
}

// whitelistWriteParams 是 ssh.whitelist.add / ssh.whitelist.remove 的入参。
type whitelistWriteParams struct {
	IP   string `json:"ip"`
	Note string `json:"note,omitempty"`
}

// banWriteParams 是 ssh.ban.add / ssh.ban.remove 的入参。
type banWriteParams struct {
	IP string `json:"ip"`
	// Confirm 是不可回滚动作（fail2ban-banip）的一次性 confirm 令牌：
	// 由管理员会话向内核 confirm-token 端点申请后随本方法传入，插件原样转发给内核核销。
	// ban.remove（unbanip）是恢复性动作，不需要令牌。
	Confirm string `json:"confirm,omitempty"`
}

// banWriteResult 是 ssh.ban.add / ssh.ban.remove 的结果：真实执行信息 + 回读证明。
//
// 字段口径：
//   - Applied=true 表示经内核提权通道的 fail2ban-client 命令已执行且退出码 0（不是"排队等待"）；
//   - Banned / BannedCount / Verified 来自**执行后**经 fail2ban-status 动作的回读——
//     回读不可用时 Verified=false 且 Note 说明原因（绝不假装已生效）；
//   - Stdout / Stderr 只回首行摘要，避免把宿主输出整段塞进协议帧。
type banWriteResult struct {
	IP          string   `json:"ip"`
	Action      string   `json:"action"` // fail2ban-banip | fail2ban-unbanip
	Applied     bool     `json:"applied"`
	ExitCode    int      `json:"exit_code"`
	Stdout      string   `json:"stdout,omitempty"`
	Stderr      string   `json:"stderr,omitempty"`
	Banned      []string `json:"banned"`
	BannedCount int      `json:"banned_count"`
	Verified    bool     `json:"verified"`
	Note        string   `json:"note,omitempty"`
}

// banExecErrorDetail 是封禁命令「执行了但退出码非 0」错误 Detail 的结构化载荷。
type banExecErrorDetail struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
}

// rootHintDetail 是 E_NEED_ROOT 错误 Detail 的结构化载荷。
type rootHintDetail struct {
	Hint       string `json:"hint"`
	RootAction string `json:"root_action"`
}

// encode 把结构体编成 json.RawMessage；失败时返回空对象字面量。
// 这里的结构体字段全是标量/切片， Marshal 不会失败；兜底只是避免 panic。
func encode(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
