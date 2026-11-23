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
}

// auditCheck 是单条配置审计项：指令名、当前值、是否合规、修复建议。
type auditCheck struct {
	Directive   string `json:"directive"`
	Current     string `json:"current"`
	Compliant   bool   `json:"compliant"`
	Recommended string `json:"recommended"`
	Advice      string `json:"advice"`
}

// banEntry 是封禁清单中的单条记录（骨架阶段不产生真实记录）。
type banEntry struct {
	Address string `json:"address"`
	Reason  string `json:"reason"`
	Until   string `json:"until"`
}

// banListResult 是 ssh.ban.list 的结构化结果。
type banListResult struct {
	Bans    []banEntry `json:"bans"`
	Count   int        `json:"count"`
	Limit   int        `json:"limit"`
	Offset  int        `json:"offset"`
	Applied bool       `json:"applied"`
}

// banParams 是 ssh.ban.list 的入参；Limit 有默认值，用一个指针区分"未设置"与"显式 0"。
type banParams struct {
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	Address string `json:"address"`
	limit   *int   `json:"-"`
}

// limitSet 报告 limit 是否被显式设置（显式 0 也必须判为越界）。
func (p banParams) limitSet() bool { return p.limit != nil }

// UnmarshalJSON 让 banParams 记录 limit 是否出现在请求里。
func (p *banParams) UnmarshalJSON(raw []byte) error {
	type alias struct {
		Limit   *int   `json:"limit"`
		Offset  int    `json:"offset"`
		Address string `json:"address"`
	}
	var a alias
	if err := json.Unmarshal(raw, &a); err != nil {
		return err
	}
	p.Offset = a.Offset
	p.Address = a.Address
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
	RawLines          int         `json:"raw_lines"`
	RawTail           []string    `json:"raw_tail"`
	Truncated         bool        `json:"truncated"`
	Note              string      `json:"note,omitempty"`
}

// banItem 是封禁/可疑 IP 清单的单条记录（fail2ban 实封或日志推断）。
type banItem struct {
	Address  string `json:"address"`
	Failures int    `json:"failures"`
	LastSeen string `json:"last_seen,omitempty"`
	Reason   string `json:"reason"`
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
	Persisted           bool   `json:"persisted"`
	Note                string `json:"note"`
}

// configSetParams 是 ssh.config.set 的入参；全指针字段，未设置 = 不修改。
type configSetParams struct {
	LogPath             *string `json:"log_path"`
	LogSource           *string `json:"log_source"`
	SuspiciousThreshold *int    `json:"suspicious_threshold"`
	RawTailLimit        *int    `json:"raw_tail_limit"`
}

// banWriteParams 是 ssh.ban.add / ssh.ban.remove 的入参。
type banWriteParams struct {
	IP string `json:"ip"`
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
