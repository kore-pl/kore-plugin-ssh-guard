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

// encode 把结构体编成 json.RawMessage；失败时返回空对象字面量。
// 这里的结构体字段全是标量/切片， Marshal 不会失败；兜底只是避免 panic。
func encode(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
