package main

import (
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// logEvent 是从 SSH 日志行解析出的单条认证事件。
// Kind ∈ {"failed"（Failed password）, "invalid"（Invalid user，用户名探测）, "success"（Accepted）}；
// 用户名**不落库**——聚合视图只保留 IP 与计数（敏感值白名单：IP）。
type logEvent struct {
	At      time.Time
	Kind    string
	IP      string
	HasTime bool
}

// 事件类别常量。
const (
	kindFailed  = "failed"
	kindInvalid = "invalid"
	kindSuccess = "success"
)

var (
	// tsISOPattern 匹配 rsyslog ISO 时间戳与 journalctl short-iso（2026-11-17T11:39:29[.fraction][+08:00]）。
	tsISOPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
	// tsSyslogPattern 匹配经典 syslog 时间戳（Nov 17 11:39:29 / Nov  7 ...，无年份）。
	tsSyslogPattern = regexp.MustCompile(`^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) `)
	// msgFailedPattern 提取 Failed password 行的来源 IP（用户名不捕获保存）。
	msgFailedPattern = regexp.MustCompile(`^Failed password for (?:invalid user )?\S+ from (\S+)`)
	// msgInvalidPattern 提取 Invalid user 行的来源 IP。
	msgInvalidPattern = regexp.MustCompile(`^Invalid user \S+ from (\S+)`)
	// msgAcceptedPattern 提取 Accepted（password/publickey 等）行的来源 IP。
	msgAcceptedPattern = regexp.MustCompile(`^Accepted \S+ for \S+ from (\S+)`)
)

// parseSSHLogLine 解析一行 SSH 日志为事件；yearHint 供无年份的 syslog 时间戳补年。
// 不匹配任何已知认证消息、或来源 IP 非法时返回 (zero, false)。
func parseSSHLogLine(line string, yearHint int) (logEvent, bool) {
	event := logEvent{HasTime: false}
	if ts, ok := parseLogTimestamp(line, yearHint); ok {
		event.At = ts
		event.HasTime = true
	}
	msg := logMessage(line)
	switch {
	case msgAcceptedPattern.MatchString(msg):
		event.Kind = kindSuccess
		event.IP = msgAcceptedPattern.FindStringSubmatch(msg)[1]
	case msgFailedPattern.MatchString(msg):
		event.Kind = kindFailed
		event.IP = msgFailedPattern.FindStringSubmatch(msg)[1]
	case msgInvalidPattern.MatchString(msg):
		event.Kind = kindInvalid
		event.IP = msgInvalidPattern.FindStringSubmatch(msg)[1]
	default:
		return logEvent{}, false
	}
	if net.ParseIP(event.IP) == nil {
		return logEvent{}, false
	}
	return event, true
}

// parseEvents 批量解析，忽略不可解析行（格式健壮：一行坏不致命）。
func parseEvents(lines []string) []logEvent {
	yearHint := time.Now().Year()
	events := make([]logEvent, 0, len(lines))
	for _, line := range lines {
		if event, ok := parseSSHLogLine(line, yearHint); ok {
			events = append(events, event)
		}
	}
	return events
}

// logMessage 取日志行中 "]: " 之后的消息体；无该分隔符时退回整行。
func logMessage(line string) string {
	if idx := strings.Index(line, "]: "); idx >= 0 {
		return line[idx+3:]
	}
	return line
}

// parseLogTimestamp 解析行首时间戳：ISO（rsyslog 24.04+ / journalctl short-iso）或经典 syslog。
// syslog 无年份，用 yearHint 补齐；解析失败返回 ok=false（事件保留但无时间维度）。
func parseLogTimestamp(line string, yearHint int) (time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, false
	}
	if tsISOPattern.MatchString(fields[0]) {
		if ts, err := time.Parse(time.RFC3339, fields[0]); err == nil {
			return ts, true
		}
		// journalctl 某些配置输出 +0800（无冒号），补一次解析。
		if ts, err := time.Parse("2006-01-02T15:04:05-0700", fields[0]); err == nil {
			return ts, true
		}
		return time.Time{}, false
	}
	if m := tsSyslogPattern.FindStringSubmatch(line); m != nil {
		normalized := m[1] + " " + m[2] + " " + m[3] + ":" + m[4] + ":" + m[5] + " " + strconv.Itoa(yearHint)
		if ts, err := time.ParseInLocation("Jan _2 15:04:05 2006", normalized, time.Local); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}

// attemptStats 是聚合后的攻击统计视图。
type attemptStats struct {
	Total             int
	Failed            int // failed + invalid（爆破与用户名探测都是失败尝试）
	InvalidUsers      int
	SuccessfulLogins  int
	UniqueIPs         int
	EventsWithoutTime int
	IPStats           []ipCount
	Timeline          []hourCount
}

// perIP 统计单个来源 IP 的成功/失败次数。
type perIP struct {
	failed  int
	success int
}

// aggregateEvents 聚合事件：since/until 窗口过滤（无时间事件保留计数、不入时间线），
// topN 控制 top_ips 条数。结果稳定排序（失败数 desc → 成功数 desc → IP asc）。
func aggregateEvents(events []logEvent, since, until time.Time, topN int) attemptStats {
	if topN <= 0 {
		topN = 10
	}
	stats := attemptStats{}
	ips := map[string]*perIP{}
	hours := map[string]*hourCount{}
	for _, e := range events {
		if e.HasTime && !since.IsZero() && e.At.Before(since) {
			continue
		}
		if e.HasTime && !until.IsZero() && e.At.After(until) {
			continue
		}
		stats.Total++
		switch e.Kind {
		case kindSuccess:
			stats.SuccessfulLogins++
		case kindInvalid:
			stats.InvalidUsers++
			stats.Failed++
		case kindFailed:
			stats.Failed++
		}
		if !e.HasTime {
			stats.EventsWithoutTime++
		}
		ip, ok := ips[e.IP]
		if !ok {
			ip = &perIP{}
			ips[e.IP] = ip
		}
		if e.Kind == kindSuccess {
			ip.success++
		} else {
			ip.failed++
		}
		if e.HasTime {
			key := e.At.Local().Truncate(time.Hour).Format("2006-01-02T15:04")
			h, ok := hours[key]
			if !ok {
				h = &hourCount{Hour: key}
				hours[key] = h
			}
			if e.Kind == kindSuccess {
				h.Success++
			} else {
				h.Failed++
			}
		}
	}
	stats.UniqueIPs = len(ips)
	stats.IPStats = rankIPs(ips, topN)
	stats.Timeline = sortHours(hours)
	return stats
}

// rankIPs 按（失败数 desc → 成功数 desc → IP asc）排序并截断 topN。
func rankIPs(ips map[string]*perIP, topN int) []ipCount {
	result := make([]ipCount, 0, len(ips))
	for ip, stat := range ips {
		result = append(result, ipCount{IP: ip, Failed: stat.failed, Success: stat.success, Total: stat.failed + stat.success})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Failed != result[j].Failed {
			return result[i].Failed > result[j].Failed
		}
		if result[i].Success != result[j].Success {
			return result[i].Success > result[j].Success
		}
		return result[i].IP < result[j].IP
	})
	if len(result) > topN {
		result = result[:topN]
	}
	return result
}

// sortHours 按小时升序输出时间线（只有出现过事件的桶）。
func sortHours(hours map[string]*hourCount) []hourCount {
	result := make([]hourCount, 0, len(hours))
	for _, h := range hours {
		result = append(result, *h)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Hour < result[j].Hour })
	return result
}

var (
	// sanitizeFailedPattern 将 Failed password 行中的用户名打码。
	sanitizeFailedPattern = regexp.MustCompile(`^Failed password for (invalid user )?(\S+) (from .*)$`)
	// sanitizeAcceptedPattern 将 Accepted 行中的用户名打码。
	sanitizeAcceptedPattern = regexp.MustCompile(`^(Accepted \S+ for )(\S+)( from .*)$`)
	// sanitizeInvalidPattern 将 Invalid user 行中的用户名打码。
	sanitizeInvalidPattern = regexp.MustCompile(`^(Invalid user )(\S+)( from .*)$`)
)

// sanitizeLogLine 对原始日志行做用户名脱敏：IP 是唯一允许展示的敏感值，
// 用户名在 raw_tail 里一律替换为 ***。打码只作用于 "]: " 之后的消息体，
// 时间戳/主机/进程名原样保留；不匹配已知模式的行原样返回。
func sanitizeLogLine(line string) string {
	prefix := ""
	msg := line
	if idx := strings.Index(line, "]: "); idx >= 0 {
		prefix = line[:idx+3]
		msg = line[idx+3:]
	}
	if m := sanitizeFailedPattern.FindStringSubmatch(msg); m != nil {
		out := "Failed password for "
		if m[1] != "" {
			out += "invalid user "
		}
		return prefix + out + "*** " + m[3]
	}
	if m := sanitizeAcceptedPattern.FindStringSubmatch(msg); m != nil {
		return prefix + m[1] + "***" + m[3]
	}
	if m := sanitizeInvalidPattern.FindStringSubmatch(msg); m != nil {
		return prefix + m[1] + "***" + m[3]
	}
	return line
}

// suspiciousIPs 从事件中推断可疑 IP：任一自然小时内失败次数 ≥ threshold 即命中。
// 返回按（桶内失败数 desc → IP asc）排序的封禁候选；threshold ≤ 0 视为 1。
func suspiciousIPs(events []logEvent, threshold int) []banItem {
	if threshold <= 0 {
		threshold = 1
	}
	type bucket struct {
		maxFailures int
		lastSeen    time.Time
		hasSeen     bool
	}
	hourly := map[string]map[string]int{} // ip -> hourKey -> failures
	lastSeen := map[string]time.Time{}
	for _, e := range events {
		if e.Kind == kindSuccess {
			continue
		}
		m, ok := hourly[e.IP]
		if !ok {
			m = map[string]int{}
			hourly[e.IP] = m
		}
		if e.HasTime {
			m[e.At.Local().Truncate(time.Hour).Format("2006-01-02T15:04")]++
			if prev, ok := lastSeen[e.IP]; !ok || e.At.After(prev) {
				lastSeen[e.IP] = e.At
			}
		}
	}
	items := make([]banItem, 0, len(hourly))
	for ip, m := range hourly {
		max := 0
		for _, count := range m {
			if count > max {
				max = count
			}
		}
		if max >= threshold {
			item := banItem{
				Address:  ip,
				Failures: max,
				Reason:   "近 1 小时内失败 " + strconv.Itoa(max) + " 次 ≥ 阈值 " + strconv.Itoa(threshold) + "（从 sshd 日志推断）",
			}
			if ts, ok := lastSeen[ip]; ok {
				item.LastSeen = ts.Local().Format(time.RFC3339)
			}
			items = append(items, item)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Failures != items[j].Failures {
			return items[i].Failures > items[j].Failures
		}
		return items[i].Address < items[j].Address
	})
	return items
}
