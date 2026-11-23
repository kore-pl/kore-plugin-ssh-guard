package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 真实日志行样本：第一行来自本机 journalctl -u ssh 实录（2026-11-17 成功登录），
// 其余为构造的真实格式行（Ubuntu rsyslog ISO / 经典 syslog / journalctl short-iso）。
const (
	realAcceptedISO = "2026-11-17T11:39:29.279845+08:00 U-PT sshd-session[2006374]: Accepted password for pt from 192.168.192.1 port 56139 ssh2"
	journalFailed   = "2026-11-17T10:00:00+08:00 U-PT sshd-session[12345]: Failed password for root from 203.0.113.7 port 41022 ssh2"
	journalInvalid  = "2026-11-17T10:00:01+08:00 U-PT sshd-session[12345]: Invalid user admin from 203.0.113.8 port 41024"
	syslogFailed    = "Nov 17 10:00:02 host sshd[999]: Failed password for invalid user oracle from 198.51.100.9 port 5555 ssh2"
	syslogFailed2   = "Nov 17 10:00:03 host sshd[999]: Failed password for root from 198.51.100.9 port 5556 ssh2"
	nonSSHLine      = "2026-11-22T00:57:23.078406+08:00 U-PT gnome-keyring-daemon[2249]: asked to register item /org/freedesktop/secrets/collection/login/13, but it's already registered"
	badIPLine       = "2026-11-17T10:00:04+08:00 U-PT sshd-session[1]: Failed password for root from not-an-ip port 1 ssh2"
)

// TestParseSSHLogLine 覆盖三种真实格式的解析与坏行丢弃。
func TestParseSSHLogLine(t *testing.T) {
	year := 2026
	cases := []struct {
		name    string
		line    string
		want    logEvent
		wantOK  bool
		wantHas bool
	}{
		{"本机真实成功登录（ISO 带小数秒）", realAcceptedISO, logEvent{Kind: kindSuccess, IP: "192.168.192.1"}, true, true},
		{"journalctl 失败尝试", journalFailed, logEvent{Kind: kindFailed, IP: "203.0.113.7"}, true, true},
		{"用户名探测", journalInvalid, logEvent{Kind: kindInvalid, IP: "203.0.113.8"}, true, true},
		{"经典 syslog 无年份", syslogFailed, logEvent{Kind: kindFailed, IP: "198.51.100.9"}, true, true},
		{"非 SSH 行", nonSSHLine, logEvent{}, false, false},
		{"非法 IP 丢弃", badIPLine, logEvent{}, false, false},
		{"空行", "", logEvent{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSSHLogLine(tc.line, year)
			if ok != tc.wantOK {
				t.Fatalf("ok=%v 期望 %v（event=%+v）", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.Kind != tc.want.Kind || got.IP != tc.want.IP {
				t.Fatalf("kind/ip=%s/%s 期望 %s/%s", got.Kind, got.IP, tc.want.Kind, tc.want.IP)
			}
			if got.HasTime != tc.wantHas {
				t.Fatalf("has_time=%v 期望 %v", got.HasTime, tc.wantHas)
			}
			if tc.wantHas {
				if got.At.Year() != year {
					t.Fatalf("解析年份=%d 期望 %d（at=%v）", got.At.Year(), year, got.At)
				}
				if !got.At.Equal(got.At.Local()) {
					t.Fatalf("时区应保留本地偏移：%v", got.At)
				}
			}
		})
	}
}

// TestParseSSHLogLineSyslogHour 校验 syslog 时间的具体小时解析（10:00 本地）。
func TestParseSSHLogLineSyslogHour(t *testing.T) {
	event, ok := parseSSHLogLine(syslogFailed, 2026)
	if !ok || !event.HasTime {
		t.Fatalf("syslog 行应可解析且带时间：%+v ok=%v", event, ok)
	}
	if event.At.Local().Hour() != 10 || event.At.Local().Month() != time.November {
		t.Fatalf("syslog 时间解析错误：%v", event.At)
	}
}

// TestParseEvents 整行混排：坏行不致命、其余全收。
func TestParseEvents(t *testing.T) {
	events := parseEvents([]string{realAcceptedISO, nonSSHLine, journalFailed, syslogFailed2, badIPLine, ""})
	if len(events) != 3 {
		t.Fatalf("解析出 %d 条事件，期望 3：%+v", len(events), events)
	}
}

// TestSanitizeLogLine 校验用户名打码：IP 是唯一允许展示的敏感值。
func TestSanitizeLogLine(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"成功登录", realAcceptedISO, "2026-11-17T11:39:29.279845+08:00 U-PT sshd-session[2006374]: Accepted password for *** from 192.168.192.1 port 56139 ssh2"},
		{"失败尝试", journalFailed, "2026-11-17T10:00:00+08:00 U-PT sshd-session[12345]: Failed password for *** from 203.0.113.7 port 41022 ssh2"},
		{"带 invalid user", syslogFailed, "Nov 17 10:00:02 host sshd[999]: Failed password for invalid user *** from 198.51.100.9 port 5555 ssh2"},
		{"用户名探测", journalInvalid, "2026-11-17T10:00:01+08:00 U-PT sshd-session[12345]: Invalid user *** from 203.0.113.8 port 41024"},
		{"无关行原样", nonSSHLine, nonSSHLine},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLogLine(tc.in)
			if got != tc.want {
				t.Fatalf("脱敏结果不符：\n got=%s\nwant=%s", got, tc.want)
			}
			if strings.Contains(tc.in, " for pt ") && strings.Contains(got, " for pt ") {
				t.Fatalf("用户名泄漏：%s", got)
			}
		})
	}
}

// TestAggregateEvents 覆盖窗口过滤、top 排序、小时桶、无时间事件计数。
func TestAggregateEvents(t *testing.T) {
	base := time.Date(2026, 11, 17, 10, 0, 0, 0, time.Local)
	events := []logEvent{
		{At: base.Add(-25 * time.Hour), Kind: kindFailed, IP: "10.0.0.1", HasTime: true}, // 窗口外 → 丢弃
		{At: base, Kind: kindFailed, IP: "203.0.113.7", HasTime: true},
		{At: base, Kind: kindFailed, IP: "203.0.113.7", HasTime: true},
		{At: base.Add(time.Minute), Kind: kindInvalid, IP: "203.0.113.8", HasTime: true},
		{At: base.Add(30 * time.Minute), Kind: kindSuccess, IP: "192.168.192.1", HasTime: true},
		{At: base.Add(90 * time.Minute), Kind: kindFailed, IP: "203.0.113.7", HasTime: true}, // 下一小时桶
		{Kind: kindFailed, IP: "9.9.9.9", HasTime: false},                                    // 无时间 → 计数不入桶
	}
	stats := aggregateEvents(events, base.Add(-24*time.Hour), base.Add(2*time.Hour), 2)
	if stats.Total != 6 || stats.Failed != 5 || stats.SuccessfulLogins != 1 {
		t.Fatalf("total/failed/success=%d/%d/%d 期望 6/5/1：%+v", stats.Total, stats.Failed, stats.SuccessfulLogins, stats)
	}
	if stats.InvalidUsers != 1 || stats.UniqueIPs != 4 || stats.EventsWithoutTime != 1 {
		t.Fatalf("invalid/unique/无时间=%d/%d/%d 期望 1/4/1", stats.InvalidUsers, stats.UniqueIPs, stats.EventsWithoutTime)
	}
	if len(stats.IPStats) != 2 {
		t.Fatalf("topN=2 应只回 2 条：%+v", stats.IPStats)
	}
	if stats.IPStats[0].IP != "203.0.113.7" || stats.IPStats[0].Failed != 3 {
		t.Fatalf("榜首应为 203.0.113.7（3 次失败）：%+v", stats.IPStats[0])
	}
	if len(stats.Timeline) != 2 {
		t.Fatalf("应有两个小时桶：%+v", stats.Timeline)
	}
	if stats.Timeline[0].Hour != base.Format("2006-01-02T15:04") || stats.Timeline[0].Failed != 3 || stats.Timeline[0].Success != 1 {
		t.Fatalf("首小时桶不符：%+v", stats.Timeline[0])
	}
}

// TestAggregateEmpty 空输入（无日志降级）返回零值且切片非 nil。
func TestAggregateEmpty(t *testing.T) {
	stats := aggregateEvents(nil, time.Now().Add(-time.Hour), time.Now(), 10)
	if stats.Total != 0 || stats.UniqueIPs != 0 {
		t.Fatalf("空输入应零值：%+v", stats)
	}
}

// TestSuspiciousThreshold 校验可疑 IP 推断：单小时 ≥ 阈值命中，分散不命中。
func TestSuspiciousThreshold(t *testing.T) {
	base := time.Date(2026, 11, 17, 10, 0, 0, 0, time.Local)
	var burst, spread []logEvent
	for i := 0; i < 10; i++ {
		burst = append(burst, logEvent{At: base.Add(time.Duration(i) * time.Second), Kind: kindFailed, IP: "198.51.100.9", HasTime: true})
	}
	// 同一 IP 10 次分散在两个小时（5+5）→ 不命中阈值 10。
	for i := 0; i < 5; i++ {
		spread = append(spread, logEvent{At: base.Add(time.Duration(i) * time.Second), Kind: kindFailed, IP: "198.51.100.10", HasTime: true})
		spread = append(spread, logEvent{At: base.Add(time.Hour + time.Duration(i)*time.Second), Kind: kindFailed, IP: "198.51.100.10", HasTime: true})
	}
	items := suspiciousIPs(append(append([]logEvent{}, burst...), spread...), 10)
	if len(items) != 1 || items[0].Address != "198.51.100.9" || items[0].Failures != 10 {
		t.Fatalf("只有集中爆破的 IP 应命中：%+v", items)
	}
	if !strings.Contains(items[0].Reason, "≥ 阈值 10") {
		t.Fatalf("reason 应写明阈值：%q", items[0].Reason)
	}
	if items[0].LastSeen == "" {
		t.Fatal("可疑项应带 last_seen")
	}
	if got := suspiciousIPs(spread, 10); len(got) != 0 {
		t.Fatalf("分散失败不应命中：%+v", got)
	}
}

// TestReadFileTail 校验尾部限读与半行丢弃。
func TestReadFileTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	content := strings.Repeat("x", 2048) + "\n" + realAcceptedISO + "\n" + journalFailed + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// 全量读取（上限大于文件）。
	lines, truncated, err := readFileTail(path, maxLogTailBytes)
	if err != nil || truncated || len(lines) != 3 {
		t.Fatalf("全量读取错误：lines=%d truncated=%v err=%v", len(lines), truncated, err)
	}
	// 限读 1 KiB：只留尾部，且无半行残留。
	lines, truncated, err = readFileTail(path, 1024)
	if err != nil || !truncated {
		t.Fatalf("限读应标记 truncated：err=%v truncated=%v", err, truncated)
	}
	if len(lines) == 0 || !strings.HasSuffix(lines[len(lines)-1], "port 41022 ssh2") {
		t.Fatalf("尾部行不完整：%q", lines)
	}
	for _, line := range lines {
		if strings.HasPrefix(line, strings.Repeat("x", 100)) {
			t.Fatalf("半行未丢弃：%q", line[:40])
		}
	}
}

// TestReadFileTailMissing 缺失文件返回错误（由 collectLogLines 降级，不致命）。
func TestReadFileTailMissing(t *testing.T) {
	if _, _, err := readFileTail(filepath.Join(t.TempDir(), "nope.log"), 1024); err == nil {
		t.Fatal("缺失文件应返回错误")
	}
}
