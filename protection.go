package main

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// cmdRunner 抽象外部命令执行，便于单测注入假 runner（不真跑 fail2ban）。
type cmdRunner interface {
	LookPath(name string) (string, error)
	Run(args ...string) (stdout string, err error)
}

// execRunner 是默认实现：每次调用限时（G-19：请求级 context，defer cancel）。
type execRunner struct {
	timeout time.Duration
}

// Run 执行外部命令并返回 stdout；超时或失败返回 error（stderr 拼进错误便于诊断）。
func (r execRunner) Run(args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("空命令")
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return stdout.String(), errors.New(err.Error() + ": " + msg)
		}
		return stdout.String(), err
	}
	return stdout.String(), nil
}

// LookPath 在 PATH 中查找命令。
func (r execRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// guardRunner 是业务侧使用的 runner 实例；单测可整体替换（用后恢复）。
var guardRunner cmdRunner = execRunner{timeout: 5 * time.Second}

// fail2banState 是 fail2ban 探测结果；Installed=false 表示命令不存在（未安装）。
type fail2banState struct {
	Installed       bool
	Active          bool
	Version         string
	CurrentlyBanned int
	BannedIPs       []string
}

// probeFail2ban 探测 fail2ban：LookPath 判安装，`fail2ban-client status` 判可用，
// `status sshd` 解析 sshd jail 的当前封禁计数与 IP 清单。任何一步失败都如实降级，不抛错。
func probeFail2ban(r cmdRunner) fail2banState {
	var st fail2banState
	if _, err := r.LookPath("fail2ban-client"); err != nil {
		return st // 未安装：engine 走 sshd 日志降级
	}
	st.Installed = true
	if _, err := r.Run("fail2ban-client", "status"); err != nil {
		return st // 已安装但 socket 不可访问（通常需 root）→ 按 sshd 日志降级
	}
	st.Active = true
	if version, err := r.Run("fail2ban-client", "version"); err == nil {
		st.Version = firstLine(version)
	}
	if jail, err := r.Run("fail2ban-client", "status", "sshd"); err == nil {
		st.CurrentlyBanned, st.BannedIPs = parseFail2banJail(jail)
	}
	return st
}

// parseFail2banJail 解析 `fail2ban-client status <jail>` 输出：
//
//	|- Currently banned:	3
//	`- Banned IP list:	1.2.3.4 5.6.7.8
//
// 分隔兼容 tab 与 ": "（不同版本输出不一致）；标签按包含匹配并去掉装饰前缀。
// 标签本地化时解析失败返回 0 + 空清单（诚实：不编造数据）。
func parseFail2banJail(out string) (count int, ips []string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		label, value, ok := splitJailLabel(line)
		if !ok {
			continue
		}
		switch {
		case strings.Contains(label, "Currently banned"):
			if n, err := strconv.Atoi(value); err == nil {
				count = n
			}
		case strings.Contains(label, "Banned IP list"):
			ips = append(ips, strings.Fields(value)...)
		}
	}
	return count, ips
}

// splitJailLabel 把 jail 状态行拆成标签与值：优先 tab 分隔，其次 ": " 分隔。
// 标签保留装饰前缀（|- 等），由调用方按 Contains 匹配。
func splitJailLabel(line string) (label, value string, ok bool) {
	if idx := strings.LastIndex(line, "\t"); idx >= 0 {
		label = strings.TrimSuffix(strings.TrimSpace(line[:idx]), ":")
		return label, strings.TrimSpace(line[idx+1:]), label != ""
	}
	if idx := strings.LastIndex(line, ": "); idx >= 0 {
		label = strings.TrimSuffix(strings.TrimSpace(line[:idx]), ":")
		return label, strings.TrimSpace(line[idx+2:]), label != ""
	}
	return "", "", false
}

// firstLine 返回多行文本的首行。
func firstLine(text string) string {
	if idx := strings.IndexByte(text, '\n'); idx >= 0 {
		return strings.TrimSpace(text[:idx])
	}
	return strings.TrimSpace(text)
}

// detectProtection 检测防护源：fail2ban（活跃则为主引擎）+ sshd 日志（降级统计源）。
// available = fail2ban 活跃 或 任一日志源可读；两者皆无 → engine=none、available=false。
func detectProtection(g guardConfig, r cmdRunner) protectionInfo {
	st := probeFail2ban(r)
	since := time.Now().Add(-24 * time.Hour)
	lines, source, _, _ := collectLogLines(g, since)
	events := parseEvents(lines)
	stats := aggregateEvents(events, since, time.Now(), 0)
	info := protectionInfo{
		Fail2banInstalled: st.Installed,
		Fail2banActive:    st.Active,
		EngineVersion:     st.Version,
		BannedCount:       st.CurrentlyBanned,
		Failed24h:         stats.Failed,
		LogSource:         source,
	}
	switch {
	case st.Active:
		info.Available, info.Engine = true, "fail2ban"
	case source != "none":
		info.Available, info.Engine = true, "sshd"
	default:
		info.Engine = "none"
	}
	info.Hint = protectionHint(st, source, g)
	return info
}

// protectionHint 组装可操作提示（ADR-0018 降级口径：可解释、可操作）。
func protectionHint(st fail2banState, source string, g guardConfig) string {
	var parts []string
	switch {
	case !st.Installed:
		parts = append(parts, "fail2ban 未安装；以 sshd 日志统计为降级源（只读，不执行封禁）。如需封禁可安装 fail2ban（apt/dnf install fail2ban）")
	case !st.Active:
		parts = append(parts, "fail2ban 已安装但客户端无法访问其 socket（通常需要 root 或 adm 组权限）；按 sshd 日志降级统计")
	}
	if source == "none" {
		parts = append(parts, "auth.log（"+g.LogPath+"）与 journalctl 均不可读，攻击统计不可用；可将本进程加入 adm 组或以可读日志的账号运行 kored")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；")
}
