package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// fail2banClientPath 是 fail2ban-client 的**唯一路径口径**：代码与 info.json 的
// root_actions[].argv[0] 逐字一致（TestFail2banPathsMatchInfoJSON 锁定）。
//
// 为什么是绝对路径而不是命令名：pluginapi.RootCommandAllowlist 不含 fail2ban-client
// （协议常量在内核仓，本仓不改），argv[0] 只能写规范化绝对路径。因此本插件：
//   - 进程内**不执行** fail2ban-client（只读探测一律经声明的 root action 由内核代理执行）；
//   - 只用 exec.LookPath(fail2banClientPath) 判断「声明路径是否存在且可执行」，不向 PATH
//     回退查找别处的同名二进制——避免「进程内探测成功、提权动作却因路径不同失败」的分裂。
const fail2banClientPath = "/usr/bin/fail2ban-client"

// root action id 常量：与 info.json 的 root_actions 一一对应，并在代码里被真实引用
// （status/bans 探测 → fail2ban-status；ban.add/ban.remove → banip/unbanip），
// 不再出现「声明了能力但代码零引用」（0.2.0 复核发现的 P1 债）。
const (
	rootActionFail2banStatus  = "fail2ban-status"
	rootActionFail2banBanIP   = "fail2ban-banip"
	rootActionFail2banUnbanIP = "fail2ban-unbanip"
)

// lookPath 抽象可执行文件探测（只查文件，不执行命令）；单测可注入。
var lookPath = exec.LookPath

// guardRootAction 是内核提权通道调用面；nil 表示内核未注入 KORE_KERNEL_SOCK
// （旧内核 / 独立调试）→ 状态读取按降级处理，不假装能读。
// 单测在 TestMain 里置 nil，避免读宿主机真实环境。
var guardRootAction rootActionFunc = rootActionFuncFromEnv()

// fail2banState 是 fail2ban 探测结果；Installed=false 表示声明路径不存在（未安装，
// 或装在别处而提权动作同样会失败）。
type fail2banState struct {
	Installed       bool
	Active          bool
	CurrentlyBanned int
	BannedIPs       []string
	// Channel 报告探测时 root-action 通道是否可用；ProbeErr 是失败原因（内部诊断，不进 JSON）。
	Channel  bool
	ProbeErr string
}

// probeFail2ban 探测 fail2ban：
//  1. 声明路径存在且可执行 → Installed=true；
//  2. 经内核 root 通道执行声明动作 fail2ban-status（固定 argv：status sshd）；
//  3. 退出码 0 → Active=true 并解析 sshd jail 的封禁计数与 IP 清单。
//
// 任何一步失败都如实降级（Active=false + ProbeErr），不抛错、不编造数据。
func probeFail2ban(call rootActionFunc) fail2banState {
	st := fail2banState{Channel: call != nil}
	if _, err := lookPath(fail2banClientPath); err != nil {
		return st // 声明路径不存在：未安装态（engine 走 sshd 日志降级）
	}
	st.Installed = true
	if call == nil {
		return st // 已安装但通道未注入：无法读取状态，hint 指向缺失的提权通道
	}
	out, err := call(rootActionFail2banStatus, nil)
	if err != nil {
		st.ProbeErr = err.Error()
		return st
	}
	if out.ExitCode != 0 {
		reason := firstLine(out.Stderr)
		if reason == "" {
			st.ProbeErr = fmt.Sprintf("%s 退出码 %d", rootActionFail2banStatus, out.ExitCode)
		} else {
			st.ProbeErr = fmt.Sprintf("%s 退出码 %d：%s", rootActionFail2banStatus, out.ExitCode, reason)
		}
		return st
	}
	st.Active = true
	st.CurrentlyBanned, st.BannedIPs = parseFail2banJail(out.Stdout)
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
func detectProtection(g guardConfig, call rootActionFunc) protectionInfo {
	st := probeFail2ban(call)
	since := time.Now().Add(-24 * time.Hour)
	lines, source, _, _ := collectLogLines(g, since)
	events := parseEvents(lines)
	stats := aggregateEvents(events, since, time.Now(), 0)
	info := protectionInfo{
		Fail2banInstalled: st.Installed,
		Fail2banActive:    st.Active,
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
		parts = append(parts, "fail2ban 未安装（提权声明路径 "+fail2banClientPath+" 不存在）；以 sshd 日志统计为降级源（只读，不执行封禁）。如需封禁可安装 fail2ban（apt/dnf install fail2ban）；若已装在 /usr/local/bin 等其它路径，请创建符号链接 ln -s <实际路径> "+fail2banClientPath+" 后重启插件")
	case !st.Active && st.ProbeErr != "":
		parts = append(parts, "fail2ban 已安装但状态读取失败（提权动作 "+rootActionFail2banStatus+"）："+st.ProbeErr+"；请确认 kored 以 root 启动且 systemd 提权通道可用；已降级为 sshd 日志统计")
	case !st.Active:
		parts = append(parts, "fail2ban 已安装，但内核未注入 root-action 通道（KORE_KERNEL_SOCK 缺省）；状态读取经提权动作 "+rootActionFail2banStatus+"，通道缺失时无法读取（插件进程内不再直呼 fail2ban-client）；已降级为 sshd 日志统计")
	}
	if source == "none" {
		parts = append(parts, "auth.log（"+g.LogPath+"）与 journalctl 均不可读，攻击统计不可用；可将本进程加入 adm 组或以可读日志的账号运行 kored")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；")
}
