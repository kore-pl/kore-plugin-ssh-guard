package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRunner 是 cmdRunner 的内存实现：按命令名返回预置输出，用于单测注入。
type fakeRunner struct {
	paths    map[string]string // LookPath 结果；缺省返回 exec.ErrNotFound
	outputs  map[string]string // Run 输出；key 为空格连接的 argv
	failures map[string]error  // Run 失败；key 同上
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if path, ok := f.paths[name]; ok {
		return path, nil
	}
	return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
}

func (f *fakeRunner) Run(args ...string) (string, error) {
	key := strings.Join(args, " ")
	if err, ok := f.failures[key]; ok {
		return "", err
	}
	return f.outputs[key], nil
}

// fakeFail2banRunner 构造一个"已安装且活跃"的 fail2ban 假环境。
func fakeFail2banRunner() *fakeRunner {
	return &fakeRunner{
		paths: map[string]string{"fail2ban-client": "/usr/bin/fail2ban-client"},
		outputs: map[string]string{
			"fail2ban-client status":      "Status\n|- Number of jail:      1\n`- Jail list:           sshd",
			"fail2ban-client version":     "1.1.0\n",
			"fail2ban-client status sshd": "Status for the jail: sshd\n|- Filter\n|  |- Currently failed: 0\n`- Actions\n   |- Currently banned: 2\n   |- Total banned:     7\n   `- Banned IP list:   203.0.113.7 198.51.100.9",
		},
	}
}

// TestProbeFail2banNotInstalled 未安装 → 全零态（engine 走 sshd 降级）。
func TestProbeFail2banNotInstalled(t *testing.T) {
	st := probeFail2ban(&fakeRunner{})
	if st.Installed || st.Active || st.CurrentlyBanned != 0 || len(st.BannedIPs) != 0 {
		t.Fatalf("未安装应全零：%+v", st)
	}
}

// TestProbeFail2banActive 已安装且活跃 → 版本、封禁计数与 IP 清单完整解析。
func TestProbeFail2banActive(t *testing.T) {
	st := probeFail2ban(fakeFail2banRunner())
	if !st.Installed || !st.Active {
		t.Fatalf("应为安装且活跃：%+v", st)
	}
	if st.Version != "1.1.0" {
		t.Fatalf("version=%q 期望 1.1.0", st.Version)
	}
	if st.CurrentlyBanned != 2 {
		t.Fatalf("Currently banned 解析=%d 期望 2", st.CurrentlyBanned)
	}
	if len(st.BannedIPs) != 2 || st.BannedIPs[0] != "203.0.113.7" {
		t.Fatalf("Banned IP list 解析=%v", st.BannedIPs)
	}
}

// TestProbeFail2banSocketDenied 已安装但 socket 不可访问 → installed=true, active=false（如实降级）。
func TestProbeFail2banSocketDenied(t *testing.T) {
	r := &fakeRunner{
		paths:    map[string]string{"fail2ban-client": "/usr/bin/fail2ban-client"},
		failures: map[string]error{"fail2ban-client status": errors.New("exit status 255: ERROR:FAILED to connect to fail2ban socket")},
	}
	st := probeFail2ban(r)
	if !st.Installed || st.Active || st.CurrentlyBanned != 0 {
		t.Fatalf("socket 拒绝应按不活跃降级：%+v", st)
	}
}

// TestDetectProtectionSshdFallback fail2ban 未装 + auth.log 可读 → engine=sshd、available=true、失败计数入账。
// 日志时间戳取"当前时间往前 1 小时"确保落在 failed_24h 窗口内（不依赖具体日期）。
func TestDetectProtectionSshdFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	ts := func(offset time.Duration) string {
		return time.Now().Add(-time.Hour + offset).Format("2006-01-02T15:04:05+08:00")
	}
	log := strings.Join([]string{
		ts(0) + " U-PT sshd-session[12345]: Failed password for root from 203.0.113.7 port 41022 ssh2",
		ts(time.Second) + " U-PT sshd-session[12345]: Failed password for root from 203.0.113.7 port 41023 ssh2",
		ts(2*time.Second) + " U-PT sshd-session[12345]: Invalid user admin from 203.0.113.8 port 41024",
		ts(3*time.Second) + " U-PT sshd-session[2006374]: Accepted password for pt from 192.168.192.1 port 56139 ssh2",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	g := guardConfig{LogPath: path, LogSource: "auth", SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, &fakeRunner{}) // fake runner：fail2ban 未安装
	if !info.Available || info.Engine != "sshd" {
		t.Fatalf("降级源应可用且 engine=sshd：%+v", info)
	}
	if info.Fail2banInstalled || info.Fail2banActive || info.BannedCount != 0 {
		t.Fatalf("未安装 fail2ban 不应报已安装/活跃：%+v", info)
	}
	if info.Failed24h != 3 { // failed 2 + invalid 1
		t.Fatalf("failed_24h=%d 期望 3", info.Failed24h)
	}
	if info.LogSource != "auth" {
		t.Fatalf("log_source=%q 期望 auth", info.LogSource)
	}
}

// TestDetectProtectionNone 日志不可读 + fail2ban 未装 → available=false、engine=none、hint 给可操作路径。
func TestDetectProtectionNone(t *testing.T) {
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth", SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, &fakeRunner{})
	if info.Available || info.Engine != "none" || info.LogSource != "none" {
		t.Fatalf("应如实报不可用：%+v", info)
	}
	if !strings.Contains(info.Hint, "均不可读") {
		t.Fatalf("hint 应说明日志不可读：%q", info.Hint)
	}
}

// TestDetectProtectionFail2banPrimary fail2ban 活跃 → engine=fail2ban、封禁计数取自 jail。
func TestDetectProtectionFail2banPrimary(t *testing.T) {
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth", SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, fakeFail2banRunner())
	if !info.Available || info.Engine != "fail2ban" {
		t.Fatalf("fail2ban 活跃应为可用主引擎：%+v", info)
	}
	if info.BannedCount != 2 || !info.Fail2banActive || !info.Fail2banInstalled {
		t.Fatalf("封禁计数/标志不符：%+v", info)
	}
	if info.EngineVersion != "1.1.0" {
		t.Fatalf("version=%q", info.EngineVersion)
	}
}

// TestProtectionHintUninstalled 校验诚实口径：未安装必须写"fail2ban 未安装；以 sshd 日志统计为降级源"。
func TestProtectionHintUninstalled(t *testing.T) {
	hint := protectionHint(fail2banState{}, "auth", defaultGuardConfig())
	if !strings.Contains(hint, "fail2ban 未安装") || !strings.Contains(hint, "以 sshd 日志统计为降级源") {
		t.Fatalf("hint 缺诚实口径：%q", hint)
	}
}

// TestProtectionHintFail2banActive 活跃时无提示（不刷屏）。
func TestProtectionHintFail2banActive(t *testing.T) {
	hint := protectionHint(fail2banState{Installed: true, Active: true}, "auth", defaultGuardConfig())
	if hint != "" {
		t.Fatalf("活跃态不应有降级提示：%q", hint)
	}
}

// TestParseFail2banJail 标签解析与本地化降级（不认识的标签 → 0，不编造数据）。
func TestParseFail2banJail(t *testing.T) {
	count, ips := parseFail2banJail("|- Currently banned: 3\n`- Banned IP list:\t9.9.9.9\n")
	if count != 3 || len(ips) != 1 || ips[0] != "9.9.9.9" {
		t.Fatalf("解析=%d/%v 期望 3/[9.9.9.9]", count, ips)
	}
	count, ips = parseFail2banJail("被本地化的输出：没有可识别标签")
	if count != 0 || len(ips) != 0 {
		t.Fatalf("不可识别输出应返回 0，实际 %d/%v", count, ips)
	}
}
