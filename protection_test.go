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

// fakeRootAction 是 rootActionFunc 的内存实现：记录被调用的 action id，返回预置输出。
type fakeRootAction struct {
	calls  []string
	output rootActionOutput
	err    error
}

func (f *fakeRootAction) call(actionID string, args []string) (rootActionOutput, error) {
	f.calls = append(f.calls, actionID)
	return f.output, f.err
}

// fail2banJailFixture 是 `fail2ban-client status sshd` 的最小可解析输出。
const fail2banJailFixture = "Status for the jail: sshd\n" +
	"|- Filter\n" +
	"|  |- Currently failed: 0\n" +
	"`- Actions\n" +
	"   |- Currently banned: 2\n" +
	"   |- Total banned:     7\n" +
	"   `- Banned IP list:   203.0.113.7 198.51.100.9"

// stubLookPath 替换 lookPath 并记录被查询的路径名；existing 控制声明路径是否存在/可执行。
func stubLookPath(t *testing.T, existing bool) *[]string {
	t.Helper()
	asked := make([]string, 0, 2)
	old := lookPath
	t.Cleanup(func() { lookPath = old })
	lookPath = func(name string) (string, error) {
		asked = append(asked, name)
		if !existing {
			return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
		}
		return name, nil
	}
	return &asked
}

// TestProbeFail2banNotInstalled 声明路径不存在 → 全零态，且只查声明绝对路径（不问 PATH 裸名）。
func TestProbeFail2banNotInstalled(t *testing.T) {
	asked := stubLookPath(t, false)
	st := probeFail2ban(nil)
	if st.Installed || st.Active || st.CurrentlyBanned != 0 || len(st.BannedIPs) != 0 {
		t.Fatalf("未安装应全零：%+v", st)
	}
	if len(*asked) != 1 || (*asked)[0] != fail2banClientPath {
		t.Fatalf("只应探测声明绝对路径 %q，实际 %v", fail2banClientPath, *asked)
	}
}

// TestProbeFail2banViaRootAction 已安装 + 通道成功 → 经 fail2ban-status 读取并解析 jail。
func TestProbeFail2banViaRootAction(t *testing.T) {
	stubLookPath(t, true)
	fake := &fakeRootAction{output: rootActionOutput{Stdout: fail2banJailFixture}}
	st := probeFail2ban(fake.call)
	if !st.Installed || !st.Active || !st.Channel {
		t.Fatalf("应为安装且活跃（经通道）：%+v", st)
	}
	if st.CurrentlyBanned != 2 {
		t.Fatalf("Currently banned 解析=%d 期望 2", st.CurrentlyBanned)
	}
	if len(st.BannedIPs) != 2 || st.BannedIPs[0] != "203.0.113.7" {
		t.Fatalf("Banned IP list 解析=%v", st.BannedIPs)
	}
	if len(fake.calls) != 1 || fake.calls[0] != rootActionFail2banStatus {
		t.Fatalf("应调用声明的 %q，实际 %v", rootActionFail2banStatus, fake.calls)
	}
	if st.ProbeErr != "" {
		t.Fatalf("成功态不应有错误：%q", st.ProbeErr)
	}
}

// TestProbeFail2banChannelUnavailable 已安装但内核未注入通道 → installed=true/active=false，
// hint 指向缺失的 root-action 通道与动作 id（不再进程内直呼客户端）。
func TestProbeFail2banChannelUnavailable(t *testing.T) {
	stubLookPath(t, true)
	st := probeFail2ban(nil)
	if !st.Installed || st.Active || st.Channel {
		t.Fatalf("通道缺失应为已安装/未活跃：%+v", st)
	}
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth",
		SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, nil)
	if !strings.Contains(info.Hint, "KORE_KERNEL_SOCK") || !strings.Contains(info.Hint, rootActionFail2banStatus) {
		t.Fatalf("hint 应指明缺失通道与动作 id：%q", info.Hint)
	}
}

// TestProbeFail2banChannelError 通道报 E_NEED_ROOT → active=false，原因进入 hint。
func TestProbeFail2banChannelError(t *testing.T) {
	stubLookPath(t, true)
	fake := &fakeRootAction{err: errors.New("E_NEED_ROOT: 需要 root 权限：请用 sudo/systemd 启动 kored（用 `sudo kored` 启动）")}
	st := probeFail2ban(fake.call)
	if !st.Installed || st.Active {
		t.Fatalf("通道失败应为已安装/未活跃：%+v", st)
	}
	if !strings.Contains(st.ProbeErr, "E_NEED_ROOT") {
		t.Fatalf("ProbeErr 应保留内核错误码：%q", st.ProbeErr)
	}
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth",
		SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, fake.call)
	if info.Fail2banActive {
		t.Fatalf("通道失败不应报活跃：%+v", info)
	}
	if !strings.Contains(info.Hint, "E_NEED_ROOT") || !strings.Contains(info.Hint, rootActionFail2banStatus) {
		t.Fatalf("hint 应含错误码与动作 id：%q", info.Hint)
	}
}

// TestProbeFail2banExitNonZero 通道执行成功但命令退出码非 0 → 未活跃 + 原因含 stderr 首行。
func TestProbeFail2banExitNonZero(t *testing.T) {
	stubLookPath(t, true)
	fake := &fakeRootAction{output: rootActionOutput{
		ExitCode: 255,
		Stderr:   "ERROR:FAILED to connect to fail2ban socket\n（更多输出略）",
	}}
	st := probeFail2ban(fake.call)
	if !st.Installed || st.Active {
		t.Fatalf("非零退出码应为已安装/未活跃：%+v", st)
	}
	if !strings.Contains(st.ProbeErr, "退出码 255") || !strings.Contains(st.ProbeErr, "FAILED to connect") {
		t.Fatalf("ProbeErr 应含退出码与 stderr 首行：%q", st.ProbeErr)
	}
}

// TestDetectProtectionSshdFallback fail2ban 未装 + auth.log 可读 → engine=sshd、available=true。
// 日志时间戳取"当前时间往前 1 小时"确保落在 failed_24h 窗口内（不依赖具体日期）。
func TestDetectProtectionSshdFallback(t *testing.T) {
	stubLookPath(t, false)
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
	info := detectProtection(g, nil) // 通道未注入：fail2ban 未安装态
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

// TestDetectProtectionNone 日志不可读 + fail2ban 未装 → available=false、engine=none、hint 可操作。
func TestDetectProtectionNone(t *testing.T) {
	stubLookPath(t, false)
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth",
		SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, nil)
	if info.Available || info.Engine != "none" || info.LogSource != "none" {
		t.Fatalf("应如实报不可用：%+v", info)
	}
	if !strings.Contains(info.Hint, "均不可读") {
		t.Fatalf("hint 应说明日志不可读：%q", info.Hint)
	}
}

// TestDetectProtectionFail2banPrimary fail2ban 经通道读取成功 → engine=fail2ban、计数取自 jail。
func TestDetectProtectionFail2banPrimary(t *testing.T) {
	stubLookPath(t, true)
	fake := &fakeRootAction{output: rootActionOutput{Stdout: fail2banJailFixture}}
	g := guardConfig{LogPath: filepath.Join(t.TempDir(), "missing.log"), LogSource: "auth",
		SuspiciousThreshold: 10, RawTailLimit: 200}
	info := detectProtection(g, fake.call)
	if !info.Available || info.Engine != "fail2ban" {
		t.Fatalf("fail2ban 活跃应为可用主引擎：%+v", info)
	}
	if info.BannedCount != 2 || !info.Fail2banActive || !info.Fail2banInstalled {
		t.Fatalf("封禁计数/标志不符：%+v", info)
	}
	if info.EngineVersion != "" {
		t.Fatalf("经通道读取不填充 version（status sshd 输出不含版本），实际 %q", info.EngineVersion)
	}
}

// TestProtectionHintUninstalled 校验诚实口径：未安装写"fail2ban 未安装；以 sshd 日志统计为降级源"，
// 并给出声明路径（跨发行版缺路径时的可操作线索）。
func TestProtectionHintUninstalled(t *testing.T) {
	hint := protectionHint(fail2banState{}, "auth", defaultGuardConfig())
	if !strings.Contains(hint, "fail2ban 未安装") || !strings.Contains(hint, "以 sshd 日志统计为降级源") {
		t.Fatalf("hint 缺诚实口径：%q", hint)
	}
	if !strings.Contains(hint, fail2banClientPath) {
		t.Fatalf("hint 应含声明的绝对路径：%q", hint)
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
