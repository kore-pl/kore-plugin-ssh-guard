package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// writeAuthLog 写一份合成的 auth.log（只在本轮 t.TempDir() 里，用完随测试目录清理）。
func writeAuthLog(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("写合成日志失败: %v", err)
	}
	return path
}

// logLine 拼一条 rsyslog ISO 时间戳的 sshd 行（时间用相对偏移，保证落在窗口内）。
func logLine(t *testing.T, ago time.Duration, msg string) string {
	t.Helper()
	return logLineAt(time.Now().Add(-ago), msg)
}

// logLineAt 用**显式时刻**拼日志行：可疑 IP 推断按「自然小时分桶取最大值」判定，
// 用 now-偏移 会在整点附近把同一批失败拆进两个桶，导致用例随运行时刻抖动。
func logLineAt(at time.Time, msg string) string {
	return at.Format(time.RFC3339Nano) + " host sshd[4242]: " + msg
}

// dispatchWith 在进程内调用与 serve 同一入口的 dispatch（不建 socket、不碰宿主）。
func dispatchWith(t *testing.T, cfg *config, method string, params json.RawMessage) *pluginapi.Response {
	t.Helper()
	request := &pluginapi.Request{Type: pluginapi.TypeRequest, ID: "id-" + method, ReqID: "req-" + method, Method: method, Params: params}
	response, shutdown := dispatch(request, cfg, testLogger())
	if shutdown {
		t.Fatalf("%s 不应触发 kore.shutdown", method)
	}
	if response == nil {
		t.Fatalf("%s 返回 nil 响应", method)
	}
	return response
}

// TestWhitelistStorePersists 白名单必须真的落盘并可重载（否则"防误封自己"撑不过一次插件重启）。
func TestWhitelistStorePersists(t *testing.T) {
	dir := t.TempDir()
	store := newWhitelistStore(dir)
	if !store.Persisted() || store.Path() != filepath.Join(dir, whitelistFileName) {
		t.Fatalf("白名单未按插件数据目录落盘: persisted=%v path=%q", store.Persisted(), store.Path())
	}
	if _, added, err := store.Add("203.0.113.9", "手动填写", time.Now()); err != nil || !added {
		t.Fatalf("首次加入白名单失败: added=%v err=%v", added, err)
	}
	// 幂等：同一 IP 再加一次不重复、不覆盖原记录。
	if entry, added, err := store.Add("203.0.113.9", "重复", time.Now()); err != nil || added {
		t.Fatalf("重复加入应幂等: entry=%+v added=%v err=%v", entry, added, err)
	}
	if entry := store.Entries(); len(entry) != 1 || entry[0].Note != "手动填写" {
		t.Fatalf("重复加入不应覆盖原记录: %+v", entry)
	}
	info, err := os.Stat(filepath.Join(dir, whitelistFileName))
	if err != nil {
		t.Fatalf("白名单文件不存在: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("白名单文件权限=%#o，期望 0600（运维出口 IP 清单不给别人读）", info.Mode().Perm())
	}
	// 重载：新进程读到同一份内容。
	reloaded := newWhitelistStore(dir)
	if !reloaded.Contains("203.0.113.9") || !reloaded.Contains("::ffff:203.0.113.9") {
		t.Fatalf("重载后未命中白名单（IPv4-mapped IPv6 也必须等价命中）: %+v", reloaded.Entries())
	}
	if !reloaded.Remove("203.0.113.9") {
		t.Fatal("移除白名单条目失败")
	}
	if reloaded.Remove("203.0.113.9") {
		t.Fatal("重复移除应返回 false（幂等）")
	}
	if newWhitelistStore(dir).Contains("203.0.113.9") {
		t.Fatal("移除后重载仍命中：落盘内容没更新")
	}
}

// TestWhitelistAddThenBanRefused 是"防误封自己"的核心回归：白名单 IP 的封禁必须被
// 插件侧直接拒绝（E_CONFLICT），而且**不依赖提权通道**——没 root 的环境同样拦得住。
func TestWhitelistAddThenBanRefused(t *testing.T) {
	cfg := testConfig()
	cfg.whitelist = newWhitelistStore(t.TempDir())

	added := dispatchWith(t, &cfg, "ssh-guard.whitelist.add", json.RawMessage(`{"ip":"203.0.113.9","note":"最近一次成功 SSH 登录的 IP"}`))
	if added.Error != nil {
		t.Fatalf("加入白名单失败: %+v", added.Error)
	}
	var write whitelistWriteResult
	if err := json.Unmarshal(added.Result, &write); err != nil {
		t.Fatalf("解析白名单写结果失败: %v", err)
	}
	if !write.Added || write.Whitelist.Count != 1 || write.Whitelist.Entries[0].IP != "203.0.113.9" {
		t.Fatalf("白名单写结果不符: %+v", write)
	}

	// 白名单 IP 封禁 → E_CONFLICT（且 hint 指向"先移除白名单"）。
	refused := dispatchWith(t, &cfg, "ban.add", json.RawMessage(`{"ip":"203.0.113.9","confirm":"tok"}`))
	if refused.Error == nil || refused.Error.Code != pluginapi.E_CONFLICT {
		t.Fatalf("白名单 IP 封禁应 E_CONFLICT，实际 %+v", refused.Error)
	}
	if !strings.Contains(refused.Error.Message, "白名单") || !strings.Contains(string(refused.Error.Detail), "hint") {
		t.Fatalf("拒绝文案缺少白名单说明/detail：%+v", refused.Error)
	}

	// 非白名单 IP 仍走正常路径：无提权通道 → E_NEED_ROOT（证明上面的拦截是白名单特例，
	// 不是把所有封禁都挡成了 E_CONFLICT）。
	other := dispatchWith(t, &cfg, "ban.add", json.RawMessage(`{"ip":"198.51.100.9","confirm":"tok"}`))
	if other.Error == nil || other.Error.Code != needRootCode {
		t.Fatalf("非白名单 IP 应走提权通道降级 E_NEED_ROOT，实际 %+v", other.Error)
	}

	// 移除白名单后，同一 IP 恢复为"可封"（回到 E_NEED_ROOT，而不是继续被拦）。
	removed := dispatchWith(t, &cfg, "ssh-guard.whitelist.remove", json.RawMessage(`{"ip":"203.0.113.9"}`))
	if removed.Error != nil {
		t.Fatalf("移除白名单失败: %+v", removed.Error)
	}
	again := dispatchWith(t, &cfg, "ban.add", json.RawMessage(`{"ip":"203.0.113.9","confirm":"tok"}`))
	if again.Error == nil || again.Error.Code != needRootCode {
		t.Fatalf("移除白名单后应恢复为 E_NEED_ROOT，实际 %+v", again.Error)
	}
}

// TestWhitelistCandidatesFromLog 校验「你的 IP 是哪条」：候选来自成功登录日志，
// 最近一次成功登录的 IP 就是 current_ip，且加到白名单后 current_whitelisted=true。
func TestWhitelistCandidatesFromLog(t *testing.T) {
	cfg := testConfig()
	cfg.guard = defaultGuardConfig()
	cfg.guard.LogSource = "auth"
	cfg.guard.LogPath = writeAuthLog(t, []string{
		logLine(t, 3*time.Hour, "Accepted password for pt from 203.0.113.9 port 50000 ssh2"),
		logLine(t, 30*time.Minute, "Accepted publickey for pt from 198.51.100.20 port 50001 ssh2"),
		logLine(t, 20*time.Minute, "Failed password for root from 192.0.2.66 port 50002 ssh2"),
	})
	cfg.whitelist = newWhitelistStore(t.TempDir())

	read := dispatchWith(t, &cfg, "ssh-guard.whitelist", nil)
	var got whitelistResult
	if err := json.Unmarshal(read.Result, &got); err != nil {
		t.Fatalf("解析 whitelist 结果失败: %v", err)
	}
	if got.Count != 0 || len(got.Entries) != 0 {
		t.Fatalf("空白名单应为 0 条: %+v", got)
	}
	if got.CurrentIP != "198.51.100.20" {
		t.Fatalf("current_ip=%q，期望最近一次成功登录的 198.51.100.20（失败来源不应成为候选）", got.CurrentIP)
	}
	if len(got.Candidates) != 2 || got.Candidates[0].IP != "198.51.100.20" {
		t.Fatalf("候选应按最近成功登录降序且不含失败来源: %+v", got.Candidates)
	}
	if got.CurrentWhitelisted {
		t.Fatal("尚未加入白名单时 current_whitelisted 必须为 false")
	}

	write := dispatchWith(t, &cfg, "whitelist.add", json.RawMessage(`{"ip":"198.51.100.20","note":"最近一次成功 SSH 登录的 IP"}`))
	if write.Error != nil {
		t.Fatalf("加入白名单失败: %+v", write.Error)
	}
	var wrote whitelistWriteResult
	if err := json.Unmarshal(write.Result, &wrote); err != nil {
		t.Fatalf("解析白名单写结果失败: %v", err)
	}
	if !wrote.Whitelist.CurrentWhitelisted {
		t.Fatalf("加入后 current_whitelisted 应为 true: %+v", wrote.Whitelist)
	}
}

// TestBanListEnrichedFromLog 校验封禁清单的富化口径（无 fail2ban 的降级态）：
// 每条要有来源、触发规则、封禁时刻（并标明是日志推断）、白名单标记，且**不编造**
// 剩余时长（fail2ban bantime 未知 → remaining_s 缺省）。
func TestBanListEnrichedFromLog(t *testing.T) {
	cfg := testConfig()
	cfg.guard = defaultGuardConfig()
	cfg.guard.LogSource = "auth"
	cfg.guard.SuspiciousThreshold = 2
	// 整点前一小时的固定 5 分钟内：全部落在同一个自然小时桶里（推断按桶取最大值），
	// 不受"运行时刻离整点多近"影响，避免用例在城市时间边界上抖动。
	base := time.Now().Truncate(time.Hour).Add(-12 * time.Minute)
	cfg.guard.LogPath = writeAuthLog(t, []string{
		logLineAt(base, "Failed password for root from 203.0.113.7 port 40001 ssh2"),
		logLineAt(base.Add(time.Minute), "Failed password for admin from 203.0.113.7 port 40002 ssh2"),
		logLineAt(base.Add(2*time.Minute), "Failed password for root from 203.0.113.7 port 40003 ssh2"),
		logLineAt(base.Add(3*time.Minute), "Invalid user oracle from 192.0.2.55 port 40004 ssh2"),
		logLineAt(base.Add(4*time.Minute), "Failed password for postgres from 192.0.2.55 port 40006 ssh2"),
		logLine(t, 5*time.Minute, "Accepted password for pt from 198.51.100.20 port 40005 ssh2"),
	})
	cfg.whitelist = newWhitelistStore(t.TempDir())

	response := dispatchWith(t, &cfg, "ssh-guard.ban.list", json.RawMessage(`{"limit":10}`))
	if response.Error != nil {
		t.Fatalf("ban.list 失败: %+v", response.Error)
	}
	var result banListResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 ban.list 结果失败: %v", err)
	}
	if result.Count == 0 || len(result.Bans) == 0 {
		t.Fatalf("日志里有 3 次失败应产生可疑 IP: %+v", result)
	}
	top := result.Bans[0]
	if top.Address != "203.0.113.7" {
		t.Fatalf("Top 可疑 IP=%q，期望 203.0.113.7（失败最多）", top.Address)
	}
	if top.Source != banSourceLog || !strings.Contains(top.Rule, "阈值 2") {
		t.Fatalf("来源/触发规则未富化: %+v", top)
	}
	if top.Failures < 3 || top.BannedAt == "" || top.BannedAtSource != "log" {
		t.Fatalf("触发时刻/失败次数未富化: %+v", top)
	}
	if top.RemainingS != nil {
		t.Fatalf("bantime 未知时不应编造剩余时长: %+v", top)
	}
	// 成功登录来源不得出现在可疑清单里。
	for _, item := range result.Bans {
		if item.Address == "198.51.100.20" {
			t.Fatalf("成功登录的 IP 不该被当成可疑来源: %+v", item)
		}
	}
	// 按地址精确过滤 + 分页回显。
	filtered := dispatchWith(t, &cfg, "ban.list", json.RawMessage(`{"address":"192.0.2.55","limit":5}`))
	var only banListResult
	if err := json.Unmarshal(filtered.Result, &only); err != nil {
		t.Fatalf("解析过滤结果失败: %v", err)
	}
	if only.Count != 1 || len(only.Bans) != 1 || only.Bans[0].Address != "192.0.2.55" || only.Limit != 5 {
		t.Fatalf("地址过滤/分页回显不符: %+v", only)
	}
}

// TestBanListFail2banRemaining 校验 fail2ban 活跃态：真实封禁清单 + 本插件封禁时刻 +
// 已知 bantime → 剩余时长可算；未观测过的封禁不编造剩余时长。
func TestBanListFail2banRemaining(t *testing.T) {
	cfg := testConfig()
	cfg.guard = defaultGuardConfig()
	cfg.guard.LogSource = "auth"
	cfg.guard.LogPath = writeAuthLog(t, []string{
		logLine(t, 20*time.Minute, "Failed password for root from 203.0.113.7 port 41001 ssh2"),
	})
	cfg.guard.BantimeS = 3600
	cfg.whitelist = newWhitelistStore(t.TempDir())

	stubLookPath(t, true)
	fake := &fakeRootAction{output: rootActionOutput{Stdout: fail2banJailFixture}}
	old := guardRootAction
	guardRootAction = fake.call
	t.Cleanup(func() { guardRootAction = old })

	// 本插件 10 分钟前亲手封了 203.0.113.7（账本记录），198.51.100.9 是别人封的（无账本）。
	cfg.banledger.Record("203.0.113.7", time.Now().Add(-10*time.Minute), "")

	response := dispatchWith(t, &cfg, "ssh-guard.ban.list", nil)
	if response.Error != nil {
		t.Fatalf("ban.list 失败: %+v", response.Error)
	}
	var result banListResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 ban.list 结果失败: %v", err)
	}
	if result.Engine != "fail2ban" || !result.Available || result.Source != banSourceFail2ban {
		t.Fatalf("fail2ban 活跃时应报告真实封禁清单: %+v", result)
	}
	if result.Count != 2 {
		t.Fatalf("jail 有 2 条封禁，实际 %d: %+v", result.Count, result.Bans)
	}
	for _, item := range result.Bans {
		switch item.Address {
		case "203.0.113.7":
			if item.BannedAtSource != "observed" || item.RemainingS == nil {
				t.Fatalf("本插件封禁的 IP 应有 observed 时刻与剩余时长: %+v", item)
			}
			if left := *item.RemainingS; left < 2900 || left > 3600 {
				t.Fatalf("剩余时长=%d 秒，期望约 3000（1 小时 bantime - 已封 10 分钟）", left)
			}
		case "198.51.100.9":
			if item.RemainingS != nil {
				t.Fatalf("没有观测时刻时不应编造剩余时长: %+v", item)
			}
		default:
			t.Fatalf("出现未预期的封禁记录: %+v", item)
		}
	}
	// 白名单标注：把封禁中的 IP 加进白名单后，清单要能报出自锁风险。
	if _, _, err := cfg.whitelist.Add("198.51.100.9", "受信运维", time.Now()); err != nil {
		t.Fatalf("加白名单失败: %v", err)
	}
	second := dispatchWith(t, &cfg, "ssh-guard.ban.list", nil)
	var after banListResult
	if err := json.Unmarshal(second.Result, &after); err != nil {
		t.Fatalf("解析结果失败: %v", err)
	}
	if after.Whitelisted != 1 {
		t.Fatalf("白名单中仍被封着的 IP 数=%d，期望 1（页面据此提示自锁）", after.Whitelisted)
	}
	wl := dispatchWith(t, &cfg, "ssh-guard.whitelist", nil)
	var status whitelistResult
	if err := json.Unmarshal(wl.Result, &status); err != nil {
		t.Fatalf("解析白名单结果失败: %v", err)
	}
	if len(status.BannedWhitelisted) != 1 || status.BannedWhitelisted[0] != "198.51.100.9" {
		t.Fatalf("banned_whitelisted 未报告自锁 IP: %+v", status)
	}
}

// TestAttemptsKinds 校验失败类型聚合：三种真实日志文本族各自归类，占比以 failed 为分母。
func TestAttemptsKinds(t *testing.T) {
	cfg := testConfig()
	cfg.guard = defaultGuardConfig()
	cfg.guard.LogSource = "auth"
	cfg.guard.LogPath = writeAuthLog(t, []string{
		logLine(t, 30*time.Minute, "Failed password for root from 203.0.113.7 port 42001 ssh2"),
		logLine(t, 29*time.Minute, "Failed password for invalid user bob from 203.0.113.7 port 42002 ssh2"),
		logLine(t, 28*time.Minute, "Invalid user admin from 192.0.2.55 port 42003 ssh2"),
		logLine(t, 27*time.Minute, "error: maximum authentication attempts exceeded for invalid user admin from 192.0.2.55 port 42004 ssh2 [preauth]"),
		logLine(t, 26*time.Minute, "Accepted password for pt from 198.51.100.20 port 42005 ssh2"),
	})
	since := time.Now().Add(-2 * time.Hour).Format(time.RFC3339)
	params, err := json.Marshal(map[string]any{"since": since, "raw_limit": 0})
	if err != nil {
		t.Fatal(err)
	}
	response := dispatchWith(t, &cfg, "ssh-guard.attempts", params)
	if response.Error != nil {
		t.Fatalf("attempts 失败: %+v", response.Error)
	}
	var result attemptsResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析 attempts 结果失败: %v", err)
	}
	if result.Failed != 4 {
		t.Fatalf("failed=%d，期望 4（3 条 Failed password + 1 条 Invalid user）", result.Failed)
	}
	got := map[string]int{}
	ratioSum := 0
	for _, kind := range result.Kinds {
		got[kind.Kind] = kind.Count
		ratioSum += kind.Ratio
		if kind.Label == "" {
			t.Fatalf("失败类型缺少展示名: %+v", kind)
		}
	}
	want := map[string]int{failKindPassword: 1, failKindInvalidUs: 2, failKindTooMany: 1}
	for kind, count := range want {
		if got[kind] != count {
			t.Fatalf("失败类型 %s 次数=%d，期望 %d（全部: %+v）", kind, got[kind], count, result.Kinds)
		}
	}
	if ratioSum != 100 {
		t.Fatalf("各失败类型占比合计=%d%%，期望 100%%（分母是 failed）: %+v", ratioSum, result.Kinds)
	}
}
