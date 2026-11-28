package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// capabilityManifest 是 info.json 中本文件关心的方法级能力 + root 动作声明。
// 不复用 declaration_test.go 的 declaredManifest：那里没有 method_capabilities，
// 这里显式定形（G-24），两处各自覆盖自己的field子集。
type capabilityManifest struct {
	ID                 string               `json:"id"`
	Version            string               `json:"version"`
	Capabilities       []string             `json:"capabilities"`
	MethodCapabilities map[string]string    `json:"method_capabilities"`
	RootActions        []declaredRootAction `json:"root_actions"`
}

// expectedMethodCapabilities 是本仓 12 条方法级能力的唯一期望表：
// 9 个业务方法（methods.go 的 businessVerb 白名单）+ 2 个配置面板契约方法 + 1 个白名单写方法。
//
// 只读 6 条 → system:read（status / attempts / bans / ban.list / whitelist / suggest；config.get 同为只读）；
// 写 5 条 → system:admin（ban.add / ban.remove / whitelist.add / whitelist.remove；config.set 同为写）。
// 分类错误的后果是把写权限降给只读会话，因此这张表也是"只读/写"分类的验收依据。
var expectedMethodCapabilities = map[string]string{
	"status":             "system:read",
	"attempts":           "system:read",
	"bans":               "system:read",
	"suggest":            "system:read",
	"ban.list":           "system:read",
	"whitelist":          "system:read",
	"ban.add":            "system:admin",
	"ban.remove":         "system:admin",
	"whitelist.add":      "system:admin",
	"whitelist.remove":   "system:admin",
	"config.get":         "system:read",
	"config.set":         "system:admin",
	"apply-hardening":    "system:admin",
	"rollback-hardening": "system:admin",
}

// privilegedCapabilitySet 是内核唯一白名单（internal/core/registry/validate.go）。
var privilegedCapabilitySet = map[string]struct{}{
	"system:read": {}, "system:admin": {},
	"net:read": {}, "net:write": {},
	"proc:read": {}, "proc:write": {},
}

// loadCapabilityManifest 读取仓根 info.json。
func loadCapabilityManifest(t *testing.T) capabilityManifest {
	t.Helper()
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json: %v", err)
	}
	var m capabilityManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	return m
}

// TestMethodCapabilitiesMatchMethods 表驱动校验方法级能力声明与实现面一致：
//   - 条数 = 12（9 业务 + 2 config + 1 whitelist 写），键域必须是 ssh-guard.<action>；
//   - 每个键都能被 businessVerb 接受（声明 ⊆ 实现），且 businessVerb 白名单里的每个方法
//     都有声明（实现 ⊆ 声明）；
//   - 值只能是 6 项特权能力，且只读/写分类与 expectedMethodCapabilities 一致。
func TestMethodCapabilitiesMatchMethods(t *testing.T) {
	m := loadCapabilityManifest(t)
	if m.ID != "ssh-guard" {
		t.Fatalf("info.json id=%q，期望 ssh-guard", m.ID)
	}
	if len(m.MethodCapabilities) != len(expectedMethodCapabilities) {
		t.Fatalf("method_capabilities 声明 %d 条，期望 %d 条（9 业务方法 + config.get/set + whitelist 写）",
			len(m.MethodCapabilities), len(expectedMethodCapabilities))
	}
	prefix := m.ID + "."
	declared := make(map[string]string, len(m.MethodCapabilities))
	for method, capability := range m.MethodCapabilities {
		if !strings.HasPrefix(method, prefix) {
			t.Fatalf("方法键 %q 必须以插件自身 id 为域（应为 %s<action>）", method, prefix)
		}
		action := strings.TrimPrefix(method, prefix)
		if _, ok := expectedMethodCapabilities[action]; !ok {
			t.Fatalf("info.json 声明了未预期的方法键 %q（实现面没有对应分发路径，声明漂移）", method)
		}
		if _, ok := privilegedCapabilitySet[capability]; !ok {
			t.Fatalf("%s 的能力值 %q 不是 6 项特权能力之一", method, capability)
		}
		if _, ok := businessVerb(action, m.ID); !ok {
			t.Fatalf("info.json 声明了 %q，但 methods.go 的 businessVerb 不接受它（声明 ⊆ 实现 失败）", action)
		}
		declared[action] = capability
	}
	// 实现 ⊆ 声明：businessVerb 白名单里的方法一个都不能漏声明。
	for action := range expectedMethodCapabilities {
		if _, ok := businessVerb(action, m.ID); !ok {
			t.Fatalf("businessVerb 不接受 %q，与期望表不一致", action)
		}
		if _, ok := declared[action]; !ok {
			t.Fatalf("%q 在实现里可分发，但 info.json 未声明方法级能力（未声明会回退插件级 system:admin）", action)
		}
	}
	// 只读 / 写分类逐条锁定。
	for action, want := range expectedMethodCapabilities {
		if got := declared[action]; got != want {
			t.Fatalf("方法 %q 的能力=%q，期望 %q（读方法只能 read，写方法必须 admin）", action, got, want)
		}
	}
	// 反向：未声明的动词不得被分发（防"实现了但没声明"与"声明了但没实现"两侧漂移）。
	if _, ok := businessVerb("deploy", m.ID); ok {
		t.Fatal("businessVerb 不应接受未声明的动词 deploy")
	}
}

// TestBanArgvShapeAcceptedByKernelPolicy 用公开 SDK 复核「声明 argv + 运行时追加参数」的形状：
// 合法 IP 作为唯一追加参数应通过；带注入字符的串必须被内核侧（shapeIPOrCIDR）拒绝。
// 这是插件 net.ParseIP 校验之外的第二道防线（插件被攻破也不能把任意串送进 argv）。
func TestBanArgvShapeAcceptedByKernelPolicy(t *testing.T) {
	m := loadCapabilityManifest(t)
	argvOf := func(id string) []string {
		for _, action := range m.RootActions {
			if action.ID == id {
				return action.Argv
			}
		}
		t.Fatalf("info.json 缺少 root action %q", id)
		return nil
	}
	for _, id := range []string{rootActionFail2banBanIP, rootActionFail2banUnbanIP} {
		argv := argvOf(id)
		if err := pluginapi.ValidateRootAppendedArgv(argv, []string{"203.0.113.7"}); err != nil {
			t.Fatalf("%s + 合法 IP 应通过 SDK 形状校验: %v", id, err)
		}
		if err := pluginapi.ValidateRootAppendedArgv(argv, []string{"::1"}); err != nil {
			t.Fatalf("%s + 合法 IPv6 应通过 SDK 形状校验: %v", id, err)
		}
		for _, bad := range []string{"203.0.113.7; id", "203.0.113.7 && reboot", "$(id)", "203.0.113.7\n1.2.3.4"} {
			if err := pluginapi.ValidateRootAppendedArgv(argv, []string{bad}); err == nil {
				t.Fatalf("%s + 注入串 %q 必须被 SDK 形状校验拒绝", id, bad)
			}
		}
	}
}

// invokeBanWrite 在注入 fake 提权通道 + 声明路径存在的前提下调用写方法。
func invokeBanWrite(t *testing.T, fake *fakeRootAction, method, params string) *pluginapi.Response {
	t.Helper()
	stubLookPath(t, true)
	old := guardRootAction
	guardRootAction = fake.call
	t.Cleanup(func() { guardRootAction = old })
	return invoke(t, method, "r-ban-write", json.RawMessage(params))
}

// TestBanAddExecutesViaChannel 封禁执行链路：ban.add → fail2ban-banip（argv 固定 + IP 追加 +
// confirm 令牌）→ fail2ban-status 回读 → 结果含真实执行信息与回读证明。
func TestBanAddExecutesViaChannel(t *testing.T) {
	fake := &fakeRootAction{results: []fakeRootResult{
		{output: rootActionOutput{ExitCode: 0, Stdout: "OK\n"}},
		{output: rootActionOutput{ExitCode: 0, Stdout: fail2banJailFixture}},
	}}
	response := invokeBanWrite(t, fake, "ssh-guard.ban.add", `{"ip":"203.0.113.7","confirm":"confirm-tok-1"}`)
	resultString(t, response)

	var result banWriteResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析结果失败: %v", err)
	}
	// 调用顺序与 argv 形状：先 banip（只追加 IP），再 status（无追加参数）回读。
	if len(fake.calls) != 2 || fake.calls[0] != rootActionFail2banBanIP || fake.calls[1] != rootActionFail2banStatus {
		t.Fatalf("通道调用序列=%v，期望 [%s %s]", fake.calls, rootActionFail2banBanIP, rootActionFail2banStatus)
	}
	if len(fake.args[0]) != 1 || fake.args[0][0] != "203.0.113.7" {
		t.Fatalf("banip 追加参数=%v，期望恰为 [203.0.113.7]", fake.args[0])
	}
	if len(fake.args[1]) != 0 {
		t.Fatalf("status 回读不应带追加参数，实际 %v", fake.args[1])
	}
	if fake.confirms[0] != "confirm-tok-1" {
		t.Fatalf("banip 的 confirm=%q，期望原样转发 confirm-tok-1", fake.confirms[0])
	}
	if result.Applied != true || result.ExitCode != 0 || result.Action != rootActionFail2banBanIP {
		t.Fatalf("执行结果=%+v，期望 applied=true/exit=0/action=%s", result, rootActionFail2banBanIP)
	}
	if !result.Verified || result.BannedCount != 2 || !containsIP(result.Banned, "203.0.113.7") {
		t.Fatalf("回读证明不足：verified=%v count=%d banned=%v", result.Verified, result.BannedCount, result.Banned)
	}
	if result.IP != "203.0.113.7" {
		t.Fatalf("ip=%q，期望回显 203.0.113.7", result.IP)
	}
}

// TestBanAddRequiresConfirm 不可回滚动作缺令牌 → E_UNAUTHORIZED + hint，且不发任何命令。
func TestBanAddRequiresConfirm(t *testing.T) {
	fake := &fakeRootAction{}
	response := invokeBanWrite(t, fake, "ban.add", `{"ip":"203.0.113.7"}`)
	if response.Error == nil || response.Error.Code != pluginapi.E_UNAUTHORIZED {
		t.Fatalf("缺 confirm 应 E_UNAUTHORIZED，实际 %v", response.Error)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("缺令牌时不得调用提权通道，实际调用 %v", fake.calls)
	}
	var detail rootHintDetail
	if err := json.Unmarshal(response.Error.Detail, &detail); err != nil {
		t.Fatalf("detail 解析失败: %v", err)
	}
	if detail.RootAction != rootActionFail2banBanIP || !strings.Contains(detail.Hint, "confirm-token") {
		t.Fatalf("detail 应指向 %s 并给出 confirm-token 获取路径：%+v", rootActionFail2banBanIP, detail)
	}
}

// TestBanRemoveExecutesWithoutConfirm 解封是恢复性动作：不需要 confirm，回读应看到 IP 已移除。
func TestBanRemoveExecutesWithoutConfirm(t *testing.T) {
	afterUnban := "Status for the jail: sshd\n" +
		"`- Actions\n" +
		"   |- Currently banned: 1\n" +
		"   `- Banned IP list:   198.51.100.9"
	fake := &fakeRootAction{results: []fakeRootResult{
		{output: rootActionOutput{ExitCode: 0, Stdout: "OK\n"}},
		{output: rootActionOutput{ExitCode: 0, Stdout: afterUnban}},
	}}
	response := invokeBanWrite(t, fake, "ban.remove", `{"ip":"203.0.113.7"}`)
	resultString(t, response)

	var result banWriteResult
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatalf("解析结果失败: %v", err)
	}
	if fake.calls[0] != rootActionFail2banUnbanIP {
		t.Fatalf("首个动作=%q，期望 %s", fake.calls[0], rootActionFail2banUnbanIP)
	}
	if fake.confirms[0] != "" {
		t.Fatalf("unbanip 不应携带 confirm，实际 %q", fake.confirms[0])
	}
	if !result.Applied || !result.Verified {
		t.Fatalf("解封应 applied=true verified=true，实际 %+v", result)
	}
	if containsIP(result.Banned, "203.0.113.7") {
		t.Fatalf("回读清单不应再含已解封 IP：%v", result.Banned)
	}
}

// TestBanWriteRejectsIPInjection IP 校验是注入防线：非纯 IP 字面量一律 E_INVALID，
// 且**不得**触达到提权通道（命令根本不发起）。
func TestBanWriteRejectsIPInjection(t *testing.T) {
	cases := []struct{ name, ip string }{
		{"分号注入", "203.0.113.7; id"},
		{"命令串联", "203.0.113.7 && reboot"},
		{"命令替换", "$(id)"},
		{"反引号", "`id`"},
		{"换行注入", "203.0.113.7\n1.2.3.4"},
		{"空格多 IP", "203.0.113.7 198.51.100.9"},
		{"通配", "*"},
		{"all", "all"},
		{"CIDR", "203.0.113.0/24"},
		{"越界段", "999.1.1.1"},
		{"空串", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRootAction{}
			params, _ := json.Marshal(banWriteParams{IP: tc.ip, Confirm: "confirm-tok-1"})
			response := invokeBanWrite(t, fake, "ban.add", string(params))
			if response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("ip=%q 应 E_INVALID，实际 %v", tc.ip, response.Error)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("ip=%q 非法时不得调用提权通道，实际 %v", tc.ip, fake.calls)
			}
		})
	}
}

// TestBanWriteKernelErrorCodesPreserved 通道/内核拒绝时保留内核错误码（不吞成泛化错误）。
func TestBanWriteKernelErrorCodesPreserved(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"需要 root", errors.New("E_NEED_ROOT: 需要 root 权限：请用 sudo/systemd 启动 kored"), needRootCode},
		{"没有 systemd", errors.New("E_NO_SYSTEMD: 环境不支持提权通道：systemd 不可用"), pluginapi.E_NO_SYSTEMD},
		{"令牌无效", errors.New("E_UNAUTHORIZED: confirm 令牌无效或已被使用"), pluginapi.E_UNAUTHORIZED},
		{"其他", errors.New("调用内核 root-action 失败：connection reset"), pluginapi.E_INTERNAL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeRootAction{err: tc.err, results: []fakeRootResult{{err: tc.err}}}
			response := invokeBanWrite(t, fake, "ban.add", `{"ip":"203.0.113.7","confirm":"confirm-tok-1"}`)
			if response.Error == nil || response.Error.Code != tc.want {
				t.Fatalf("错误码=%v，期望 %s", response.Error, tc.want)
			}
			if !strings.Contains(response.Error.Message, tc.err.Error()) {
				t.Fatalf("错误信息应保留底层原因：%q", response.Error.Message)
			}
		})
	}
}

// TestBanWriteExecFailure 命令跑了但退出码非 0 → 显式失败（E_INTERNAL + detail），绝不返回 applied=true。
func TestBanWriteExecFailure(t *testing.T) {
	fake := &fakeRootAction{results: []fakeRootResult{
		{output: rootActionOutput{ExitCode: 255, Stderr: "ERROR: FAILED to connect to fail2ban socket\n"}},
	}}
	response := invokeBanWrite(t, fake, "ban.add", `{"ip":"203.0.113.7","confirm":"confirm-tok-1"}`)
	if response.Error == nil || response.Error.Code != pluginapi.E_INTERNAL {
		t.Fatalf("退出码 255 应 E_INTERNAL，实际 %v", response.Error)
	}
	if response.Result != nil {
		t.Fatalf("失败时不得返回 result：%s", response.Result)
	}
	var detail banExecErrorDetail
	if err := json.Unmarshal(response.Error.Detail, &detail); err != nil {
		t.Fatalf("detail 解析失败: %v", err)
	}
	if detail.ExitCode != 255 || !strings.Contains(detail.Stderr, "FAILED to connect") {
		t.Fatalf("detail 应含退出码与 stderr 摘要：%+v", detail)
	}
	// 执行失败后不应再发 status 回读（省一次提权动作）。
	if len(fake.calls) != 1 {
		t.Fatalf("执行失败后不应回读，实际调用 %v", fake.calls)
	}
}

// TestBanWriteReadbackUnverified 执行成功但回读不可用 / 与预期不符 → verified=false + note，
// 仍然 applied=true（命令确实跑了），不静默也不假装生效。
func TestBanWriteReadbackUnverified(t *testing.T) {
	t.Run("回读失败", func(t *testing.T) {
		fake := &fakeRootAction{results: []fakeRootResult{
			{output: rootActionOutput{ExitCode: 0}},
			{output: rootActionOutput{ExitCode: 255, Stderr: "ERROR: FAILED to connect"}},
		}}
		response := invokeBanWrite(t, fake, "ban.add", `{"ip":"203.0.113.7","confirm":"t"}`)
		resultString(t, response)
		var result banWriteResult
		if err := json.Unmarshal(response.Result, &result); err != nil {
			t.Fatalf("解析结果失败: %v", err)
		}
		if !result.Applied || result.Verified {
			t.Fatalf("applied 应为 true、verified 应为 false：%+v", result)
		}
		if !strings.Contains(result.Note, "回读失败") {
			t.Fatalf("note 应说明回读失败原因：%q", result.Note)
		}
	})
	t.Run("回读与预期不符", func(t *testing.T) {
		// 封禁 192.0.2.55，但回读清单（fixture：203.0.113.7 / 198.51.100.9）里没有它 → verified=false。
		fake := &fakeRootAction{results: []fakeRootResult{
			{output: rootActionOutput{ExitCode: 0}},
			{output: rootActionOutput{ExitCode: 0, Stdout: fail2banJailFixture}},
		}}
		response := invokeBanWrite(t, fake, "ban.add", `{"ip":"192.0.2.55","confirm":"t"}`)
		resultString(t, response)
		var result banWriteResult
		if err := json.Unmarshal(response.Result, &result); err != nil {
			t.Fatalf("解析结果失败: %v", err)
		}
		if !result.Applied || result.Verified {
			t.Fatalf("applied 应为 true、verified 应为 false：%+v", result)
		}
		if !strings.Contains(result.Note, "回读与预期不符") {
			t.Fatalf("note 应指出回读与预期不符：%q", result.Note)
		}
	})
}

// TestStatusConfigSource 降权可用性口径：审计文本来源显式暴露；
// 未拿到文本时 config_source=none + note 说明「(未设置) 不等于宿主不合规」。
func TestStatusConfigSource(t *testing.T) {
	t.Run("请求内联", func(t *testing.T) {
		response := invoke(t, "status", "r-src-1",
			json.RawMessage(`{"sshd_config":"PermitRootLogin prohibit-password\nPasswordAuthentication no"}`))
		var result statusAuditResult
		if err := json.Unmarshal([]byte(resultString(t, response)), &result); err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if result.ConfigSource != configSourceRequest {
			t.Fatalf("config_source=%q，期望 %q", result.ConfigSource, configSourceRequest)
		}
		if result.Note != "" {
			t.Fatalf("有文本时不应有降级说明：%q", result.Note)
		}
	})
	t.Run("无文本", func(t *testing.T) {
		response := invoke(t, "status", "r-src-2", nil)
		var result statusAuditResult
		if err := json.Unmarshal([]byte(resultString(t, response)), &result); err != nil {
			t.Fatalf("解析失败: %v", err)
		}
		if result.ConfigSource != configSourceNone {
			t.Fatalf("config_source=%q，期望 %q（测试用 config 无注入文本）", result.ConfigSource, configSourceNone)
		}
		if !strings.Contains(result.Note, "不代表宿主配置不合规") {
			t.Fatalf("note 必须点明缺失文本不等于不合规：%q", result.Note)
		}
		if result.Issues != len(auditRules) {
			t.Fatalf("issues=%d，期望 %d（无文本时 5 条均为未设置）", result.Issues, len(auditRules))
		}
	})
}

// TestParseConfigTextSource 单测口径：来源优先级 请求 > 宿主注入 > none。
func TestParseConfigTextSource(t *testing.T) {
	cfg := config{sshdConfig: "PermitRootLogin no"}
	text, source, perr := parseConfigText(nil, cfg)
	if perr != nil || text != "PermitRootLogin no" || source != configSourceHost {
		t.Fatalf("宿主注入路径：text=%q source=%q perr=%v", text, source, perr)
	}
	text, source, perr = parseConfigText(json.RawMessage(`{"sshd_config":"PasswordAuthentication no"}`), cfg)
	if perr != nil || text != "PasswordAuthentication no" || source != configSourceRequest {
		t.Fatalf("请求内联路径：text=%q source=%q perr=%v", text, source, perr)
	}
	text, source, perr = parseConfigText(nil, config{})
	if perr != nil || text != "" || source != configSourceNone {
		t.Fatalf("无文本路径：text=%q source=%q perr=%v", text, source, perr)
	}
}
