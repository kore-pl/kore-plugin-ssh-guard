package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// stubCurrentConfig 让 suggest 读到可控的“当前配置”（默认不可读走错误分支）。
func stubCurrentConfig(t *testing.T, text string, err error) {
	t.Helper()
	oldPath, oldRead := sshdConfigPath, readSSHDConfig
	sshdConfigPath = "/tmp/kore-suggest-test-sshd_config"
	readSSHDConfig = func(string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(text), nil
	}
	t.Cleanup(func() { sshdConfigPath, readSSHDConfig = oldPath, oldRead })
}

func invokeSuggest(t *testing.T, params string) suggestResult {
	t.Helper()
	resp := invoke(t, "ssh-guard.suggest", "r-suggest", json.RawMessage(params))
	if resp.Error != nil {
		t.Fatalf("suggest 失败: %+v", resp.Error)
	}
	var got suggestResult
	if err := json.Unmarshal([]byte(resultString(t, resp)), &got); err != nil {
		t.Fatalf("解析 suggest 结果: %v", err)
	}
	return got
}

// TestSuggestIdempotentAndFourCombos 四种开关组合的 config_text 快照 + 同参两次同文本。
func TestSuggestIdempotentAndFourCombos(t *testing.T) {
	stubCurrentConfig(t, "Include /etc/ssh/sshd_config.d/*.conf\n", nil)
	cases := []struct {
		name         string
		params       string
		wantAuth     bool
		wantRoot     bool
		wantRiskCode []string
	}{
		{"不加固", `{}`, false, false, nil},
		{"仅禁密码", `{"disable_password_auth":true}`, true, false, []string{"disable_password_auth"}},
		{"仅禁root", `{"disable_root_login":true}`, false, true, []string{"disable_root_login"}},
		{"禁密码+禁root", `{"disable_password_auth":true,"disable_root_login":true}`, true, true, []string{"disable_password_auth", "disable_root_login"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first := invokeSuggest(t, c.params)
			second := invokeSuggest(t, c.params)
			if first.ConfigText != second.ConfigText {
				t.Fatalf("同参数两次 config_text 不一致（不幂等）:\n%s\n---\n%s", first.ConfigText, second.ConfigText)
			}
			if got := strings.Contains(first.ConfigText, "PasswordAuthentication no"); got != c.wantAuth {
				t.Fatalf("PasswordAuthentication 出现=%v，期望 %v:\n%s", got, c.wantAuth, first.ConfigText)
			}
			if got := strings.Contains(first.ConfigText, "PermitRootLogin no"); got != c.wantRoot {
				t.Fatalf("PermitRootLogin 出现=%v，期望 %v:\n%s", got, c.wantRoot, first.ConfigText)
			}
			if len(first.Risk) != len(c.wantRiskCode) {
				t.Fatalf("risk 条数=%d，期望 %d: %+v", len(first.Risk), len(c.wantRiskCode), first.Risk)
			}
			for i, code := range c.wantRiskCode {
				if first.Risk[i].Code != code || first.Risk[i].Rollback == "" {
					t.Fatalf("risk[%d]=%+v，期望 code=%s 且 rollback 非空", i, first.Risk[i], code)
				}
			}
			if !first.DryRun {
				t.Fatal("suggest 必须 dry_run=true（不写宿主）")
			}
		})
	}
}

// TestSuggestRiskRules 改 port / 禁密码 / 禁 root / MaxAuthTries 各自命中规则。
func TestSuggestRiskRules(t *testing.T) {
	stubCurrentConfig(t, "", errors.New("permission denied"))
	got := invokeSuggest(t, `{"disable_password_auth":true,"disable_root_login":true,"port":2222,"max_auth_tries":3}`)
	want := []string{"port_change", "disable_password_auth", "disable_root_login", "max_auth_tries"}
	if len(got.Risk) != len(want) {
		t.Fatalf("risk 条数=%d，期望 %d: %+v", len(got.Risk), len(want), got.Risk)
	}
	for i, code := range want {
		if got.Risk[i].Code != code {
			t.Fatalf("risk[%d].Code=%q，期望 %q", i, got.Risk[i].Code, code)
		}
		if got.Risk[i].Message == "" || got.Risk[i].Rollback == "" {
			t.Fatalf("risk %s 缺少提示或回滚说明: %+v", code, got.Risk[i])
		}
	}
	if !strings.Contains(got.Risk[0].Message, "2222/tcp") || !strings.Contains(got.Risk[0].Message, "ssh -p 2222") {
		t.Fatalf("port 风险应给出放行与验证命令: %+v", got.Risk[0])
	}
}

// TestSuggestApplyCommandsNoPlaceholders 命令序列可直接复制：关键步骤齐备且无占位符残留。
func TestSuggestApplyCommandsNoPlaceholders(t *testing.T) {
	stubCurrentConfig(t, "", errors.New("permission denied"))
	got := invokeSuggest(t, `{"disable_password_auth":true,"port":2222}`)
	joined := strings.Join(got.ApplyCommands, "\n")
	for _, want := range []string{"cp -a /etc/ssh/sshd_config", "install -d -m 0755 /etc/ssh/sshd_config.d", "tee /etc/ssh/sshd_config.d/kore.conf", "sshd -t", "systemctl reload sshd", "PasswordAuthentication no", "Port 2222"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("apply_commands 缺少 %q:\n%s", want, joined)
		}
	}
	bad := []string{"<your", "<port>", "<ip>", "<path>", "TODO", "XXX", "YOUR_", "changeme", "placeholder"}
	for _, line := range got.ApplyCommands {
		lower := strings.ToLower(line)
		for _, token := range bad {
			if strings.Contains(lower, token) {
				t.Fatalf("apply_commands 含占位符 %q: %q", token, line)
			}
		}
	}
	if len(got.VerifyCommands) == 0 {
		t.Fatal("verify_commands 不能为空")
	}
	if v := strings.Join(got.VerifyCommands, "\n"); !strings.Contains(v, "sshd -T") {
		t.Fatalf("verify_commands 应使用 sshd -T: %s", v)
	}
}

// TestSuggestDiffFromCurrent 可读主配置时给出关键项 current vs suggested 对比。
func TestSuggestDiffFromCurrent(t *testing.T) {
	stubCurrentConfig(t, "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPasswordAuthentication yes\nPermitRootLogin prohibit-password\n", nil)
	got := invokeSuggest(t, `{"disable_password_auth":true,"disable_root_login":true,"port":2222}`)
	if len(got.DiffFromCurrent) != 3 {
		t.Fatalf("diff 条数=%d，期望 3: %+v", len(got.DiffFromCurrent), got.DiffFromCurrent)
	}
	want := map[string]string{"PasswordAuthentication": "yes", "PermitRootLogin": "prohibit-password", "Port": "22"}
	for _, item := range got.DiffFromCurrent {
		if want[item.Directive] != item.Current {
			t.Fatalf("%s current=%q，期望 %q", item.Directive, item.Current, want[item.Directive])
		}
		if item.Suggested == "" || item.Suggested == item.Current {
			t.Fatalf("%s 未给出有差异的建议值: %+v", item.Directive, item)
		}
	}
	if !strings.Contains(got.PathHint, "已包含 Include") {
		t.Fatalf("可读且含 Include 时 path_hint 不对: %s", got.PathHint)
	}
}

// TestSuggestUnreadableConfig 读不到主配置时不给 diff，path_hint 说明原因。
func TestSuggestUnreadableConfig(t *testing.T) {
	stubCurrentConfig(t, "", errors.New("open /etc/ssh/sshd_config: permission denied"))
	got := invokeSuggest(t, `{"disable_password_auth":true}`)
	if len(got.DiffFromCurrent) != 0 {
		t.Fatalf("不可读时不应有 diff: %+v", got.DiffFromCurrent)
	}
	if !strings.Contains(got.PathHint, "读不到") || !strings.Contains(got.PathHint, "无法给出当前值对比") {
		t.Fatalf("path_hint 应解释不可读原因: %s", got.PathHint)
	}
	if !strings.Contains(got.PathHint, dropInPath) {
		t.Fatalf("path_hint 应给出建议路径: %s", got.PathHint)
	}
}

// TestSuggestInvalidParams 端口/尝试次数越界直接 E_INVALID，不生成建议。
func TestSuggestInvalidParams(t *testing.T) {
	cases := []string{
		`{"port":70000}`,
		`{"port":-1}`,
		`{"max_auth_tries":101}`,
		`{"max_auth_tries":-1}`,
		`[]`,
	}
	for _, params := range cases {
		resp := invoke(t, "ssh-guard.suggest", "r-bad", json.RawMessage(params))
		if resp.Error == nil || resp.Error.Code != pluginapi.E_INVALID {
			t.Fatalf("params=%s 期望 E_INVALID，得到 %+v", params, resp.Error)
		}
	}
}
