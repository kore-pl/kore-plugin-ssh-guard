package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// invoke 发一个请求并读回响应与 serve 结束状态（每个用例独立连接）。
func invoke(t *testing.T, method, reqID string, params json.RawMessage) *pluginapi.Response {
	t.Helper()
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := startServe(pluginConn)
	writeRequest(t, kernelConn, method, reqID, params)
	response := readResponse(t, kernelConn)
	writeRequest(t, kernelConn, "kore.shutdown", "r-shutdown", nil)
	if shutdown := readResponse(t, kernelConn); string(shutdown.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", shutdown.Result)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
	return response
}

// resultString 断言无错误并返回 result 原文。
func resultString(t *testing.T, response *pluginapi.Response) string {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("意外错误: code=%s message=%s", response.Error.Code, response.Error.Message)
	}
	return string(response.Result)
}

// TestStatusMethods 覆盖 status 裸名/全名与 req_id 回显。
func TestStatusMethods(t *testing.T) {
	for _, method := range []string{"status", "ssh-guard.status"} {
		t.Run(method, func(t *testing.T) {
			response := invoke(t, method, "r-1", nil)
			if response.ReqID != "r-1" {
				t.Fatalf("req_id=%q，期望回显 r-1", response.ReqID)
			}
			var result statusAuditResult
			if err := json.Unmarshal(response.Result, &result); err != nil {
				t.Fatalf("解析 status 结果失败: %v", err)
			}
			if result.Status != "ready" || result.Applied {
				t.Fatalf("status/applied=%q/%v，期望 ready/false", result.Status, result.Applied)
			}
			if result.Total != len(auditRules) || len(result.Checks) != len(auditRules) {
				t.Fatalf("total/checks=%d/%d，期望 %d", result.Total, len(result.Checks), len(auditRules))
			}
		})
	}
}

// TestStatusAudit 校验审计建议：合规项与不合规项分别判定。
func TestStatusAudit(t *testing.T) {
	params := json.RawMessage(`{"sshd_config":"PermitRootLogin prohibit-password\nPasswordAuthentication no\nPermitEmptyPasswords no\nMaxAuthTries 3\nChallengeResponseAuthentication no\n"}`)
	var result statusAuditResult
	if err := json.Unmarshal([]byte(resultString(t, invoke(t, "ssh-guard.status", "r-2", params))), &result); err != nil {
		t.Fatal(err)
	}
	if result.Issues != 0 {
		t.Fatalf("全合规配置 issues=%d，期望 0：%+v", result.Issues, result.Checks)
	}
	weak := json.RawMessage(`{"sshd_config":"PermitRootLogin yes # root 登录\nPasswordAuthentication yes\n"}`)
	if err := json.Unmarshal([]byte(resultString(t, invoke(t, "status", "r-3", weak))), &result); err != nil {
		t.Fatal(err)
	}
	if result.Issues < 4 {
		t.Fatalf("弱配置 issues=%d，期望至少 4：%+v", result.Issues, result.Checks)
	}
	if result.Checks[0].Current != "yes" || result.Checks[0].Compliant {
		t.Fatalf("PermitRootLogin 检查错误：%+v", result.Checks[0])
	}
	if !strings.Contains(result.Checks[0].Advice, "root") {
		t.Fatalf("建议缺少修复方向：%q", result.Checks[0].Advice)
	}
}

// TestBanListMethods 校验 ban.list 的裸名/全名、分页与空清单。
func TestBanListMethods(t *testing.T) {
	for _, method := range []string{"ban.list", "ssh-guard.ban.list"} {
		t.Run(method, func(t *testing.T) {
			var result banListResult
			response := invoke(t, method, "r-b", nil)
			if err := json.Unmarshal([]byte(resultString(t, response)), &result); err != nil {
				t.Fatal(err)
			}
			if result.Count != 0 || len(result.Bans) != 0 || result.Applied {
				t.Fatalf("ban.list=%+v，期望空清单且 applied=false", result)
			}
			if result.Limit != 20 || result.Offset != 0 {
				t.Fatalf("默认分页=%+v，期望 limit=20 offset=0", result)
			}
		})
	}
	paged := json.RawMessage(`{"limit":5,"offset":10,"address":"192.168.1.1"}`)
	var result banListResult
	if err := json.Unmarshal([]byte(resultString(t, invoke(t, "ban.list", "r-p", paged))), &result); err != nil {
		t.Fatal(err)
	}
	if result.Limit != 5 || result.Offset != 10 {
		t.Fatalf("分页回显=%+v，期望 limit=5 offset=10", result)
	}
}

// TestInvalidParams 覆盖非法参数：非对象、limit 越界、负 offset、非法 IP、超长配置。
func TestInvalidParams(t *testing.T) {
	cases := []struct {
		name     string
		method   string
		params   json.RawMessage
		contains string
	}{
		{"非对象", "status", json.RawMessage(`"x"`), "params 必须是 JSON 对象"},
		{"字段类型错配", "ban.list", json.RawMessage(`{"limit":"abc"}`), "params 解析失败"},
		{"limit 为 0", "ban.list", json.RawMessage(`{"limit":0}`), "limit 必须在 1..100"},
		{"limit 超 100", "ban.list", json.RawMessage(`{"limit":101}`), "limit 必须在 1..100"},
		{"负 offset", "ban.list", json.RawMessage(`{"offset":-1}`), "offset 不能为负"},
		{"非法 IP", "ban.list", json.RawMessage(`{"address":"999.1.1.1"}`), "address 不是合法 IP"},
		{"超长配置", "status", json.RawMessage(`{"sshd_config":"` + strings.Repeat("x", 70000) + `"}`), "64 KiB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, tc.method, "r-e", tc.params)
			if response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("期望 E_INVALID，实际 error=%v result=%s", response.Error, response.Result)
			}
			if !strings.Contains(response.Error.Message, tc.contains) {
				t.Fatalf("error message=%q，期望包含 %q", response.Error.Message, tc.contains)
			}
		})
	}
}

// TestUnknownMethod 未知方法回 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	response := invoke(t, "ssh-guard.nope", "r-1", nil)
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("error=%v，期望 E_NOTFOUND", response.Error)
	}
}

// TestAuditParseDirectives 校验注释、重复项与等号写法的解析。
func TestAuditParseDirectives(t *testing.T) {
	text := "# PermitRootLogin yes\nPermitRootLogin prohibit-password\nPasswordAuthentication=no # 注释\nInclude /etc/ssh/extra.conf\n"
	values := parseDirectives(text)
	if values["permitrootlogin"] != "prohibit-password" {
		t.Fatalf("重复项应取首次有效值，实际 %q", values["permitrootlogin"])
	}
	if values["passwordauthentication"] != "no" {
		t.Fatalf("等号写法解析失败：%q", values["passwordauthentication"])
	}
	if _, ok := values["include"]; ok {
		t.Fatal("Include 行应被忽略")
	}
}
