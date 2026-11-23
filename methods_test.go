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

// TestAttemptsParams 覆盖 ssh.attempts 的参数校验。
func TestAttemptsParams(t *testing.T) {
	cases := []struct {
		name     string
		params   json.RawMessage
		contains string
	}{
		{"非对象", json.RawMessage(`"x"`), "params 必须是 JSON 对象"},
		{"since 非法", json.RawMessage(`{"since":"yesterday"}`), "RFC3339"},
		{"since 未来", json.RawMessage(`{"since":"2099-01-01T00:00:00Z"}`), "不能晚于当前时间"},
		{"since 超 7 天", json.RawMessage(`{"since":"2020-01-01T00:00:00Z"}`), "7 天前"},
		{"source 非法", json.RawMessage(`{"source":"syslog-ng"}`), "source 只支持"},
		{"raw_limit 超 500", json.RawMessage(`{"raw_limit":501}`), "raw_limit 必须在 0..500"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, "attempts", "r-a", tc.params)
			if response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("期望 E_INVALID，实际 error=%v result=%s", response.Error, response.Result)
			}
			if !strings.Contains(response.Error.Message, tc.contains) {
				t.Fatalf("message=%q 缺 %q", response.Error.Message, tc.contains)
			}
		})
	}
}

// TestAttemptsResult 结构与降级：默认参数可调用，聚合字段齐全、raw_tail 已脱敏、切片非 nil。
func TestAttemptsResult(t *testing.T) {
	response := invoke(t, "ssh-guard.attempts", "r-at", nil)
	var result attemptsResult
	if err := json.Unmarshal([]byte(resultString(t, response)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Source == "" || result.Since == "" || result.Until == "" {
		t.Fatalf("source/since/until 缺失：%+v", result)
	}
	if result.TopIPs == nil || result.TimelineHourly == nil || result.RawTail == nil {
		t.Fatalf("切片字段必须非 nil（显式 schema）：%+v", result)
	}
	// raw_tail 已脱敏：任何回传行都不含用户名（本机无攻击流量，行数可能为 0，但结构必须成立）。
	for _, line := range result.RawTail {
		if strings.Contains(line, " for pt from ") && !strings.Contains(line, "***") {
			t.Fatalf("原始行未脱敏：%s", line)
		}
	}
}

// TestBansResult 校验 ssh.bans 结构：applied=false、threshold 回显、bans 非 nil。
func TestBansResult(t *testing.T) {
	response := invoke(t, "ssh-guard.bans", "r-bans", nil)
	var result bansResult
	if err := json.Unmarshal([]byte(resultString(t, response)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Applied {
		t.Fatal("bans 是只读方法，applied 必须 false")
	}
	if result.Threshold != 10 {
		t.Fatalf("threshold=%d 期望缺省 10", result.Threshold)
	}
	if result.Bans == nil {
		t.Fatal("bans 必须非 nil")
	}
	// source 覆盖参数校验。
	if response := invoke(t, "bans", "r-bans2", json.RawMessage(`{"source":"bad"}`)); response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
		t.Fatalf("非法 source 应 E_INVALID，实际 %v", response.Error)
	}
}

// TestConfigGetSet 校验配置契约：get 缺省值、set 校验与进程内生效、不落盘声明。
func TestConfigGetSet(t *testing.T) {
	var got configResult
	if err := json.Unmarshal([]byte(resultString(t, invoke(t, "ssh-guard.config.get", "r-g", nil))), &got); err != nil {
		t.Fatal(err)
	}
	if got.LogPath != "/var/log/auth.log" || got.LogSource != "auto" || got.SuspiciousThreshold != 10 || got.RawTailLimit != 200 {
		t.Fatalf("缺省配置不符：%+v", got)
	}
	if got.Persisted {
		t.Fatal("lazy 插件不落盘，persisted 必须 false")
	}
	// 非法参数全部 E_INVALID。
	bad := []struct {
		name   string
		params json.RawMessage
	}{
		{"相对路径", json.RawMessage(`{"log_path":"var/log/x.log"}`)},
		{"空路径", json.RawMessage(`{"log_path":""}`)},
		{"非法源", json.RawMessage(`{"log_source":"file"}`)},
		{"阈值 0", json.RawMessage(`{"suspicious_threshold":0}`)},
		{"阈值超限", json.RawMessage(`{"suspicious_threshold":10001}`)},
		{"raw_tail 超 500", json.RawMessage(`{"raw_tail_limit":501}`)},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if response := invoke(t, "config.set", "r-s", tc.params); response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("期望 E_INVALID，实际 %v", response.Error)
			}
		})
	}
	// 合法 set → get 回读生效：必须走**同一连接**（invoke 每次新建配置实例）。
	set := json.RawMessage(`{"log_source":"journal","suspicious_threshold":25,"raw_tail_limit":100,"log_path":"/var/log/other.log"}`)
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := startServe(pluginConn)
	writeRequest(t, kernelConn, "config.set", "r-s2", set)
	var updated configResult
	if err := json.Unmarshal([]byte(resultString(t, readResponse(t, kernelConn))), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.LogSource != "journal" || updated.SuspiciousThreshold != 25 || updated.RawTailLimit != 100 || updated.LogPath != "/var/log/other.log" {
		t.Fatalf("set 未生效：%+v", updated)
	}
	writeRequest(t, kernelConn, "config.get", "r-g2", nil)
	if err := json.Unmarshal([]byte(resultString(t, readResponse(t, kernelConn))), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.SuspiciousThreshold != 25 {
		t.Fatalf("set 后 get 应读到 25，实际 %d", updated.SuspiciousThreshold)
	}
	writeRequest(t, kernelConn, "kore.shutdown", "r-shutdown", nil)
	if shutdown := readResponse(t, kernelConn); string(shutdown.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", shutdown.Result)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
}

// TestBanWriteNeedsRoot 校验写操作降级口径：E_NEED_ROOT + hint + root_action 指向。
func TestBanWriteNeedsRoot(t *testing.T) {
	cases := []struct {
		verb   string
		action string
	}{
		{"ban.add", "fail2ban-banip"},
		{"ban.remove", "fail2ban-unbanip"},
		{"ssh-guard.ban.add", "fail2ban-banip"},
	}
	for _, tc := range cases {
		t.Run(tc.verb, func(t *testing.T) {
			response := invoke(t, tc.verb, "r-w", json.RawMessage(`{"ip":"203.0.113.7"}`))
			if response.Error == nil || response.Error.Code != "E_NEED_ROOT" {
				t.Fatalf("期望 E_NEED_ROOT，实际 %v", response.Error)
			}
			var detail rootHintDetail
			if err := json.Unmarshal(response.Error.Detail, &detail); err != nil {
				t.Fatalf("detail 解析失败: %v", err)
			}
			if detail.RootAction != tc.action {
				t.Fatalf("root_action=%q 期望 %q", detail.RootAction, tc.action)
			}
			if !strings.Contains(detail.Hint, "sudo 启动 kored") {
				t.Fatalf("hint 应含可操作路径：%q", detail.Hint)
			}
		})
	}
	// 非法 IP → E_INVALID（不是 E_NEED_ROOT）。
	if response := invoke(t, "ban.add", "r-w2", json.RawMessage(`{"ip":"999.9.9.9"}`)); response.Error == nil || response.Error.Code != pluginapi.E_INVALID {
		t.Fatalf("非法 IP 应 E_INVALID，实际 %v", response.Error)
	}
}
