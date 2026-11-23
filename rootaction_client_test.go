package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startKernelSocket 起一个仅监听 UDS 的 HTTP 服务（模拟内核 root-action 端点），返回 socket 路径。
func startKernelSocket(t *testing.T, handler http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kore-rootaction-")
	if err != nil {
		t.Fatalf("创建临时目录: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "kore.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("监听 UDS: %v", err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket
}

// setKernelEnv 注入通道三要素（supervisor 在生产环境做的事）。
func setKernelEnv(t *testing.T, socket string) {
	t.Helper()
	t.Setenv("KORE_KERNEL_SOCK", socket)
	t.Setenv("KORE_PLUGIN_TOKEN", "test-token")
	t.Setenv("KORE_PLUGIN_ID", "ssh-guard")
}

// TestRootActionClientCall 校验真实 HTTP/UDS 契约：路径、bearer、action_id、输出与退出码。
func TestRootActionClientCall(t *testing.T) {
	requestOK := false
	socket := startKernelSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost ||
			r.URL.Path != "/api/v1/plugins/ssh-guard/root-action" {
			t.Errorf("请求行不符：%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization=%q，期望 Bearer test-token", got)
		}
		var body rootActionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("解析请求体: %v", err)
		}
		if body.ActionID != rootActionFail2banStatus || len(body.Args) != 0 {
			t.Errorf("请求体=%+v，期望 action_id=%s 且无追加参数", body, rootActionFail2banStatus)
		}
		requestOK = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rootActionResponse{
			Executed: true, ExitCode: 0, Stdout: fail2banJailFixture, Stderr: "", Unit: "kore-root-x",
		})
	}))
	setKernelEnv(t, socket)
	client := newRootActionClient()
	if client == nil {
		t.Fatal("三要素齐备时应构造出通道客户端")
	}
	if rootActionFuncFromEnv() == nil {
		t.Fatal("三要素齐备时应返回非 nil 调用面")
	}
	out, err := client.Call(rootActionFail2banStatus, nil, "")
	if err != nil {
		t.Fatalf("通道调用失败: %v", err)
	}
	if !requestOK {
		t.Fatal("内核侧未收到合法请求")
	}
	if out.ExitCode != 0 || out.Stdout != fail2banJailFixture {
		t.Fatalf("输出/退出码不符：%+v", out)
	}
}

// TestRootActionClientForwardsConfirm 不可回滚动作必须把 confirm 令牌放进请求体（内核据此核销）。
func TestRootActionClientForwardsConfirm(t *testing.T) {
	var got rootActionRequest
	socket := startKernelSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("解析请求体: %v", err)
		}
		_ = json.NewEncoder(w).Encode(rootActionResponse{Executed: true, ExitCode: 0, Stdout: "ok"})
	}))
	setKernelEnv(t, socket)
	out, err := newRootActionClient().Call(rootActionFail2banBanIP, []string{"203.0.113.7"}, "confirm-tok-1")
	if err != nil {
		t.Fatalf("通道调用失败: %v", err)
	}
	if out.ExitCode != 0 {
		t.Fatalf("退出码=%d，期望 0", out.ExitCode)
	}
	if got.ActionID != rootActionFail2banBanIP || len(got.Args) != 1 || got.Args[0] != "203.0.113.7" {
		t.Fatalf("请求体=%+v，期望 action_id=%s args=[203.0.113.7]", got, rootActionFail2banBanIP)
	}
	if got.Confirm != "confirm-tok-1" {
		t.Fatalf("confirm=%q，期望 confirm-tok-1（不可回滚动作必须透传令牌）", got.Confirm)
	}
}

// TestRootActionClientNonZeroExit 退出码透传（命令跑了但失败，例如 socket 不可连）。
func TestRootActionClientNonZeroExit(t *testing.T) {
	socket := startKernelSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(rootActionResponse{
			Executed: true, ExitCode: 255, Stderr: "ERROR:FAILED to connect to fail2ban socket",
		})
	}))
	setKernelEnv(t, socket)
	out, err := newRootActionClient().Call(rootActionFail2banStatus, nil, "")
	if err != nil {
		t.Fatalf("非零退出码不是通道错误: %v", err)
	}
	if out.ExitCode != 255 || !strings.Contains(out.Stderr, "FAILED to connect") {
		t.Fatalf("退出码/stderr 未透传：%+v", out)
	}
}

// TestRootActionClientProtocolError 内核拒绝（E_NEED_ROOT）时保留错误码与 hint。
func TestRootActionClientProtocolError(t *testing.T) {
	socket := startKernelSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(rootActionError{
			Code: "E_NEED_ROOT", Message: "需要 root 权限", Hint: "请用 sudo/systemd 启动 kored",
		})
	}))
	setKernelEnv(t, socket)
	_, err := newRootActionClient().Call(rootActionFail2banStatus, nil, "")
	if err == nil {
		t.Fatal("内核拒绝时应返回错误")
	}
	if !strings.Contains(err.Error(), "E_NEED_ROOT") || !strings.Contains(err.Error(), "请用 sudo/systemd 启动 kored") {
		t.Fatalf("错误应保留内核错误码与 hint：%v", err)
	}
}

// TestRootActionClientMissingEnv 三要素缺一 → 通道不可用（nil），不得 panic。
func TestRootActionClientMissingEnv(t *testing.T) {
	for _, missing := range []string{"KORE_KERNEL_SOCK", "KORE_PLUGIN_TOKEN", "KORE_PLUGIN_ID"} {
		t.Run(missing, func(t *testing.T) {
			setKernelEnv(t, "/tmp/does-not-exist.sock")
			t.Setenv(missing, "")
			if newRootActionClient() != nil || rootActionFuncFromEnv() != nil {
				t.Fatalf("%s 为空时应判定通道不可用", missing)
			}
		})
	}
}
