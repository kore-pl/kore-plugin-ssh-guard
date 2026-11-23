package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// testConfig 构造握手与会话循环共用的一致配置（不依赖环境变量）。
// guard 与真实 loadConfig 一致：从缺省值起底（不读环境，保证测试确定性）。
func testConfig() config {
	return config{
		id:           "ssh-guard",
		version:      "0.1.0",
		requiresKore: ">=0.1.0 <0.2.0",
		capabilities: []string{"system:admin"},
		startedAt:    time.Now(),
		guard:        defaultGuardConfig(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startServe(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	cfg := testConfig()
	go func() {
		err := serve(conn, &cfg, testLogger())
		_ = conn.Close()
		done <- err
	}()
	return done
}

func readFrame(t *testing.T, conn net.Conn) any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := pluginapi.ReadFrame(conn, pluginapi.MaxFrameSize)
	if err != nil {
		t.Fatalf("读帧失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	return env
}

func readRequest(t *testing.T, conn net.Conn) *pluginapi.Request {
	t.Helper()
	env := readFrame(t, conn)
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request
}

func readResponse(t *testing.T, conn net.Conn) *pluginapi.Response {
	t.Helper()
	env := readFrame(t, conn)
	response, ok := env.(*pluginapi.Response)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 response", env)
	}
	return response
}

func writeRequest(t *testing.T, conn net.Conn, method, reqID string, params json.RawMessage) {
	t.Helper()
	request := &pluginapi.Request{
		Type: pluginapi.TypeRequest, ID: "id-" + reqID, ReqID: reqID, Method: method, Params: params,
	}
	if err := pluginapi.WriteJSON(conn, request); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
}

func writeResponse(t *testing.T, conn net.Conn, id, reqID string, result json.RawMessage) {
	t.Helper()
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: id, ReqID: reqID, Result: result}
	if err := pluginapi.WriteJSON(conn, response); err != nil {
		t.Fatalf("写响应失败: %v", err)
	}
}

// TestHandshake 校验 hello 首帧字段与三步握手。
func TestHandshake(t *testing.T) {
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := make(chan error, 1)
	go func() { done <- handshake(pluginConn, testConfig()); _ = pluginConn.Close() }()

	request := readRequest(t, kernelConn)
	if request.Method != helloMethod {
		t.Fatalf("首帧方法=%q，期望 %q", request.Method, helloMethod)
	}
	var params helloParams
	if err := json.Unmarshal(request.Params, &params); err != nil {
		t.Fatalf("解析 hello 参数失败: %v", err)
	}
	if params.PluginID != "ssh-guard" || params.ID != "ssh-guard" {
		t.Fatalf("plugin_id/id=%q/%q，期望都是 ssh-guard", params.PluginID, params.ID)
	}
	if params.Protocol != pluginapi.Protocol || params.Version != "0.1.0" {
		t.Fatalf("protocol/version=%q/%q 不符合 §5", params.Protocol, params.Version)
	}
	if params.PID != os.Getpid() {
		t.Fatalf("pid=%d，期望 %d", params.PID, os.Getpid())
	}
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatalf("序列化握手响应失败: %v", err)
	}
	writeResponse(t, kernelConn, request.ID, request.ReqID, result)
	if err := <-done; err != nil {
		t.Fatalf("握手返回错误: %v", err)
	}
}
