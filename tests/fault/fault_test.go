// Package fault_test 是 ssh-guard 的基础故障注入测试（kill / timeout）。
//
// 用真实二进制 + UDS 握手做黑盒验证：
//   - kill fault：握手完成后 SIGKILL 插件进程，验证其立即退出、不残留；
//   - timeout fault：握手后不回响应，验证插件在 hello 超时（2s）内自行退出。
//
// basic 级的磁盘满 / cgroup 超限故障延 v1.1（提案 §2.1 批1）。
package fault_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// buildPlugin 把插件构建到临时目录，供两个故障用例共用。
func buildPlugin(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ssh-guard-fault-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "ssh-guard")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			buildErr = err
			t.Logf("build stderr: %s", stderr.String())
		}
	})
	if buildErr != nil {
		t.Fatalf("构建插件失败: %v", buildErr)
	}
	return binPath
}

// pluginHarness 启动插件并接受握手首帧；返回进程、连接与清场函数。
type pluginHarness struct {
	cmd  *exec.Cmd
	conn net.Conn
}

// startPlugin 启动插件进程并读到 kore.hello 首帧。
func startPlugin(t *testing.T) *pluginHarness {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "kore.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("监听 UDS 失败: %v", err)
	}
	bin := buildPlugin(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"KORE_PLUGIN_SOCK="+sock,
		"KORE_PLUGIN_ID=ssh-guard",
		"KORE_LOG_LEVEL=error",
	)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		t.Fatalf("启动插件失败: %v", err)
	}
	_ = ln.(*net.UnixListener).SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := ln.Accept()
	_ = ln.Close()
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("接受插件连接失败: %v", err)
	}
	h := &pluginHarness{cmd: cmd, conn: conn}
	t.Cleanup(func() {
		_ = conn.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	})
	method := h.readMethod(t)
	if method != "kore.hello" {
		t.Fatalf("握手首帧=%q，期望 kore.hello", method)
	}
	return h
}

// readMethod 从连接读一帧 hello 并返回其 method 字段。
func (h *pluginHarness) readMethod(t *testing.T) string {
	t.Helper()
	_ = h.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [4]byte
	if _, err := io.ReadFull(h.conn, hdr[:]); err != nil {
		t.Fatalf("读取帧头失败: %v", err)
	}
	payload := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(h.conn, payload); err != nil {
		t.Fatalf("读取帧体失败: %v", err)
	}
	env, err := pluginapi.DecodeFrame(payload)
	if err != nil {
		t.Fatalf("解码帧失败: %v", err)
	}
	request, ok := env.(*pluginapi.Request)
	if !ok {
		t.Fatalf("帧类型是 %T，不是 request", env)
	}
	return request.Method
}

// replyHello 回一个 ok=true 的握手响应，让插件进入会话循环。
func (h *pluginHarness) replyHello(t *testing.T) {
	t.Helper()
	result, err := json.Marshal(helloResult{OK: true, Protocol: pluginapi.Protocol})
	if err != nil {
		t.Fatal(err)
	}
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: "id-r1", ReqID: "r1", Result: result}
	if err := pluginapi.WriteJSON(h.conn, response); err != nil {
		t.Fatalf("回握手响应失败: %v", err)
	}
}

// helloResult 与插件侧握手响应结构一致。
type helloResult struct {
	OK       bool   `json:"ok"`
	Protocol string `json:"protocol"`
}

// waitExit 在给定时限内等待进程退出，返回 (是否按时退出, Wait 错误)。
func waitExit(cmd *exec.Cmd, timeout time.Duration) (bool, error) {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return true, err
	case <-time.After(timeout):
		return false, nil
	}
}

// isExitError 断言进程异常退出（被信号杀死或以非 0 码退出）。
func isExitError(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr)
}

// TestKillFault 握手完成后 SIGKILL 插件，验证进程立即退出（≤2s）。
func TestKillFault(t *testing.T) {
	h := startPlugin(t)
	h.replyHello(t)
	if err := h.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("发送 SIGKILL 失败: %v", err)
	}
	exited, err := waitExit(h.cmd, 2*time.Second)
	if !exited {
		t.Fatal("kill 后插件未能在 2s 内退出")
	}
	if err == nil || !isExitError(err) {
		t.Fatalf("被 SIGKILL 的进程应以 ExitError 退出，实际 err=%v", err)
	}
	t.Logf("kill fault: 进程已退出 err=%v", err)
}

// TestTimeoutFault 握手后故意不回响应，验证插件在 hello 超时内自行退出（≤5s）。
func TestTimeoutFault(t *testing.T) {
	h := startPlugin(t)
	// 不调用 replyHello：插件侧 helloTimeout=2s 应触发并以非 0 码退出。
	exited, err := waitExit(h.cmd, 5*time.Second)
	if !exited {
		t.Fatal("hello 超时后插件未能在 5s 内自行退出（可能未设置 deadline）")
	}
	if err == nil || !isExitError(err) {
		t.Fatalf("hello 超时应以非 0 码退出，实际 err=%v", err)
	}
	t.Logf("timeout fault: 进程已退出 err=%v", err)
}

// writeRawFrame 向插件侧连接写一个原始帧（4 字节长度前缀 + 载荷），用于注入非法帧。
func writeRawFrame(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		t.Fatalf("写帧头失败: %v", err)
	}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("写帧体失败: %v", err)
	}
}

// TestGarbageFrameFault 握手后注入无法解码的垃圾帧，验证插件立即退出（≤2s），
// 不进入"忽略坏帧继续跑"的降级——协议层要求解码失败即断开（§9）。
func TestGarbageFrameFault(t *testing.T) {
	h := startPlugin(t)
	h.replyHello(t)
	writeRawFrame(t, h.conn, []byte("garbage-not-a-frame"))
	exited, err := waitExit(h.cmd, 2*time.Second)
	if !exited {
		t.Fatal("垃圾帧后插件未能在 2s 内退出（应解码失败即断开）")
	}
	if err == nil || !isExitError(err) {
		t.Fatalf("垃圾帧应以非 0 码退出，实际 err=%v", err)
	}
	t.Logf("garbage frame fault: 进程已退出 err=%v", err)
}

// TestOversizedFrameFault 握手后注入超过 MaxFrameSize 的长度前缀（不发送载荷），
// 验证插件在读取前即拒绝并退出（≤2s），不分配 8 MiB+ 的缓冲。
func TestOversizedFrameFault(t *testing.T) {
	h := startPlugin(t)
	h.replyHello(t)
	oversized := pluginapi.MaxFrameSize + 1
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(oversized))
	if _, err := h.conn.Write(hdr[:]); err != nil {
		t.Fatalf("写超帧前缀失败: %v", err)
	}
	exited, err := waitExit(h.cmd, 2*time.Second)
	if !exited {
		t.Fatalf("超帧前缀后插件未能在 2s 内退出（长度=%d > MaxFrameSize=%d）", oversized, pluginapi.MaxFrameSize)
	}
	if err == nil || !isExitError(err) {
		t.Fatalf("超帧应以非 0 码退出，实际 err=%v", err)
	}
	t.Logf("oversized frame fault: 进程已退出 err=%v", err)
}
