// Package main 是 kore 的 ssh-guard 插件：SSH 加固（配置审计 + 攻击统计 + 封禁视图）。
//
// 0.2.0（L1.5）：在只读配置审计之上新增真实日志统计与防护源检测——
//   - 日志只读：解析 auth.log / journalctl 的 sshd 记录（尾部限读 1 MiB），
//     聚合攻击尝试、可疑 IP 与时间线；用户名不进聚合视图（敏感值白名单：IP）。
//   - 防护源：探测 fail2ban（未装/不可用时以 sshd 日志统计降级，不报错）。
//   - 封禁/解封等写操作需要宿主 root：按 ADR-0018 声明 root_actions 交内核代理，
//     插件进程自身永不提权，非 root 时返回 E_NEED_ROOT + 可操作提示。
//
// 协议面（kore.plugin.v1）：连接内核注入的 UDS → kore.hello 握手 → 会话循环
// 读 request、按 method 分发并回 response；stdout 留给协议，日志一律写 stderr。
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
)

// main 按退出码区分失败：0 优雅退出、1 启动或协议失败。
func main() {
	logger := newLogger(os.Getenv("KORE_LOG_LEVEL"))
	if err := run(logger); err != nil {
		logger.Error("插件退出", "err", err)
		os.Exit(1)
	}
}

// run 依次完成建连、hello 握手与会话循环；收到 kore.shutdown 后返回 nil。
func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	conn, err := net.Dial("unix", cfg.socket)
	if err != nil {
		return fmt.Errorf("连接主壳 socket %s: %w", cfg.socket, err)
	}
	defer func() { _ = conn.Close() }()
	if err := handshake(conn, cfg); err != nil {
		return err
	}
	logger.Info("hello 完成", "plugin_id", cfg.id, "version", cfg.version)
	return serve(conn, &cfg, logger)
}
