# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.1.0] - 2026-11-22

### 新增

- 首个 M5 批1 SSH 加固插件骨架（`depth_level = basic`、`lifecycle = lazy`），协议 `kore.plugin.v1` / 能力 `system:admin`。
- `kore.hello` 三步握手：发 `kore.hello`（§5 全字段 + `id`/`token` 别名）→ 读响应帧 → 校验 `ok`/`id`/协议主版本。
- 会话循环：读帧 → 按 `method` 分发 → 写 `response`，回显 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`。
- `ssh.status`：只读配置审计，检查 `PermitRootLogin` / `PasswordAuthentication` / `PermitEmptyPasswords` /
  `MaxAuthTries` / `ChallengeResponseAuthentication`，返回结构化 `checks` / `total` / `issues` / `applied:false`；
  配置文本来自请求内联或宿主注入，**不读不写真实 sshd_config**。
- `ssh.ban.list`：参数校验（`limit` 1..100、`offset` ≥0、`address` 合法 IP），返回空封禁清单与分页回显；
  basic 骨架不内置任何封禁执行器。
- 安全边界：配置文本 64 KiB 上限、严格 JSON 对象入参校验、禁止路径穿越；不捆绑 fail2ban/iptables/nftables 二进制。
- `Makefile`：`build` / `dist`（确定性打包 + 回填实际 tarball 字节数 + `SHA256SUMS` + 包旁 `.sha256`）/ `check` / `clean`。
- 单测与故障注入：`net.Pipe` 覆盖握手/方法/参数校验；`tests/fault/` 真实二进制 UDS 黑盒覆盖 `kill -9` 与 hello 超时。

### 说明

- 真实封禁执行器、配置落盘回滚、生产级故障注入（磁盘满 / cgroup 超限）延 v1.1。
