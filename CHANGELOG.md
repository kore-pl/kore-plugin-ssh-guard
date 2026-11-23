# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.2.0] - 2026-11-23

### 新增

- **L1 → L1.5**：`ssh-guard.status` 新增防护源检测 `protection`（`available` / `engine` / `version` /
  `banned_count` / `failed_24h` / `log_source` / `hint`）：探测 fail2ban（`fail2ban-client status`，
  未装或 socket 不可用时如实降级）；以 sshd 日志统计为降级源，**不报错**。
- `ssh-guard.attempts {since?, source?, raw_limit?}`：只读日志解析聚合——`total` / `failed` /
  `invalid_users` / `successful_logins` / `unique_ips` / `top_ips`（top 10，失败数优先）/
  `timeline_hourly`（本地小时桶）/ `raw_tail`（最多 500 条、用户名脱敏为 ***）；
  支持 rsyslog ISO、journalctl short-iso 与经典 syslog 三种真实格式；尾部限读 1 MiB（`truncated` 标记）。
- `ssh-guard.bans {source?}`：fail2ban 活跃时读 sshd jail 的封禁清单；否则按可疑阈值
  （单小时失败 ≥ N，缺省 10）从日志推断可疑 IP（`applied` 恒 false，本插件不执行封禁）。
- `ssh-guard.config.get` / `ssh-guard.config.set`：日志路径 / 日志源 / 可疑阈值 / 原始行上限的
  配置契约；set 进程内生效（lazy 生命周期不落盘，诚实标注 `persisted:false`）。
- `ssh-guard.ban.add` / `ssh-guard.ban.remove`：写操作按 ADR-0018 降级口径返回 `E_NEED_ROOT` +
  可操作 hint + root_action 指向；**本轮只声明不验证成功路径**（本机非 root 且 fail2ban 未安装）。
- `info.json` 声明 `requires_root: true` 与 3 个 `root_actions`（`fail2ban-status` / `fail2ban-banip` /
  `fail2ban-unbanip`，固定 argv 不经 shell；ban/unban 标记 `irreversible`），经 pluginapi root action
  schema 校验通过。

### 变更

- 配置面新增 `KORE_SSHGUARD_LOG_PATH` / `KORE_SSHGUARD_LOG_SOURCE` / `KORE_SSHGUARD_THRESHOLD` /
  `KORE_SSHGUARD_RAW_TAIL` 环境变量（非法值回退缺省）。
- `tests/fault/` 扩到四类：kill -9、hello 超时之外新增垃圾帧（解码失败即断开）与超帧前缀
  （> 8 MiB 读取前拒绝）；既有 fault 断言零改动（纯追加）。

## [0.1.1] - 2026-11-23

- build: 位级可复现打包（stage chmod + tar --mode 归一、size_bytes 收敛），二进制改嵌 manifest.json，消除同版本 sha 漂移

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
