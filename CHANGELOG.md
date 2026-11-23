# Changelog

本仓库遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与语义化版本。

## [0.3.0] - 2026-11-23

### 新增（sshd 加固建议态，非自动下发）

- **`ssh-guard.suggest`（只读 `system:read`，`dry_run` 恒 true）**：入参
  `{disable_password_auth?, disable_root_login?, port?, max_auth_tries?}`，返回
  `{config_text, path_hint, diff_from_current?, risk[], apply_commands[], verify_commands[], dry_run}`。
  `config_text` 是分段注释的 `/etc/ssh/sshd_config.d/kore.conf` drop-in；`diff_from_current` 只在主配置
  可读时给出当前值 vs 建议值；读不到则 `path_hint` 说明原因。
- **风险提示带回滚**：改 port → 先放行新端口并 `ssh -p` 验证；禁密码 → 确认已有可用密钥且当前不是唯一
  密码会话；禁 root → 确认有可 sudo 的普通用户；每条风险附具体回滚步骤。
- **可复制命令**：`apply_commands[]` 串起 `cp -a` 时间戳备份 → `install -d` + `tee` 写 drop-in →
  `sshd -t` 校验 → `systemctl reload sshd`（每步带注释、无占位符）；`verify_commands[]` 用 `sshd -T | grep`。

### 边界（诚实声明）

- **不写宿主**：内核没有受控文件写原语，`sshd -t` / `systemctl reload sshd` 不在 ADR-0022 形状表内，
  插件以非 root 运行；`apply` / `rollback` 真机下发待 v1.1（需 ADR-0022 增补受控写原语）。
  本版本只生成建议与命令，用户确认后手工执行。
- 现有 `ban.add` / `ban.remove` 的真实执行（0.2.2 起）不受影响。

## [0.2.3] - 2026-11-23

### Changed

- 提升为 `production` 深度等级（故障注入测试已覆盖）

## [0.2.2] - 2026-11-23

### 新增（封禁执行落地，§2「仍缺」的最后一块）

- **`ssh.ban.add` / `ssh.ban.remove` 真实执行**（0.2.1 之前 `handleBanWrite` 恒返 `E_NEED_ROOT`，只声明不执行）：
  经内核 root-action 通道执行 `info.json` 声明的固定 argv
  `/usr/bin/fail2ban-client set sshd banip|unbanip <ip>`。插件仍以非 root 运行、永不提权（ADR-0018）；
  argv 由清单锁死，IP 只能作为**唯一**追加参数，内核按协议 `shapeIPOrCIDR` 复核。
- **执行后回读证明**：`banip` / `unbanip` 成功后自动经 `fail2ban-status` 动作回读 sshd jail，返回
  `{ip, action, applied, exit_code, stdout, stderr, banned, banned_count, verified, note}`。
  `applied` = 命令已执行且退出码 0；`verified` = 回读状态与预期一致；回读不可用或与预期不符时
  `verified=false` + `note` 说明原因，**不假装生效**。
- **不可逆动作一次性令牌**：`ban.add` 缺少 `confirm` 时直接 `E_UNAUTHORIZED` + hint
  （给出 `GET /api/v1/plugins/ssh-guard/root-action/fail2ban-banip/confirm-token` 的取用路径），
  且**不发起任何命令**；令牌由管理员会话签发（插件 bearer 无权自签），插件只原样转发给内核核销。
  `ban.remove`（unbanip）仍是恢复性动作、无需令牌（0.2.1 语义保持不变）。
- **IP 注入双防线**：插件侧 `net.ParseIP` 收窄为纯 IP 字面量并归一化（拒绝 CIDR、通配 `*`、`all`、
  分号、空格、换行、`$()`、反引号），通过后作为唯一追加参数下发；内核侧再按 `shapeIPOrCIDR` 复核。
  两层各有表驱动测试（11 类注入串 / SDK `ValidateRootAppendedArgv`）。
- **降权可用性显式化**：`ssh.status` 新增 `config_source`（`request` / `host` / `none`）与降级 `note`。
  插件以非 root 运行、读不了真实 `/etc/ssh/sshd_config`（通常 0600 root:root），提权通道的命令白名单里
  也没有 `cat` / `sshd` 形状；因此"没拿到文本"必须显式暴露成 `none`，不能让调用方把 5 条
  `(未设置)` 误读成"宿主配置不合规"。
- 通道客户端支持 `confirm` 透传：`rootActionFunc` 增加第三个参数，`rootActionRequest` 增加
  `confirm,omitempty`（只读与可逆动作传空串）。

### 变更（方法级 capability，§3.5 #12）

- `info.json` 新增 `method_capabilities` **8 条**：只读 5 条（`status` / `attempts` / `bans` /
  `ban.list` / `config.get`）→ `system:read`；写 3 条（`ban.add` / `ban.remove` / `config.set`）→ `system:admin`。
  只读调用（含配置读取）不再按插件级 `system:admin` 写 `invoke.*` 审计；写方法仍按 admin 审计。
- 三条 root action 的 `description` 补真实执行 / 回读语义；`id`、`argv`、`irreversible` 集合
  （status=false / banip=true / unbanip=false）与路径口径 `/usr/bin/fail2ban-client` 均未变。
- 版本号 0.2.1 → 0.2.2（patch：补方法级能力声明 + 落地已声明的写动作 + 新增只读字段），
  `manifest.json`（内嵌 manifest）同步 bump。

### 测试

- 新增 `banwrite_test.go`（11 个测试函数 / 19 个子用例）：方法级 capability 表驱动（8 条、键域、
  只读/写分类、与 `businessVerb` 双向对齐）、封禁执行链路（调用顺序 `banip` → `status`、
  追加参数恰为单个 IP、confirm 原样转发、`verified=true`）、`ban.add` 缺令牌零命令、
  `ban.remove` 无令牌可执行且回读确认已移除、11 类 IP 注入全部 `E_INVALID` 且不触发通道、
  SDK 形状复核（合法 IPv4/IPv6 通过、注入串被拒）、内核错误码保留、退出码非 0 显式失败、
  回读不可用 / 回读不符两条降级路径、`config_source` 三态与降级 note。
- `rootaction_client_test.go` 新增 confirm 透传契约测试（真实 UDS+HTTP 请求体断言）。
- `protection_test.go` 的 fake 通道扩展为记录追加参数与 confirm，并支持按调用顺序返回
  （执行 → 回读两步）。

## [0.2.1] - 2026-11-23

### 修复（0.2.0 只读复核发现的三项技术债）

- **`fail2ban-status` 声明未使用（P1）**：`ssh.status` / `ssh.bans` 的 fail2ban 探测改为经内核
  root-action 通道执行声明的 `fail2ban-status`（固定 argv `/usr/bin/fail2ban-client status sshd`），
  进程内不再直呼 `fail2ban-client`。代码常量 `rootActionFail2banStatus` 被真实引用，声明与行为一致；
  通道未注入 / 报 `E_NEED_ROOT` / 非零退出码时如实降级为 sshd 日志统计，并在 hint 里指明缺失通道与动作 id。
  `version` 字段因 `status sshd` 输出不含版本而留空（schema 兼容，不编造、不为展示字段新增提权动作）。
- **路径口径分裂（P1）**：`info.json` 与代码统一为唯一绝对路径常量 `/usr/bin/fail2ban-client`
  （`fail2ban-client` 不在协议 `RootCommandAllowlist` 内，声明侧无法用裸命令名）；进程内只用
  `exec.LookPath(该绝对路径)` 判断可执行性，不向 PATH 回退、不执行；执行只经内核 `systemd-run -- <声明 argv>`。
  声明路径不存在时明确报"未安装"并给符号链接提示，消除「进程内探测成功、提权动作却失败」的语义分裂。
- **`fail2ban-unbanip` 的 `irreversible` 语义（P2）**：解封是恢复性动作（可再次封禁回滚），
  去掉 `irreversible: true`，不再强制一次性 confirm 令牌；`fail2ban-banip` 保留不可逆（可能影响合法访问者）。
  内核语义已核实：`irreversible` 只决定 confirm 令牌核销/签发（`privilege/service.go`、
  `httpapi/handlers_rootaction.go`），不是身份边界——解封仍走 `system:admin` + 审计 + systemd 提权；
  对 unbanip 调 confirm-token 端点会返回 `E_INVALID`（UI 不得再申请令牌）。

### 新增

- root-action 通道客户端（`rootaction_client.go`）：`KORE_KERNEL_SOCK` + `KORE_PLUGIN_TOKEN` +
  `KORE_PLUGIN_ID` 三要素齐备时经内核 UDS/HTTP 调用自身声明的 root 动作；缺一降级。
- 声明↔代码一致性测试：`info.json` 每条 root action 的 id 与 `argv[0]` 必须与代码常量逐字一致；
  `irreversible` 集合（status=false / banip=true / unbanip=false）、manifest 与 info.json 握手字段防漂移。
- 通道客户端真实 UDS+HTTP 契约测试（bearer、action_id、退出码透传、`E_NEED_ROOT` 错误体与 hint）。

### 变更

- `README` 同步：状态读取走 root 通道、路径口径与跨发行版代价、`irreversible` 语义与影响面、
  `KORE_KERNEL_SOCK` 环境变量。

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
