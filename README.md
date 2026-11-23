# kore-plugin-ssh-guard

kore 的 **SSH 加固插件**（配置审计 + 攻击统计 + 封禁视图）。`info.json.depth_level = "basic"`、
`lifecycle = "lazy"`。0.2.0 完成 L1 → L1.5：从"注入文本审计骨架"升级为"真实日志统计 + 防护源检测 + root 动作声明"；
0.2.1 修三项技术债：fail2ban 状态读取统一走 root 通道（声明不再空置）、路径口径统一为唯一绝对路径、
`fail2ban-unbanip` 由不可逆改为可逆（恢复性动作不再强制一次性 confirm 令牌）。

## 定位与边界（先说清楚不做什么）

- **配置审计只读**：`ssh-guard.status` 的审计部分从请求内联参数或宿主预注入的 `KORE_SSHD_CONFIG` 文本读取配置给建议；
  **绝不打开、绝不改写**真实 `/etc/ssh/sshd_config`。
- **日志只读 + 尾部限读**：攻击统计只解析 `/var/log/auth.log`（或 `journalctl -u ssh`）的尾部 **1 MiB**，
  不写任何日志文件、不改系统状态。
- **用户名不外泄**：聚合视图与 `raw_tail` 都经过脱敏，用户名一律替换为 `***`；
  **IP 是唯一允许展示的敏感值**（只计数不取名）。
- **不内置二进制**：不捆绑 fail2ban / iptables / nftables / sshd 等任何执行器。
  fail2ban 状态（只读）与封禁/解封（写）**都经内核 root-action 通道**执行 `info.json` 里声明的固定 argv；
  插件进程**不再直呼** `fail2ban-client`，自身永不提权（ADR-0018）。
- 唯一依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `ssh-guard.status` / `status` | 只读配置审计（5 条规则，`checks`/`total`/`issues`/`applied:false`）**+ 防护源检测** `protection`（fail2ban 状态经 `fail2ban-status` root 动作读取） |
| `ssh-guard.attempts {since?, source?, raw_limit?}` / `attempts` | SSH 攻击尝试统计：`{total, failed, invalid_users, successful_logins, unique_ips, top_ips, timeline_hourly, raw_tail, truncated}` |
| `ssh-guard.bans {source?}` / `bans` | 当前封禁/可疑 IP 清单：fail2ban 经 root 通道可读时取 sshd jail；否则按可疑阈值从日志推断 |
| `ssh-guard.config.get` / `config.get` | 读运行配置（日志路径 / 日志源 / 可疑阈值 / 原始行上限） |
| `ssh-guard.config.set {...}` / `config.set` | 进程内改写运行配置（校验后生效；lazy 生命周期**不落盘**，进程退出回到环境变量/缺省值） |
| `ssh-guard.ban.add {ip}` / `ban.add` | 写操作：返回 `E_NEED_ROOT` + hint + root_action 指向（不执行） |
| `ssh-guard.ban.remove {ip}` / `ban.remove` | 写操作：同上 |
| `ssh-guard.ban.list` / `ban.list` | 0.1.0 兼容保留：参数校验 + 空清单回显 |
| `kore.ping` / `kore.reload` / `kore.shutdown` | 协议必选方法；`kore.reload` 无外部配置，`config_digest` 为空 |

### 防护源检测（status.protection）

```json
{"available": true, "engine": "sshd", "fail2ban_installed": false,
 "fail2ban_active": false, "banned_count": 0, "failed_24h": 0, "log_source": "journal", "hint": "..."}
```

- `engine = "fail2ban"`：经内核 root-action 通道执行声明的 `fail2ban-status`
  （固定 argv `/usr/bin/fail2ban-client status sshd`）成功；`banned_count` 取自 sshd jail 的 Currently banned。
- `engine = "sshd"`：fail2ban 未安装、提权通道不可用或通道执行失败，**以 sshd 日志统计为降级源，不报错**；
  `failed_24h` 来自日志解析（最近 24h 的失败尝试 + 用户名探测），hint 说明降级原因与下一步。
- `engine = "none"`：日志源与 fail2ban 都不可用，`available=false` + hint 给可操作路径（安装 fail2ban / 修提权通道 / 加入 adm 组）。
- **状态读取不再进程内直呼客户端**：读 fail2ban socket 需要 root，插件进程按设计永不为 root，
  进程内直呼在非 root 下本就不该成功；统一走声明动作后，探测结果与提权语义一致。
- `version` 字段：经 root 通道的 `status sshd` 输出不含版本号，0.2.1 起该字段留空（schema 兼容，不编造）；
  需要版本请在宿主执行 `fail2ban-client --version`。
- 通道三要素（`KORE_KERNEL_SOCK` / `KORE_PLUGIN_TOKEN` / `KORE_PLUGIN_ID`）缺一时无法读取状态，
  hint 会指明缺失的通道与动作 id（不会静默显示成"没有封禁"）。

### 攻击统计（attempts）

- 日志源：`source ∈ {auto, auth, journal}`（缺省 `auto`：auth.log 可读则用，否则降级 journalctl）。
  auth.log 不可读**不报错**，返回空统计 + 说明。
- 解析行型（两种格式都支持）：
  - `Failed password for [invalid user] USER from IP port P ssh2` → 失败尝试
  - `Invalid user USER from IP` → 用户名探测（计入 failed）
  - `Accepted password|publickey for USER from IP ...` → 成功登录
  - rsyslog ISO 时间戳（`2026-11-17T11:39:29.279845+08:00`）、journalctl short-iso、经典 syslog（`Nov 17 10:00:02`，无年份按当前年补齐）。
- 窗口：`since` RFC3339，缺省最近 24h，最早 7 天前；`raw_limit` 0..500（缺省 200，0 = 不回原始行）。
- `raw_tail` 每行已脱敏（用户名 → `***`）；日志超过 1 MiB 时 `truncated=true` 并只统计尾部。
- 已知限制：rsyslog 的 "message repeated N times" 合并行按 1 行计数（不展开）；
  本地化输出（非英文标签）的 fail2ban 状态解析失败时如实返回 0，不编造数据。

### 封禁/可疑 IP（bans）

- fail2ban 活跃：解析 `fail2ban-client status sshd` 的 `Banned IP list`（`reason` 注明来源）。
- 否则降级推断：单 IP **单自然小时**失败次数 ≥ `suspicious_threshold`（缺省 10）→ 可疑候选，
  `reason` 写明命中依据，`last_seen` 为该 IP 最后一次失败时间。
- `applied` 恒为 `false`：本插件只读，不执行封禁。

## root 动作声明（ADR-0018）

`info.json` 声明 `requires_root: true` 与 3 个 `root_actions`（固定 argv、不经 shell），
**三条都在代码里有真实调用点**（`fail2ban-status` 用于 status/bans 的状态读取，
`fail2ban-banip`/`fail2ban-unbanip` 用于 ban.add/ban.remove 的动作指向；由
`TestFail2banPathsMatchInfoJSON` 双向锁定）：

| action id | argv | irreversible | 代码调用点 |
| --- | --- | --- | --- |
| `fail2ban-status` | `/usr/bin/fail2ban-client status sshd` | 否 | `protection.go:probeFail2ban` 经内核通道读取 |
| `fail2ban-banip` | `/usr/bin/fail2ban-client set sshd banip`（追加 IP） | 是 | `methods.go:handleBanWrite`（ban.add） |
| `fail2ban-unbanip` | `/usr/bin/fail2ban-client set sshd unbanip`（追加 IP） | **否** | `methods.go:handleBanWrite`（ban.remove） |

### irreversible 语义（内核核实，0.2.1 调整）

内核 `pluginapi.RootAction.Irreversible=true` 时，执行前必须携带一次性 `confirm` 令牌
（5 分钟、绑定 `plugin_id+action_id`、单次有效）；缺失/过期/绑定不符/已用 → `E_UNAUTHORIZED` +
`root.action` deny 审计（`internal/core/privilege/service.go` 核销、`internal/core/httpapi/handlers_rootaction.go`
签发）。它**不是**身份边界：调用方仍需 `system:admin` 或目标插件 bearer，root/systemd 检查与审计不变。

- `fail2ban-banip` 保留 `irreversible: true`：封禁可能立刻影响合法访问者，值得二次确认。
- `fail2ban-unbanip` 改为可逆：解封是恢复性动作，可再次封禁回滚，不满足 ADR「不可回滚」定义；
  强制一次性令牌只给正常运维（误封恢复）增加阻力。
- 影响面：对 `fail2ban-unbanip` 调 confirm-token 端点会返回 `E_INVALID`（内核既有行为），UI 不得再为它申请令牌；
  解封仍走 `system:admin` + 审计 + systemd 提权，建议 UI 自己保留一次「确认解封」弹窗。

### 路径口径（唯一绝对路径）

`info.json` 与代码**共用同一个常量** `/usr/bin/fail2ban-client`（`protection.go:fail2banClientPath`）：

- `argv[0]` 必须是绝对路径或协议命令白名单名；`fail2ban-client` **不在** `RootCommandAllowlist` 内
  （`nginx/ufw/iptables/systemctl/crontab/chmod/chown/docker`），所以声明侧只能用绝对路径。
- 进程内只用 `exec.LookPath(该绝对路径)` 判断「声明路径是否存在且可执行」（**不执行命令、不向 PATH 回退**）；
  真正的执行只发生在内核侧 `systemd-run -- <声明 argv>`，两处逐字相同。
- 声明路径不存在 → `fail2ban_installed=false` + hint（含 `ln -s <实际路径> /usr/bin/fail2ban-client`），
  不再出现「进程内探测成功、提权动作却因路径不同失败」的语义分裂。
- 代价：装在 `/usr/local/bin` 等路径的发行版默认报"未安装（声明路径不存在）"，需要一次符号链接或改用发行版包；
  换来的是两条通道口径一致、失败可预期。

**诚实声明**：本机 kored 以非 root 运行且 fail2ban 未安装，`ban.add`/`ban.remove` 恒返回 `E_NEED_ROOT` +
可操作 hint；真实执行依赖内核提权通道（systemd transient unit，见
[kore ADR-0018](../kore/docs/DECISIONS/0018-privilege-model.md)），本仓只验证拒绝路径与通道客户端契约。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `info.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌：随 `kore.hello` 上报，并作为 root-action 通道的 bearer |
| `KORE_KERNEL_SOCK` | 否 | 内核 UDS 路径（root-action 通道）；缺省表示内核未启用通道，fail2ban 状态读取按降级处理 |
| `KORE_SSHD_CONFIG` | 否 | 宿主预注入的 sshd 配置文本；请求内联 `sshd_config` 优先 |
| `KORE_SSHGUARD_LOG_PATH` | 否 | sshd 日志文件路径，缺省 `/var/log/auth.log` |
| `KORE_SSHGUARD_LOG_SOURCE` | 否 | `auto`（缺省）/ `auth` / `journal` |
| `KORE_SSHGUARD_THRESHOLD` | 否 | 可疑 IP 阈值（单小时失败次数），缺省 10，1..10000 |
| `KORE_SSHGUARD_RAW_TAIL` | 否 | attempts 原始行回传上限，缺省 200，0..500 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/ssh-guard .
make dist    # 产出 dist/ssh-guard-0.2.1.tar.gz（info.json + bin/ssh-guard + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
```

`dist` 确定性打包：显式列条目、`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner`、`gzip -9n`，
首条目固定为 `info.json`。`size_bytes` 回填最终 tar.gz 的实际字节数并迭代到不动点（偏差 ≤2 字节）。
两次 `make dist` 的 tarball sha256 完全一致。

## 测试

- 根目录单测：`net.Pipe` 模拟主壳侧，覆盖握手、全部业务方法、日志解析（真实格式的
  `Failed password` / `Invalid user` / `Accepted` 行）、IP 聚合与 top 排序、小时时间线、
  无日志降级、可疑 IP 阈值（集中爆破命中 / 分散不命中）、用户名脱敏、配置契约。
- 0.2.1 新增：root-action 通道四态（成功 / 通道未注入 / 通道报 E_NEED_ROOT / 非零退出码）、
  通道客户端真实 UDS+HTTP 契约（bearer、action_id、退出码、错误体）、声明↔代码一致性
  （`info.json` 每条 root action 的 id 与 argv[0] 必须与代码常量逐字一致）、`irreversible`
  confirm 需求集合（status=false / banip=true / unbanip=false）与 manifest 版本防漂移。
- `tests/fault/`：真实二进制 + UDS 的黑盒故障注入四类——`kill -9`、hello 超时、
  垃圾帧（解码失败即断开）、超帧前缀（> 8 MiB 立即拒绝）。
  磁盘满 / cgroup 超限等故障延 v1.1（基础级边界用例延后，核心路径可用）。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 未完成项（v1.1+）

- 提权成功路径：root_actions 真实执行依赖内核提权通道 v1.0（systemd-run transient unit），本轮仅声明与拒绝路径验证。
- `sshd_config` 读取与原子写入、`sshd -t` 校验、变更回滚。
- 封禁持久化视图与 fail2ban 联动策略配置（当前 config.set 不落盘）。
- 生产级四类故障注入（磁盘满、cgroup 超限）与预设"开箱可用"标记。
