# kore-plugin-ssh-guard

kore 的 **M5 批1 SSH 加固插件**（失败封禁 + 配置审计）骨架。`info.json.depth_level = "basic"`、
`lifecycle = "lazy"`。按提案 `0005-m5-ecosystem.md §2.1` 批1：`ssh-guard | 基础级 | firewall（可选） | SSH 失败封禁 / 配置审计`。

## 定位与边界（先说清楚不做什么）

- **只读审计**：`ssh.status` 从请求内联参数或宿主预注入的 `KORE_SSHD_CONFIG` 文本读取配置给建议；
  **绝不打开、绝不改写**真实 `/etc/ssh/sshd_config`。
- **不内置二进制**：不捆绑 fail2ban / iptables / nftables / sshd 等任何执行器；`ssh.ban.list` 在基础级
  恒返回空清单且 `applied:false`，真实封禁执行器延 v1.1。
- 唯一依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.1`（其余为标准库）。
- `capabilities = ["system:admin"]` 是声明口径；本骨架不会调用任何特权操作。

## 方法表

| 方法（裸名 / 全名） | 行为 |
| --- | --- |
| `ssh-guard.status` / `status` | 只读审计：逐条检查 `PermitRootLogin`、`PasswordAuthentication`、`PermitEmptyPasswords`、`MaxAuthTries`、`ChallengeResponseAuthentication`，返回 `checks` / `total` / `issues` / `applied:false` |
| `ssh-guard.ban.list` / `ban.list` | 参数校验（`limit` 1..100、`offset` ≥0、可选 `address` 为合法 IP），返回空封禁清单与分页回显 |
| `kore.ping` / `kore.reload` / `kore.shutdown` | 协议必选方法；`kore.reload` 无外部配置，`config_digest` 为空 |

审计建议示例：`PermitRootLogin` 推荐 `prohibit-password`（禁止 root 直接密码登录，保留密钥登录应急）；
`PasswordAuthentication` 推荐 `no`（改用密钥认证抵御爆破）。配置文本支持 `#` 注释与 `Key=Value` 写法，
同一指令取首次有效值，`Include` 行忽略。

响应帧一律回显请求的 `id` 与 `req_id`；未知方法回 `E_NOTFOUND`；参数非法回 `E_INVALID`。

## 环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `KORE_PLUGIN_SOCK` | 是 | 主壳创建的 UDS 路径 |
| `KORE_PLUGIN_ID` | 否 | 内核登记 id，缺省取内嵌 `info.json.id` |
| `KORE_PLUGIN_TOKEN` | 否 | 内核注入令牌；当前只随 `kore.hello` 上报 |
| `KORE_SSHD_CONFIG` | 否 | 宿主预注入的 sshd 配置文本；请求内联 `sshd_config` 优先 |
| `KORE_LOG_LEVEL` | 否 | `debug`/`info`/`warn`/`error`，缺省 `warn`；日志只写 stderr |

`stdout` 只留给协议帧，任何日志都不得写 stdout。

## 构建与打包

```bash
make build   # CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o bin/ssh-guard .
make dist    # 产出 dist/ssh-guard-0.1.0.tar.gz（info.json + bin/ssh-guard + SHA256SUMS）与同名 .sha256
make check   # gofmt → go vet → go test -timeout 200s
```

`dist` 确定性打包：显式列条目、`--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner`、`gzip -9n`，
首条目固定为 `info.json`。`size_bytes` 回填最终 tar.gz 的实际字节数并迭代到不动点（偏差 0%）。
两次 `make dist` 的 tarball sha256 完全一致。

## 测试

- 根目录单测：`net.Pipe` 模拟主壳侧，覆盖握手、两个业务方法、审计判定、非法参数与 `req_id` 回显。
- `tests/fault/`：真实二进制 + UDS 的黑盒故障注入——`kill -9` 后立即退出、`hello` 超时后 2s 内自行退出。
  磁盘满 / cgroup 超限等故障延 v1.1（基础级边界用例延后，核心路径可用）。

本地联调依赖**不提交**的 `go.work`（`use .` + `use ../kore/pkg/pluginapi`）；跨仓 `replace` 禁止写入 `go.mod`（G-17）。

## 未完成项（v1.1）

- `ssh.ban.list` 的真实封禁数据源、封禁/解封执行器（建议与 `firewall` 插件联动，可选依赖）。
- 配置落盘、备份与回滚（当前审计只读，不触碰真实 sshd_config）。
- 生产级四类故障注入（磁盘满、cgroup 超限）与预设“开箱可用”标记。
