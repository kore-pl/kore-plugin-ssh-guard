# SSH 加固插件（ssh-guard）

## 它做什么

kore 的 SSH 加固插件：配置审计 + 攻击统计 + 封禁视图。0.2.0 从文本审计骨架升级为真实日志统计 + 防护源检测 + root 动作声明；0.2.2 封禁 / 解封真正经内核提权通道执行并回读校验；0.4.0 封禁清单为真实实现（分页、来源、剩余时间与白名单标记）。

## 协议与兼容性

协议 `kore.plugin.v1`，`lifecycle=lazy`，`depth_level=basic`，`requires_kore >=0.1.0 <0.2.0`；唯一第三方依赖 `github.com/pengtang1024/kore/pkg/pluginapi v0.1.3`。

## 主要能力

- `status`：只读配置审计（5 条规则）与防护源检测（fail2ban 状态经 root 通道读取）；绝不打开或改写真实 `/etc/ssh/sshd_config`。
- `attempts`：解析 `/var/log/auth.log`（或 journalctl）尾部 1 MiB 做攻击统计，用户名脱敏为 `***`，IP 是唯一允许展示的敏感值。
- `bans` / `ban.list`：当前封禁 / 可疑 IP，含来源、规则、观察时间与白名单冲突告警；`whitelist` 系列管理白名单（0600 落盘）。
- `suggest`：只读建议态（dry_run=true，不写宿主），给出 sshd_config.d 建议文本、风险说明、应用与验证命令。
- `ban.add` / `ban.remove`：经 `fail2ban-banip` / `fail2ban-unbanip` root 动作真实执行；封禁是不可逆动作，必须带一次性 confirm 令牌，白名单 IP 直接拒绝。插件自身永不提权，不捆绑 fail2ban / iptables / nftables / sshd。

## 安装与验证

`make check` 为本地门禁，`make dist` 产出位级可复现的 `dist/ssh-guard-0.4.0.tar.gz`。真机提权 e2e 仍依赖 root + systemd 环境，单测用替身通道覆盖 argv 与回读。
漏洞按 [SECURITY.md](SECURITY.md) 私下披露；MIT 许可；贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)。