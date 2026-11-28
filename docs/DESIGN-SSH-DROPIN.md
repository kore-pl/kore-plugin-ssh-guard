> 状态: proposal（doc-first，待 lead / architect 审阅） · 归属: c12-design · 更新: 2026-11-28 · 里程碑: R51
> 关联: task-338（本方案）/ task-334（C12 隔离验证 `b16a575`）/ task-337（回滚 mode 修复，前置依赖）
> 写域: 本仓 `docs/DESIGN-SSH-DROPIN.md`（新）；不碰代码、不落实现、不联网业务、不碰宿主 `/etc/ssh` / 8787 / `.kore-local-*`
> 性质: 新增能力（新 file_write 类目 + 指令 allowlist + 插件声明 + 前端入口）的**纯方案**。审阅通过后才另开实施卡；本文不构成任何已实现承诺。

# DESIGN：ssh-guard 一键写 sshd drop-in（doc-first 方案）

## 0. 结论先行

ADR-0028 的受控写**机制本体**（`WriteDeclared` + 备份 / 审计 fail-closed / 原子替换 / `changes.jsonl` 结构化回滚）在 C12 隔离验证（`.agents/verify/c12-sshdropin-vm.md`，五项全 PASS）中已证明可直接复用于 sshd drop-in。**缺口不在机制，在协议/插件接线**：`pkg/pluginapi/filewrite.go:85-96` 只有 `nginx.conf.d` 一类、`:220-258` 只实现 `nginx.vhost.v1`（其余 fail-closed），`kore-plugin-ssh-guard/info.json:41-75` 无 `file_write` 声明。

本方案把 C12 的**隔离副本内联补丁**（harness-only allowlist）转正为**生产协议声明**：新增 `sshd.config.d` 类目 + `sshd.dropin.v1` 内容策略（纯文本 allowlist 校验器，放 `pkg/pluginapi`，与 `nginxconf.go` 同构），插件加 `file_write` root_action + 一键应用/回滚前端入口。**不新开提权通道、不给目录授权、不把 `sshd -t` 当安全校验**。基础机制已在隔离环境验过；真正对宿主生效前必须在隔离 VM 再做一次**生产代码**闭环复验（P3）。

---

## 1. 现状与增量（①）

### 1.1 协议层现状（读码事实）

| 事实 | 证据 |
| --- | --- |
| `file_write` 类别唯一真源只有 `nginx.conf.d`：`Dir=/etc/nginx/conf.d/`、`Suffix=.conf`、`Mode=0644`、`Owner=root:root`、`PluginNamePrefix=true` | `kore/pkg/pluginapi/filewrite.go:85-96` |
| 内容策略只实现 `nginx.vhost.v1`，其它值走 fail-closed | `filewrite.go:252-257` |
| 通用校验链已具备：大小/UTF-8/NUL/控制字 → 类别策略分派 | `filewrite.go:220-258`；`ValidateFileWriteRequest` 单一入口 `:263-272` |
| 名字校验已挡 `/`、`\`、NUL、控制字、`..`、超长、后缀、插件前缀（横向覆盖） | `filewrite.go:167-203`；`FileWritePath` 再 `path.Clean` 复核 `:295-305` |
| ADR-0028 §3 白名单**本来就含** `/etc/ssh/sshd_config.d/`（4 个 drop-in 目录之一），一期也实现了通用前缀表 | `docs/DECISIONS/0028-controlled-file-write.md:69-80`；`internal/core/filewrite/filewrite.go:37-42` |
| 四类缺口（属主校验 / 文件名前缀 / 路径锁 / root-action 接线）二期已补齐，C12 harness 走的就是这条已接通链路 | ADR-0028「实施记录」§4；C12 报告 §0 `:31-41` |
| `file_write` 声明与 exec 互斥、必须 `writes_host=true`、`target` 必须逐字等于类别目录，回滚信息由内核运行时生成（不写静态 `purge_op`） | `pkg/pluginapi/rootaction.go:160-170`；`filewrite.go:274-290` |
| 协议版本：pluginapi 最新 tag `pkg/pluginapi/v0.3.0`；kore VERSION `0.1.5`；G-14 要求声明 `file_write` 的插件 `requires_kore` 下界 ≥ `0.1.1` | `git tag --list 'pkg/pluginapi/*'`；`kore/Makefile:29`、`:436-490` |

### 1.2 ssh-guard 现状

- 能力 = SSH 登录审计 + fail2ban 封禁/解封 + 白名单自保 + 加固**建议态**（`suggest.go:12-20`：`dry_run` 恒 true，`config_text`/`apply_commands` 只生成文本、绝不写宿主）。
- `info.json` 只有 3 条 fail2ban 命令型 `root_actions`，**无 `file_write` 声明**（`info.json:41-75`）；`method_capabilities` 12 条均为读/admin 方法，无加固写方法（`:13-26`）。
- 前端 `kore/web/sshguard.js:40` 明写「加固建议：只生成建议，前端没有任何『应用』写操作」；suggest 面板 `:852-945`、`:1250` 纯只读展示。
- `depth_level=basic`、`requires_kore=">=0.1.0 <0.2.0"`、`version=0.4.1`、go.mod 依赖 `pluginapi v0.1.3`（`info.json:5,8,28`；`go.mod`）。

### 1.3 C12 隔离验证证明了什么、没证明什么

C12（`b16a575`）五项全 PASS：①受控写落地 drop-in（0644 root:root、审计 begin+end 只存哈希、`changes.jsonl` + `file.remove`）；②`sshd -t` exit 0、`sshd -T` 确认生效；③按账本逐字节回滚（`file.restore`）；④路径/前缀/后缀/allowlist/参数四类拒绝 + 审计 fail-closed + 只读 FS 拒绝，零半写入；⑤容器内加固后密钥 SSH 仍可连、密码认证被拒。**同时如实暴露**：覆盖写回滚后 mode 0600≠0644（`changes.go:169-180` 裸 `os.Rename` + `filewrite.go:412-418` 备份固定 0600），已由 task-337 修；SIGHUP 失败是 harness 二进制包装问题、非配置/机制问题；容器非真机、无 systemd/PAM 长时验证。

### 1.4 增量边界（本方案要做的 / 不做的）

**增量 = 把 harness-only 补丁转正**：类别定义 + 指令 allowlist + 策略分派 case + 插件声明 + 前端入口 + 涟漪发版。**不做**：新提权端点（ADR-0052 §3.2 A2 已否）、目录授权（同 A、B 已否）、改主配置 `/etc/ssh/sshd_config`（ADR-0028 §7#3：本原语只做 drop-in）、自动 reload sshd（见 §3.3 安全裁决）、把 `sshd -t` 当内容安全校验（ADR-0052 §3.3 硬否证的 sshd 同构版本）。

---

## 2. sshd drop-in 类目与内容策略设计（②）

### 2.1 类目（与 `nginx.conf.d` 同构，复用 `ValidateFileWriteContent` 框架）

在 `pkg/pluginapi/filewrite.go` 的 `FileWritePrefixClasses` 增一条、`FileWriteOptions` 增一个策略字段、`ValidateFileWriteContent` 的 switch 增一个 case：

| 字段 | 取值 | 理由 / 复用点 |
| --- | --- | --- |
| `PrefixClass` | `sshd.config.d` | 与 ADR-0028 §3 前缀名、C12 报告建议一致；命名风格对齐 `nginx.conf.d` |
| `Dir` | `/etc/ssh/sshd_config.d/` | **带尾斜杠**，只在内核类别层定义一次；插件永远不提供目录 |
| `Suffix` | `.conf` | 排除 `.sh` 等可执行脚本；沿用 `ValidateFileWriteName` |
| `Mode` | `FileWriteModeRoot0644`（`"0644"`） | 固定，声明里写别的直接拒（`ValidateFileWrite:111-114`） |
| `Owner` | `root:root` | 属主校验已在 K3 补齐；fixed |
| `PluginNamePrefix` | `true` | 文件名必须 `kore-ssh-guard-*.conf`，防横向覆盖其它 drop-in |
| `ContentPolicy` | `sshd.dropin.v1` | 新策略名；声明与类别不一致即拒，不静默取类别值 |
| `MaxBytes` | 类别默认 `MaxFileWriteContentBytes`（256 KiB）；**插件声明自收紧到 64 KiB** | sshd 片段极小；`decl.MaxBytes` 只能收紧不能放大（`filewrite.go:122-125`） |

`target` 必须逐字等于 `/etc/ssh/sshd_config.d/`（`ValidateFileWriteTarget:149-161`）——保证 `changes.jsonl` 的人话影响对象与真实写盘对象一致，用户按账本回滚不会滚错。

**路径逃逸防护（逐层复用，不新写）**：`ValidateFileWriteName` 已挡 `..` / 路径分隔符 / 反斜杠 / NUL / 控制字 / 超 128 字符 / 后缀 / 插件前缀；`FileWritePath` 拼完后 `path.Clean(full) != full` 再拒一次；内核 `internal/core/filewrite` 另有逐级 `Lstat` 禁软链 + `O_NOFOLLOW` + 属主复核（ADR-0028 实施记录 §2）。**结论：不需要为新类目新增任何路径校验代码**，类别数据驱动即可。

### 2.2 内容策略 `sshd.dropin.v1`（新增 `pkg/pluginapi/sshdconf.go`，手写 allowlist、零新依赖）

**为什么必须做纯文本 allowlist**：被写进 `sshd_config.d` 的片段由 **root sshd** 解析；`Include` 可把任意 root 可读文件拉进配置并借解析错误回显首 token，`AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` 让 root sshd 执行任意命令，`AuthorizedKeysFile` 可把认证锚点重定向到攻击者可写文件，`HostKey` 可加载任意密钥文件——这些与 ADR-0052 §2 的 nginx `access_log` 同类。**`sshd -t` 只校验语法、不校验安全性**（且 root 身份下 `-t` 会真实打开 HostKey 等文件），不能充当安全门。策略必须是在**写盘前**对文本的纯解析（G-01：放 `pkg/pluginapi`，与 `RootCommandPolicies` / `nginxconf.go` 同层；`cmd/` 与 `internal/core` 不出现 sshd 业务词）。

**解析器形状（逐条可测）**：

1. **结构**：sshd 配置为逐行 `Directive value...`，无块、无分号。只接受「行首指令 + 空白分隔参数 + 可选整行 `#` 注释」；行内 `#`、行尾 `\` 续行、`%` 变量展开、`${}`、`"`/`'` 引号、`;`、`{`/`}` 一律拒（防「校验器看到的」与「sshd 解析的」不一致，对齐 `nginxconf.go:187-282` 的词法纪律）。
2. **指令 allowlist（默认全拒，白名单才放行）**——首版建议仅这些、每条带严格参数形状：
   | 指令 | 允许参数 | 形状判据 |
   | --- | --- | --- |
   | `PasswordAuthentication` | `yes` / `no` | 精确枚举 |
   | `PermitRootLogin` | `yes` / `prohibit-password` / `forced-commands-only` / `no` | 精确枚举 |
   | `PubkeyAuthentication` | `yes` / `no` | 精确枚举 |
   | `KbdInteractiveAuthentication` | `yes` / `no` | 精确枚举 |
   | `PermitEmptyPasswords` | `no` | **只允许 `no`**（openssh 默认已是 no，显式禁止被改成 yes） |
   | `MaxAuthTries` | 整数 `1..100` | `strconv.Atoi` + 范围（`C12` harness 已验证该判据） |
   | `ClientAliveInterval` / `ClientAliveCountMax` | 整数 `0..3600` / `0..10` | 范围 |
   | `LoginGraceTime` | 整数 `1..600` | 范围 |
   | `MaxStartups` | `start:rate:full`，各段 `1..1000` | 结构化三段 |
   参数个数、单个 token 长度、总指令数设上限（对齐 `nginxconf.go:47-57` 的 `maxNginx*` 常量族，防解析放大）。
3. **显式 deny 清单（带理由，供错误文案 / 红队 / 文档同源）**：`Include`（绕过 allowlist 拉外部配置）、`Match`（条件块可覆盖全局、且块延续到 EOF 吞掉后续配置）、`AuthorizedKeysFile` / `AuthorizedPrincipalsFile`（重定向认证锚点）、`AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` / 对应 `*User`（root 身份命令执行）、`HostKey`（指向任意密钥文件）、`Port` / `ListenAddress`（改变监听面、可致锁死）、`Subsystem` / `ForceCommand`（改变会话语义）、`AllowTcpForwarding` / `PermitTunnel` / `PermitListen` / `PermitOpen`（打开转发面）。**任何不在 allowlist 的指令一律拒**，deny 清单只为「错误信息可解释 + 用例可逐条断言」。
4. **残余风险必须披露**：allowlist 内 `PasswordAuthentication no` + `PermitRootLogin no` 的业务后果（锁死自己）由「保留密钥登录 + 一键回滚 + VM 先验」承担，不由 allowlist 消除；多发行版 include 位置差异见 §6。

**复用 + 新增边界**：`ValidateFileWriteContent:220-251` 的公共前置（大小/空/UTF-8/NUL/控制字）**一行不改**；新增只在 switch 里 `case ContentPolicySSHDropin: return ValidateSSHDropinFragment(content, opts.SSHD)`。`FileWriteOptions` 增 `SSHD SSHDPolicy`（首版无运行时注入需求，零值即默认，保持 fail-closed 语义）。

### 2.3 关于 `sshd -t` 的定位（关键区分）

- **内容安全门 = allowlist（纯文本，写盘前）**；
- **`sshd -t` = 语法/锁死门（写前 staging 一次 + 写后对真实配置复核一次）**，只证明「配置可解析、不会因语法错让 sshd 起不来」，**不证明安全**；
- **写后 `sshd -T` 复核生效值**（对齐 C12 §2②：`passwordauthentication no` / `maxauthtries 3` 实际生效）——挡「主配置 Include 位置靠后导致 drop-in 被覆盖、加固静默失效」。

---

## 3. 安全门清单（③）

> 逐条给「判据 + 落点 + 验收命令」，实施卡按此逐项交证据；任一不满足不得声明完成。

| 门 | 判据 | 落点 / 验收 |
| --- | --- | --- |
| **G-02 零新依赖** | 校验器只用标准库（`strconv`/`regexp`/`unicode/utf8`），无第三方；不引入任何常驻组件 | `go list -m all` 与白名单逐项比对；root/pluginapi `go.mod` 无新增 require |
| **G-10 用户显式** | 不自动应用：面板「一键应用」必须用户点 + 明确确认框（列将写入的文件名、指令 diff、风险与回滚方式）；无定时/触发式自动下发 | `web/sshguard.js` 入口 + `ssh-guard suggestion 面板`；`triggers: []` 保持不变 |
| **G-31 高权限受控** | 只经 `POST /plugins/ssh-guard/root-action` 走 ADR-0018 提权代理 + confirm 语义；**不新开端点**；宿主机写必须登记 `<install>/data/changes.jsonl`（ADR-0023 §3.5 #3），`writes_host=true`、运行时生成 `purge_op`（新文件 `file.remove` / 覆盖 `file.restore`） | `rootaction.go:29-38,195-211`；`handlers_rootaction.go:35-127`；C12 §2① 已验证账本+审计 begin/end |
| **fail-closed** | 非法类目 / 路径 / 文件名 / 指令 / 参数 / 审计写失败 → 拒绝且目标零落盘、零半写入；审计只存哈希不存正文（G-30） | `filewrite.go:102-127,220-258` + 新策略用例；C12 §2④ 四类拒绝已验 |
| **`sshd -t` 写前必做** | 写盘前把片段 staging 到隔离配置树，跑 `sshd -t -f <temp sshd_config>` 必须 exit 0；非 0 → 不写、报错给「怎么办」；新增 root 命令形状 `sshd -t -f <受控临时路径>` 放 `RootCommandPolicies`（与 site 的 `nginx -t/-T` 同构） | 实施卡新增 staging 用例；**不把 `-t` 当安全校验**（§2.3） |
| **保留 SSH 会话 + 自动回滚兜底** | ①本能力**不执行 reload/restart sshd**（见 §3.3）；②写后对真实配置 `sshd -t` + `sshd -T` 复核，非 0 或生效值不符 → 立即用包内 `revertWrite`（`filewrite.go:475-492`，读备份+`atomicWrite` 带 mode）自动回滚，不消费账本为「成功」；③UI 明写「应用前确认已有一条可用密钥会话，别关掉当前终端」；④一键回滚 = 按 `changes.jsonl` 的 `purge_op` 结构化回滚 | C12 §2③ 回滚路径；**依赖 task-337 先修 mode**（`changes.go:169-180` + `filewrite.go:412-418`），否则「逐属性还原」不成立 |
| **写后属性守恒（task-337 前置）** | 回滚后 drop-in 内容逐字节一致 **且 mode 0644 / root:root 不变** | task-337 回归用例（0644→写→回滚→仍 0644；sshd drop-in + nginx vhost 两类）未合入前，P1/P2 不得宣称「可回滚」 |

### 3.3 安全裁决：应用 ≠ reload

`systemctl reload/restart sshd` **不在**当前 `RootCommandPolicies`（ADR-0022 形状表），且 C12 §2⑤ 的 SIGHUP 失败已示警「运行中重读配置」的风险。首版裁决：**一键应用只写 drop-in，不 reload**。drop-in 在 sshd 下次启动/重载时生效，由运维在确认密钥会话可用后自行 reload（或后续单独 ADR 评估「受控 reload」动作）。好处：写操作与进程重启解耦，当前会话零中断，回滚只是删/还原文件、不需要逆转一次进程重启。此裁决需 lead / architect 在审阅时确认；若要求「应用即生效」，须另开 ADR 评估 reload 命令形状 + confirm + 失败回滚（**不在本方案范围**）。

---

## 4. 涟漪清单（④）

| # | 仓库 | 改动 | 门禁 / 证据 |
| --- | --- | --- | --- |
| 1 | `kore` | `pkg/pluginapi`：**feat → minor**，tag `v0.3.0 → v0.4.0`（新类目 + 新策略 = 协议加法）；新增 `sshdconf.go` + `sshdconf_test.go`；`filewrite.go` 增类目/case/options 字段 | `cd pkg/pluginapi && go test -race ./...` 绿；`make pluginapi-race` exit 0 |
| 2 | `kore` | 新 ADR（建议编号 `0059-sshd-dropin-controlled-write.md`，最终由 architect 分配）：威胁建模、`sshd -t` 非安全门论证、allowlist/deny 全表、残余风险、复审条件；**ADR-0028 追加 append-only §9 修订记录**（列入类目 + 内容策略例外 + 拒绝清单追加 + §7#1 标记已使用），不改 §1–§7 原文 | `bash scripts/docs-check.sh` exit 0；diff 只增不改 |
| 3 | `kore` | `docs/PLUGIN-PROTOCOL.md` §3.1.3 增类目/策略行；`docs/CORE.md`（root_action 口径）、`docs/SECURITY.md`（sshd 写面威胁模型与回滚）、`docs/DATA-MODEL.md`（`changes.jsonl` 的 sshd `purge_op` 实例）；`.agents/LOG/DECISIONS.md` 按 G-23 登记 | docs-check exit 0（既有 WARN 如实标注） |
| 4 | `kore-plugin-ssh-guard` | `info.json`：新增 1 条 `file_write` root_action（`sshd-dropin-write`：`prefix_class=sshd.config.d`、`mode=0644`、`content_policy=sshd.dropin.v1`、`max_bytes=65536`、`writes_host=true`、`target=/etc/ssh/sshd_config.d/`、**不写静态 purge_op**）；`method_capabilities` 增 `ssh-guard.apply-hardening` / `ssh-guard.rollback-hardening`（均 `system:admin`）；`requires_kore` 下界收窄到「首个含 sshd 类目 + task-337 回滚修复的内核版本」（P3 由发版 owner 钉死，当前先记约束不写死数字）；`description` 去掉「建议态、不下发」；**feat → minor** `0.4.1 → 0.5.0`；`CHANGELOG.md` 条目 | `make check` exit 0；`TestRootActionsDeclared` 双向一致；`version-check` 覆盖区间 |
| 5 | `kore-plugin-ssh-guard` | 方法实现：apply 渲染（复用 `suggest.go` 的 `config_text` 生成，只换写入通道）+ 回滚（经 `changes.jsonl` 的结构化 `purge_op`）；旧 `suggest` 保留为预览/dry-run；`make dist` 重打 | `go test ./...` 绿；dist sha 与索引一致 |
| 6 | `kore`（主壳前端） | `web/sshguard.js`：加固建议面板增「一键应用 / 回滚」入口（确认框 + diff + 风险 + 会话提示 + 结果状态），沿用 `KoreUI` 错误映射 / confirm-token 流程；**G-28**：PC 1440×900 + 手机 390×844 双端截图存 `.agents/verify/screenshots/`，命名 `sshguard-dropin-desktop-*.png` / `sshguard-dropin-mobile-*.png`，另写自评三问 | `make frontend` 首屏 gzip 不变、无 `*.map`；截图 `identify` 实读 + 三问原文（照 c13 node-ext 范本） |
| 7 | `kore-plugins` | `index/plugins.json` + `index/versions.lock.json` 的 ssh-guard 0.5.0 sha/`size_bytes`/`requires_kore`；`presets/security.json` 与 `presets/full.json` 版本；`market/plugins.js` 经 `build-market.sh` 重生成；索引重签 | `bash scripts/validate-index.sh` exit 0；`make market-check` exit 0；同一 `id@version` 唯一 sha |

**版本语义**：pluginapi `feat→minor`（v0.3.0→v0.4.0）、ssh-guard `feat→minor`（0.4.1→0.5.0）。kore 内核 VERSION 的处置由实施卡按「是否改内核代码 + task-337 的 patch」判定，本方案不预设；但 `requires_kore` 下界**必须 ≥ task-337 所在内核版本**（回滚 mode 修复是「可回滚」宣称的硬前置）。

---

## 5. 分期判据与验收（⑤）

### P1 — 协议类目 + 内容策略 + 单测（不含插件/前端）

- 交付：`sshd.config.d` 类目、`sshd.dropin.v1` allowlist 校验器、ADR 新文 + ADR-0028 §9、PLUGIN-PROTOCOL 同步、pluginapi tag v0.4.0。
- 判据：`go test -race ./...`（pluginapi）绿；**拒绝集用例**逐条覆盖 §2.2 的全部 deny 指令 + 每类参数越界 + 路径/文件名越界 + 引号/续行/注释构造；正例覆盖 C12 harness 的三指令片段；`docs-check` exit 0。
- 不通过情形：任何 deny 指令被放行、任何 allowlist 指令能带越界参数、`nginx.vhost.v1` 回归变红、出现新依赖。

### P2 — 插件声明 + 前端 + G-28 + 发版涟漪

- 前置：P1 合入 **且 task-337 已合入**（回滚 mode 守恒）。
- 交付：§4 第 4–7 行全部；G-28 双端截图 + 三问。
- 判据：ssh-guard `make check` exit 0；dist sha 与 index/versions.lock 逐字节一致；`validate-index`/`market-check` exit 0；`version-check` 覆盖；G-28 截图 `identify` 实读 + 三问原文齐备（缺任一不得声明完成）。

### P3 — 隔离 VM 复验 + 发版

- 交付：`.agents/verify/c12-sshdropin-prod.md`，**照 c13-node-ext-verification 六项范本**：
  1. 后端方法 / 类目声明 / deny 清单 / 白名单 / 零新依赖 / root_action 形状核对；
  2. 门禁：pluginapi + ssh-guard + kore `make check` exit 0（既有 WARN 归因，0 新增 FAIL）；
  3. 隔离断言：复用 C12 harness 口径但**用生产代码**（非内联补丁）——一键应用、`sshd -t` exit0、`sshd -T` 生效、按账本逐字节**且逐属性**回滚（含 task-337 mode 守恒）、四类拒绝 + 审计 fail-closed、容器内密钥 SSH 连通性；
  4. 索引/版本一致性：`validate-index` exit 0 + 0.4.1→0.5.0 bump 理由（改 dist sha 必 bump）+ 六处 sha 一致；
  5. G-28 双端截图实读 + 三问原文；
  6. git：精确路径 + `Signed-off-by` + 未 push + 单 worktree + 他人 dirty 原样。
- 判据：六项全 PASS、无新增 FAIL、诚实边界（容器非真机 / 无 systemd-PAM / 无竞品同口径）逐条写明。
- 发版：lead 统一收敛三仓版本与推送；本方案 worker 不 push、不打 tag。

---

## 6. 风险与回退（⑥）

| 风险 | 处置 / 依赖 | 边界（不夸大） |
| --- | --- | --- |
| **sshd 锁死自己**（最高） | 基础机制已在 C12 隔离容器五项验过；生产代码闭环放 P3 VM；写前 `sshd -t` staging + 写后 `sshd -t`/`-T` + 自动回滚；应用≠reload（§3.3）；UI 提示保留密钥会话 | 容器非真机、无 systemd/PAM、无长时窗口；**不作真机长时间安全证据** |
| **回滚 mode 缺陷** | 硬依赖 task-337（`changes.go:169-180` + `filewrite.go:412-418`），未合入前 P1/P2 不得宣称「逐属性回滚」 | 本方案不改该代码，只声明依赖；P3 用例显式包含 mode 守恒断言 |
| **include 位置/发行版差异** | 主配置须在某处 `Include sshd_config.d/*.conf`；若 include 靠后且主配置重复定义同一指令，OpenSSH「先得值优先」会让 drop-in 失效 → 写后 `sshd -T` 复核生效值挡「静默无效果」；无 include 的发行版报明确「不支持」而非假装成功 | 标准 Debian/Ubuntu 布局已由 C12 哨兵配置旁证；RHEL/SUSE/自定义布局**未逐个取证** |
| **allowlist 解析器是安全关键代码** | 引号/续行/注释/`Match`/`Include` 的解析差一就是绕过；P1 用例 + fuzz + 红队绕过集，`sshd -T` 生效值复核；新增指令须走新 ADR 复审 | 不宣称 allowlist「消除全部风险」；业务后果（禁密码登录）由回滚与 VM 先验承担 |
| **SELinux/AppArmor** | 不作安全论据（ADR-0052 §2 同口径：Tier A 覆盖无 MAC 发行版） | 本环境未实测策略 |
| **无竞品同口径** | G-28 三问第 2 问如实写「与宝塔/1Panel 同类功能差距」，**不把隔离验证写成超越竞品的证据** | 对标报告只作定位，不作能力超越断言 |
| **跨仓一致性** | 按 G-15 在 `.agents/BOARD.md` 登记变更集（kore / plugin / plugins 三仓 commit 顺序）；G-23 台账登记裁决与派发 | 本 worker 只出方案、不碰 BOARD / 不提交跨仓改动 |

### 回退路径

P1 出问题：回退 pluginapi tag（新增类目/策略为纯加法，revert 即恢复 fail-closed）。P2 出问题：插件退回当前 `suggest` 建议态（保留旧方法，前端入口用特性开关隐藏），不回退内核原语。P3 出问题：VM 内按账本逐条 `purge_op` 清理，**宿主 `/etc/ssh` 全程零写入**。任何阶段都不 force-push、不改写历史。

---

## 7. 本轮未做（审阅前边界）

- 未写任何生产代码、未 bump 版本、未改 info.json / 前端 / 索引、未发版、未 push、未联网业务。
- 未碰宿主 `/etc/ssh`、未重启 sshd、未碰 8787 / `.kore-local-*`。
- 所有「已验证」结论均引自 C12 报告（`b16a575`）与读码事实；P1–P3 均为**待实施**，不是完成态。
