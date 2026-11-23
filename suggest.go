package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// sshd 建议配置生成（降级方案 B）：只读渲染 + 风险提示 + 可复制命令，**绝不写宿主**。
//
// 为什么是"建议态"而不是自动下发：内核没有受控文件写原语，`sshd -t` 与
// `systemctl reload sshd` 也不在 ADR-0022 的形状表里；插件以非 root 运行，
// 直接写 /etc/ssh 既没权限也违反零侵入（ADR-0018/0023）。真机下发待 v1.1（需
// ADR-0022 增补受控写原语）。本方法只生成文本与命令，dry_run 恒为 true。

// dropInPath 是建议写入的 drop-in 路径（Debian/Ubuntu 默认被主文件 Include）。
const dropInPath = "/etc/ssh/sshd_config.d/kore.conf"

// sshdConfigPath 是读取当前配置的路径；readSSHDConfig 可被单测替换以模拟可读/不可读。
var (
	sshdConfigPath = "/etc/ssh/sshd_config"
	readSSHDConfig = os.ReadFile
)

// suggestParams 是 ssh-guard.suggest 的入参；零值表示不改该项。
type suggestParams struct {
	DisablePasswordAuth bool `json:"disable_password_auth,omitempty"`
	DisableRootLogin    bool `json:"disable_root_login,omitempty"`
	Port                int  `json:"port,omitempty"`
	MaxAuthTries        int  `json:"max_auth_tries,omitempty"`
}

// diffItem 是「当前值 vs 建议值」的一条关键项对比（仅当 /etc/ssh/sshd_config 可读）。
type diffItem struct {
	Directive string `json:"directive"`
	Current   string `json:"current"`
	Suggested string `json:"suggested"`
}

// riskItem 是一条风险提示：等级、后果、怎么回滚。
type riskItem struct {
	Code     string `json:"code"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Rollback string `json:"rollback"`
}

// suggestResult 是 ssh-guard.suggest 的结构化结果（dry_run 恒 true）。
type suggestResult struct {
	ConfigText      string     `json:"config_text"`
	PathHint        string     `json:"path_hint"`
	DiffFromCurrent []diffItem `json:"diff_from_current,omitempty"`
	Risk            []riskItem `json:"risk"`
	ApplyCommands   []string   `json:"apply_commands"`
	VerifyCommands  []string   `json:"verify_commands"`
	DryRun          bool       `json:"dry_run"`
}

// handleSuggest 处理 ssh-guard.suggest：校验参数 → 渲染 drop-in → 风险/命令/差异。
// 全程只读：最多 best-effort 读一次 /etc/ssh/sshd_config，不写任何文件、不执行命令。
func handleSuggest(raw json.RawMessage, response *pluginapi.Response) *pluginapi.Error {
	var p suggestParams
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	if p.Port < 0 || p.Port > 65535 {
		return invalidParam("port 必须在 1–65535 之间（0 表示不改端口）")
	}
	if p.MaxAuthTries < 0 || p.MaxAuthTries > 100 {
		return invalidParam("max_auth_tries 必须在 1–100 之间（0 表示不改）")
	}
	text := renderSuggestConfig(p)
	pathHint, currentText, readErr := inspectCurrentConfig()
	result := suggestResult{
		ConfigText:     text,
		PathHint:       pathHint,
		Risk:           suggestRisks(p),
		ApplyCommands:  applyCommandsFor(text),
		VerifyCommands: verifyCommandsFor(p),
		DryRun:         true,
	}
	if readErr == nil {
		result.DiffFromCurrent = diffFromCurrent(p, currentText)
	}
	response.Result = encode(result)
	return nil
}

// renderSuggestConfig 渲染 drop-in 文本（纯函数：同参数同文本，分段注释）。
func renderSuggestConfig(p suggestParams) string {
	var b strings.Builder
	b.WriteString("# kore ssh-guard 建议配置（建议态：插件不会自动下发）\n")
	b.WriteString("# 目标文件：" + dropInPath + "（权限 0644 root:root）\n")
	b.WriteString("# 前置：主文件 /etc/ssh/sshd_config 需包含 Include /etc/ssh/sshd_config.d/*.conf\n")
	b.WriteString("# 回滚：删除本文件后执行 sudo sshd -t && sudo systemctl reload sshd\n")
	if !hasSuggestChange(p) {
		b.WriteString("\n# 未指定任何加固项：请至少传 disable_password_auth / disable_root_login / port / max_auth_tries 之一\n")
		return b.String()
	}
	if p.DisablePasswordAuth {
		b.WriteString("\n# --- 认证方式 ---\n")
		b.WriteString("# 关闭密码认证，仅保留密钥/其它认证（确保已有可用密钥会话）\n")
		b.WriteString("PasswordAuthentication no\n")
	}
	if p.DisableRootLogin {
		b.WriteString("\n# --- root 登录 ---\n")
		b.WriteString("# 禁止 root 直接登录（保留普通用户 + sudo 运维）\n")
		b.WriteString("PermitRootLogin no\n")
	}
	if p.Port > 0 {
		b.WriteString("\n# --- 监听端口 ---\n")
		fmt.Fprintf(&b, "# 先放行 %d/tcp 并用 ssh -p %d 验证，再 reload\n", p.Port, p.Port)
		fmt.Fprintf(&b, "Port %d\n", p.Port)
	}
	if p.MaxAuthTries > 0 {
		b.WriteString("\n# --- 认证尝试次数 ---\n")
		b.WriteString("# 收紧单连接认证尝试次数\n")
		fmt.Fprintf(&b, "MaxAuthTries %d\n", p.MaxAuthTries)
	}
	return b.String()
}

// hasSuggestChange 报告是否有任何非零加固项。
func hasSuggestChange(p suggestParams) bool {
	return p.DisablePasswordAuth || p.DisableRootLogin || p.Port > 0 || p.MaxAuthTries > 0
}

// inspectCurrentConfig 尝试只读当前主配置，返回路径提示与文本；读不到时给出原因说明。
func inspectCurrentConfig() (string, string, error) {
	data, err := readSSHDConfig(sshdConfigPath)
	if err != nil {
		return "读不到 " + sshdConfigPath + "（" + err.Error() + "）：无法给出当前值对比；建议写入 " + dropInPath + "，插件不会自动写入，请按 apply_commands 手工下发", "", err
	}
	text := string(data)
	if strings.Contains(strings.ToLower(text), "include "+strings.ToLower(dropInPath[:strings.LastIndex(dropInPath, "/")])) ||
		strings.Contains(strings.ToLower(text), "include") && strings.Contains(text, "sshd_config.d") {
		return "建议写入 " + dropInPath + "（主文件已包含 Include /etc/ssh/sshd_config.d/*.conf）", text, nil
	}
	return "建议写入 " + dropInPath + "，但主文件未见 sshd_config.d 的 Include：请先确认/添加 Include /etc/ssh/sshd_config.d/*.conf（或把 config_text 追加到主文件）", text, nil
}

// suggestRisks 按加固项生成风险提示（每条都带怎么回滚）。
func suggestRisks(p suggestParams) []riskItem {
	risks := make([]riskItem, 0, 4)
	if p.Port > 0 {
		risks = append(risks, riskItem{
			Code: "port_change", Level: "high",
			Message:  fmt.Sprintf("改 Port 前必须先在防火墙/云安全组放行 %d/tcp，并用 ssh -p %d 在新端口验证可登录；否则 reload 后新连接会被拒", p.Port, p.Port),
			Rollback: "把 Port 改回原值（见 diff_from_current 的 current）后重跑 sshd -t 与 systemctl reload sshd；或从 cp -a 备份恢复主配置",
		})
	}
	if p.DisablePasswordAuth {
		risks = append(risks, riskItem{
			Code: "disable_password_auth", Level: "high",
			Message:  "禁用密码前确认：已配置可用密钥（authorized_keys）、且当前不是唯一密码会话；先另开一个密钥会话验证成功再 reload",
			Rollback: "删除 kore.conf 中的 PasswordAuthentication 行（或删整个 drop-in / 恢复备份）后执行 sudo sshd -t && sudo systemctl reload sshd",
		})
	}
	if p.DisableRootLogin {
		risks = append(risks, riskItem{
			Code: "disable_root_login", Level: "medium",
			Message:  "禁 root 前确认存在可登录、可 sudo 的普通用户；否则会失去管理入口",
			Rollback: "删除 kore.conf 中的 PermitRootLogin 行（或删整个 drop-in / 恢复备份）后执行 sudo sshd -t && sudo systemctl reload sshd",
		})
	}
	if p.MaxAuthTries > 0 {
		risks = append(risks, riskItem{
			Code: "max_auth_tries", Level: "low",
			Message:  "MaxAuthTries 过低会让多密钥/自动化客户端更早被断开；确认现有客户端认证次数不超过该值",
			Rollback: "把 MaxAuthTries 调回原值（或删除该行）后执行 sudo sshd -t && sudo systemctl reload sshd",
		})
	}
	return risks
}

// applyCommandsFor 生成可直接复制的命令序列（备份 → 写 drop-in → 校验 → reload），
// 每步带注释；不含任何占位符（端口等参数已渲染为实际值）。
func applyCommandsFor(configText string) []string {
	commands := []string{
		"# 1) 备份主配置（时间戳后缀，保留原权限）",
		"sudo cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.kore.bak.$(date +%Y%m%d-%H%M%S)",
		"# 2) 确认 drop-in 目录存在",
		"sudo install -d -m 0755 /etc/ssh/sshd_config.d",
		"# 3) 写入建议配置（0644 root:root，内容见 config_text）",
		"sudo tee " + dropInPath + " > /dev/null <<'KORE_SSHD_EOF'",
	}
	commands = append(commands, strings.Split(strings.TrimRight(configText, "\n"), "\n")...)
	commands = append(commands,
		"KORE_SSHD_EOF",
		"# 4) 语法校验：失败必须回滚，不要 reload",
		"sudo sshd -t",
		"# 5) 校验通过后 reload（不断开现有会话；不要用 restart）",
		"sudo systemctl reload sshd",
	)
	return commands
}

// verifyCommandsFor 生成验证命令（sshd -T 输出的是最终生效值）。
func verifyCommandsFor(p suggestParams) []string {
	if !hasSuggestChange(p) {
		return []string{"sudo sshd -T | grep -E '^(passwordauthentication|permitrootlogin|port|maxauthtries) '"}
	}
	commands := make([]string, 0, 4)
	if p.DisablePasswordAuth {
		commands = append(commands, "sudo sshd -T | grep -i '^passwordauthentication '")
	}
	if p.DisableRootLogin {
		commands = append(commands, "sudo sshd -T | grep -i '^permitrootlogin '")
	}
	if p.Port > 0 {
		commands = append(commands, "sudo sshd -T | grep -i '^port '")
	}
	if p.MaxAuthTries > 0 {
		commands = append(commands, "sudo sshd -T | grep -i '^maxauthtries '")
	}
	return commands
}

// diffFromCurrent 对比当前值与建议值；只返回有变化的项（当前配置不可读时返回 nil）。
func diffFromCurrent(p suggestParams, currentText string) []diffItem {
	values := parseDirectives(currentText)
	items := make([]diffItem, 0, 4)
	add := func(directive, suggested string) {
		current, ok := values[strings.ToLower(directive)]
		if !ok {
			current = "(未设置)"
		}
		if strings.EqualFold(current, suggested) {
			return
		}
		items = append(items, diffItem{Directive: directive, Current: current, Suggested: suggested})
	}
	if p.DisablePasswordAuth {
		add("PasswordAuthentication", "no")
	}
	if p.DisableRootLogin {
		add("PermitRootLogin", "no")
	}
	if p.Port > 0 {
		add("Port", fmt.Sprintf("%d", p.Port))
	}
	if p.MaxAuthTries > 0 {
		add("MaxAuthTries", fmt.Sprintf("%d", p.MaxAuthTries))
	}
	return items
}
