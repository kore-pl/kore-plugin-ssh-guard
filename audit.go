package main

import "strings"

// auditRule 定义一条 sshd 配置审计规则：指令名、推荐值、不合规时的建议。
type auditRule struct {
	Directive   string
	Recommended string
	Advice      string
}

// auditRules 是基础级审计规则集。
// 全部只读：从注入文本取值给建议，从不打开或改写真实 sshd_config。
var auditRules = []auditRule{
	{
		Directive:   "PermitRootLogin",
		Recommended: "prohibit-password",
		Advice:      "禁止 root 直接密码登录，保留密钥登录以便应急",
	},
	{
		Directive:   "PasswordAuthentication",
		Recommended: "no",
		Advice:      "关闭密码认证，改用密钥认证以抵御暴力破解",
	},
	{
		Directive:   "PermitEmptyPasswords",
		Recommended: "no",
		Advice:      "禁止空密码账户通过 SSH 登录",
	},
	{
		Directive:   "MaxAuthTries",
		Recommended: "3",
		Advice:      "收紧单次连接的认证尝试次数，降低爆破窗口",
	},
	{
		Directive:   "ChallengeResponseAuthentication",
		Recommended: "no",
		Advice:      "关闭键盘交互认证，避免绕过密码认证限制",
	},
}

// auditConfig 从配置文本提取指令值并逐条评估，返回稳定顺序的检查项。
// 同一指令多次出现时取第一次有效赋值；注释行与空行忽略。
func auditConfig(text string) []auditCheck {
	values := parseDirectives(text)
	checks := make([]auditCheck, 0, len(auditRules))
	for _, rule := range auditRules {
		current, present := values[strings.ToLower(rule.Directive)]
		check := auditCheck{
			Directive:   rule.Directive,
			Current:     current,
			Recommended: rule.Recommended,
			Advice:      rule.Advice,
			Compliant:   present && strings.EqualFold(current, rule.Recommended),
		}
		if !present {
			check.Current = "(未设置)"
		}
		checks = append(checks, check)
	}
	return checks
}

// parseDirectives 解析 sshd_config 文本：返回小写指令名到首个有效值的映射。
// 支持 "Key Value" 与 "Key=Value" 两种写法，跳过 # 注释与 Include 行。
func parseDirectives(text string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = stripInlineComment(line)
		key, value, ok := splitDirective(line)
		if !ok {
			continue
		}
		key = strings.ToLower(key)
		if key == "include" {
			continue
		}
		if _, exists := values[key]; !exists {
			values[key] = value
		}
	}
	return values
}

// splitDirective 把一行拆成指令名与值，兼容空格分隔与等号分隔。
func splitDirective(line string) (string, string, bool) {
	if i := strings.IndexAny(line, " \t="); i > 0 {
		key := line[:i]
		value := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		if value != "" {
			return key, value, true
		}
	}
	return "", "", false
}

// stripInlineComment 去掉值后面的 "# ..." 行内注释（不含行首注释）。
func stripInlineComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	return line
}
