package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// maxConfigBytes 是 sshd_config 注入文本的上限，避免超长请求占内存。
const maxConfigBytes = 64 << 10

// statusResult 是 kore.ping 的结果（PLUGIN-PROTOCOL §7.1）。
type statusResult struct {
	Status     string `json:"status"`
	UptimeS    int64  `json:"uptime_s"`
	Goroutines int    `json:"goroutines"`
}

// dispatch 把请求分发为响应帧；第二个返回值表示收到 kore.shutdown。
func dispatch(request *pluginapi.Request, cfg config, logger *slog.Logger) (*pluginapi.Response, bool) {
	response := &pluginapi.Response{Type: pluginapi.TypeResponse, ID: request.ID, ReqID: request.ReqID}
	switch request.Method {
	case "kore.shutdown":
		response.Result = json.RawMessage(`{"ok":true}`)
		logger.Info("收到 kore.shutdown，优雅退出")
		return response, true
	case "kore.ping":
		response.Result = encode(pingResult(cfg))
		return response, false
	case "kore.reload":
		response.Result = json.RawMessage(`{"ok":true,"config_digest":""}`)
		return response, false
	}
	verb, ok := businessVerb(request.Method, cfg.id)
	if !ok {
		response.Error = notFound(request.Method)
		return response, false
	}
	var perr *pluginapi.Error
	switch verb {
	case "status":
		perr = handleStatus(request.Params, cfg, response)
	case "ban.list":
		perr = handleBanList(request.Params, response)
	default:
		perr = notFound(verb)
	}
	if perr != nil {
		response.Error = perr
		response.Result = nil
	}
	return response, false
}

// businessVerb 把 <id>.<verb> 或裸 <verb> 归一为动词名。
func businessVerb(method, id string) (string, bool) {
	verb := strings.TrimPrefix(method, id+".")
	switch verb {
	case "status", "ban.list":
		return verb, true
	default:
		return "", false
	}
}

// handleStatus 返回只读审计结果：配置文本来自请求或宿主注入，不读不写真实 sshd_config。
func handleStatus(raw json.RawMessage, cfg config, response *pluginapi.Response) *pluginapi.Error {
	text, perr := parseConfigText(raw, cfg)
	if perr != nil {
		return perr
	}
	checks := auditConfig(text)
	issues := 0
	for _, c := range checks {
		if !c.Compliant {
			issues++
		}
	}
	response.Result = encode(statusAuditResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
		Checks:     checks,
		Total:      len(checks),
		Issues:     issues,
		Applied:    false,
	})
	return nil
}

// parseConfigText 校验 ssh.status 入参并取出审计文本：优先请求内联，其次宿主注入。
func parseConfigText(raw json.RawMessage, cfg config) (string, *pluginapi.Error) {
	p := struct {
		SSHDConfig *string `json:"sshd_config"`
	}{}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return "", invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", invalidParam("params 解析失败: " + err.Error())
		}
	}
	text := cfg.sshdConfig
	if p.SSHDConfig != nil {
		text = *p.SSHDConfig
	}
	if len(text) > maxConfigBytes {
		return "", invalidParam("sshd_config 超过 64 KiB 上限")
	}
	return text, nil
}

// handleBanList 返回结构化封禁清单；basic 骨架不含真实封禁执行器，恒为空且 applied=false。
func handleBanList(raw json.RawMessage, response *pluginapi.Response) *pluginapi.Error {
	p, perr := parseBanParams(raw)
	if perr != nil {
		return perr
	}
	response.Result = encode(banListResult{
		Bans:    []banEntry{},
		Count:   0,
		Limit:   p.Limit,
		Offset:  p.Offset,
		Applied: false,
	})
	return nil
}

// parseBanParams 校验 ssh.ban.list 入参：limit 1..100、offset ≥0、address 为合法 IP。
func parseBanParams(raw json.RawMessage) (banParams, *pluginapi.Error) {
	p := banParams{Limit: 20}
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return p, invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return p, invalidParam("params 解析失败: " + err.Error())
		}
		if p.limitSet() && (p.Limit < 1 || p.Limit > 100) {
			return p, invalidParam("limit 必须在 1..100")
		}
	}
	if p.Offset < 0 {
		return p, invalidParam("offset 不能为负")
	}
	if p.Address != "" && net.ParseIP(p.Address) == nil {
		return p, invalidParam("address 不是合法 IP 地址")
	}
	return p, nil
}

// invalidParam 构造 E_INVALID 错误体（§9）。
func invalidParam(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

// notFound 构造 E_NOTFOUND 错误体（§9）。
func notFound(method string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
}

// pingResult 组装 kore.ping 结果。
func pingResult(cfg config) statusResult {
	return statusResult{
		Status:     "ready",
		UptimeS:    int64(time.Since(cfg.startedAt).Seconds()),
		Goroutines: runtime.NumGoroutine(),
	}
}
