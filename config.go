package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// embeddedInfo 是随二进制发布的内嵌清单 manifest.json（只含握手字段，不含 size_bytes）：version / requires_kore /
// capabilities 与安装期 info.json 的握手字段保持一致，由 make dist 前置校验防漂移。
//
//go:embed manifest.json
var embeddedInfo []byte

// manifest 是 info.json 中插件运行期真正需要的字段，其余字段归内核校验。
type manifest struct {
	ID           string   `json:"id"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol"`
	RequiresKore string   `json:"requires_kore"`
	Capabilities []string `json:"capabilities"`
}

// 运行期可调参数的缺省值。
const (
	defaultLogPath      = "/var/log/auth.log"
	defaultLogSource    = "auto"
	defaultThreshold    = 10
	defaultRawTailLimit = 200
	// maxRawTailLimit 是 raw_tail 的协议上限（最多回 500 条原始行）。
	maxRawTailLimit = 500
)

// guardConfig 是防护统计的运行期参数：环境变量起底，ssh.config.set 可在进程内改写。
type guardConfig struct {
	LogPath             string // auth.log 路径（只读）
	LogSource           string // auto | auth | journal
	SuspiciousThreshold int    // 可疑 IP 阈值：单小时失败次数
	RawTailLimit        int    // attempts 原始行回传上限（0 = 不回传，≤500）
}

// defaultGuardConfig 返回缺省防护配置。
func defaultGuardConfig() guardConfig {
	return guardConfig{
		LogPath:             defaultLogPath,
		LogSource:           defaultLogSource,
		SuspiciousThreshold: defaultThreshold,
		RawTailLimit:        defaultRawTailLimit,
	}
}

// guardConfigFromEnv 读 KORE_SSHGUARD_* 环境变量（非法值回退缺省，不致命）。
func guardConfigFromEnv() guardConfig {
	g := defaultGuardConfig()
	if v := os.Getenv("KORE_SSHGUARD_LOG_PATH"); v != "" {
		g.LogPath = v
	}
	if v := os.Getenv("KORE_SSHGUARD_LOG_SOURCE"); v == "auto" || v == "auth" || v == "journal" {
		g.LogSource = v
	}
	if v := os.Getenv("KORE_SSHGUARD_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			g.SuspiciousThreshold = n
		}
	}
	if v := os.Getenv("KORE_SSHGUARD_RAW_TAIL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= maxRawTailLimit {
			g.RawTailLimit = n
		}
	}
	return g
}

// config 是插件运行期配置：环境变量 + 内嵌清单，不读任何配置文件。
type config struct {
	socket       string
	id           string
	token        string
	version      string
	requiresKore string
	capabilities []string
	// sshdConfig 是宿主预注入的 sshd 配置文本（KORE_SSHD_CONFIG）。
	// 为空时审计返回空检查项；本插件绝不自行读取 /etc/ssh/sshd_config。
	sshdConfig string
	startedAt  time.Time
	// guard 是 SSH 防护统计参数（日志路径 / 日志源 / 可疑阈值 / 原始行上限）。
	guard guardConfig
}

// loadConfig 读取协议环境变量与预注入配置文本，并解析内嵌 manifest.json。
func loadConfig() (config, error) {
	var m manifest
	if err := json.Unmarshal(embeddedInfo, &m); err != nil {
		return config{}, fmt.Errorf("解析内嵌 manifest.json: %w", err)
	}
	if m.Protocol != pluginapi.Protocol {
		return config{}, fmt.Errorf("info.json.protocol=%q 与 SDK 协议 %q 不一致", m.Protocol, pluginapi.Protocol)
	}
	cfg := config{
		socket:       os.Getenv("KORE_PLUGIN_SOCK"),
		id:           os.Getenv("KORE_PLUGIN_ID"),
		token:        os.Getenv("KORE_PLUGIN_TOKEN"),
		version:      m.Version,
		requiresKore: m.RequiresKore,
		capabilities: m.Capabilities,
		sshdConfig:   os.Getenv("KORE_SSHD_CONFIG"),
		startedAt:    time.Now(),
		guard:        guardConfigFromEnv(),
	}
	if cfg.id == "" {
		cfg.id = m.ID
	}
	if cfg.socket == "" {
		return config{}, fmt.Errorf("缺少环境变量 KORE_PLUGIN_SOCK")
	}
	return cfg, nil
}
