package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// rootActionTimeout 是插件经内核 root-action 通道执行只读命令的 HTTP 层上限；
// 动作本身的执行上限由 info.json 的 timeout_s 兜底，这里只防 HTTP 永久挂住。
const rootActionTimeout = 15 * time.Second

// maxRootActionBody 是 root-action 响应体的读取上限（stdout/stderr 各 ≤1 MiB，留余量）。
const maxRootActionBody = 4 << 20

// rootActionOutput 是 root 动作执行结果（内核 privilege.Result 的子集，显式定形）。
type rootActionOutput struct {
	// Stdout / Stderr 是内核采集的命令输出（各截断 1 MiB）。
	Stdout string
	Stderr string
	// ExitCode 是命令退出码；-1 表示启动失败或超时被 kill。
	ExitCode int
}

// rootActionFunc 是插件→内核提权通道的调用面；nil 表示通道未注入（按降级处理）。
//
// confirm 是不可回滚动作的一次性令牌（内核 privilege.Execute 核销）；只读与可逆动作为空串。
type rootActionFunc func(actionID string, args []string, confirm string) (rootActionOutput, error)

// rootActionClient 是插件→内核提权通道的客户端（ADR-0018）。
//
// 传输：内核 UDS 上的 HTTP（KORE_KERNEL_SOCK 由 supervisor 注入）；
// 身份：KORE_PLUGIN_TOKEN bearer——内核只允许插件调用自己声明的 root_actions，
// 且要求该插件已获 system:admin。插件自身永不 exec sudo / setuid。
type rootActionClient struct {
	pluginID string
	token    string
	client   *http.Client
}

// newRootActionClient 在三个环境变量齐备时构造客户端；缺一返回 nil（通道不可用）。
func newRootActionClient() *rootActionClient {
	socket := os.Getenv("KORE_KERNEL_SOCK")
	token := os.Getenv("KORE_PLUGIN_TOKEN")
	pluginID := os.Getenv("KORE_PLUGIN_ID")
	if socket == "" || token == "" || pluginID == "" {
		return nil
	}
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	return &rootActionClient{
		pluginID: pluginID,
		token:    token,
		client:   &http.Client{Transport: transport, Timeout: rootActionTimeout},
	}
}

// rootActionFuncFromEnv 在通道三要素齐备时返回调用面；缺一返回 nil。
func rootActionFuncFromEnv() rootActionFunc {
	client := newRootActionClient()
	if client == nil {
		return nil
	}
	return client.Call
}

// rootActionRequest / rootActionResponse / rootActionError 是通道的 JSON 契约。
type rootActionRequest struct {
	ActionID string   `json:"action_id"`
	Args     []string `json:"args,omitempty"`
	// Confirm 是不可回滚动作的一次性令牌（内核侧 schema：confirm,omitempty）。
	Confirm string `json:"confirm,omitempty"`
}

type rootActionResponse struct {
	Executed bool   `json:"executed"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	Unit     string `json:"unit"`
}

type rootActionError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// fileWriteRequest 是 file_write 动作的请求体（ADR-0052 / ADR-0060）：单层文件名 + 正文。
// 目录不在请求里——它只来自 info.json 声明的类别（sshd.config.d），
// 插件自报目录的字段根本不存在，所以这里没有第二条注入面。
type fileWriteRequest struct {
	ActionID string   `json:"action_id"`
	Args     []string `json:"args"`
	Content  string   `json:"content"`
}

// fileWriteFunc 是插件→内核受控写的调用面；nil 表示内核未注入提权通道。
//
// 与 rootActionFunc（exec 动作）分开：file_write 的请求体多一个 content 字段，
// 两种语义不混用，避免「一半走 argv、一半走正文」的歧义。
type fileWriteFunc func(actionID, name, content string) (rootActionOutput, error)

// fileDeleteFunc 是插件→内核受控删除的调用面；nil 表示内核未注入提权通道。
// 删除请求只有 action_id + args[0]（单层文件名），不带正文。
type fileDeleteFunc func(actionID, name string) (rootActionOutput, error)

// fileWriteFuncFromEnv 在通道三要素齐备时返回受控写调用面；缺一返回 nil。
func fileWriteFuncFromEnv() fileWriteFunc {
	client := newRootActionClient()
	if client == nil {
		return nil
	}
	return client.WriteFile
}

// fileDeleteFuncFromEnv 在通道三要素齐备时返回受控删除调用面；缺一返回 nil。
func fileDeleteFuncFromEnv() fileDeleteFunc {
	client := newRootActionClient()
	if client == nil {
		return nil
	}
	return client.DeleteFile
}

// Call 经内核执行一个声明过的 root 动作（exec / file_delete），返回输出与退出码。
// 错误信息保留内核错误码与 hint，便于上层拼可操作提示（不吞错、不改写成成功）。
//
// confirm 只用于不可回滚动作（info.json 的 irreversible:true）；其余动作传空串。
// 令牌由管理员会话经内核 confirm-token 端点签发，插件不自行签发/伪造。
func (c *rootActionClient) Call(actionID string, args []string, confirm string) (rootActionOutput, error) {
	body, err := json.Marshal(rootActionRequest{ActionID: actionID, Args: args, Confirm: confirm})
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("序列化 root-action 请求失败：%w", err)
	}
	return c.post(body)
}

// WriteFile 经内核受控写通道写 drop-in 片段：不 exec 任何命令，
// 备份 / 审计 / 原子替换 / 属主复核 / changes.jsonl 全在内核侧（ADR-0052/0060）。
func (c *rootActionClient) WriteFile(actionID, name, content string) (rootActionOutput, error) {
	body, err := json.Marshal(fileWriteRequest{ActionID: actionID, Args: []string{name}, Content: content})
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("序列化 file_write 请求失败：%w", err)
	}
	return c.post(body)
}

// DeleteFile 经内核受控删除通道删 drop-in 片段：不 exec 任何命令、不 os.Remove；
// 属主复核 / 强制备份 / 审计 / changes.jsonl（purge_op=file.restore）全在内核侧（ADR-0053）。
func (c *rootActionClient) DeleteFile(actionID, name string) (rootActionOutput, error) {
	body, err := json.Marshal(rootActionRequest{ActionID: actionID, Args: []string{name}})
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("序列化 file_delete 请求失败：%w", err)
	}
	return c.post(body)
}

// post 是通道请求的公共 HTTP 层：UDS → 解析协议错误 / 结果（body 由各语义各自序列化）。
func (c *rootActionClient) post(body []byte) (rootActionOutput, error) {
	req, err := http.NewRequest(http.MethodPost,
		"http://kore/api/v1/plugins/"+c.pluginID+"/root-action", bytes.NewReader(body))
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("构造 root-action 请求失败：%w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("调用内核 root-action 失败：%w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRootActionBody))
	if err != nil {
		return rootActionOutput{}, fmt.Errorf("读取 root-action 响应失败：%w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var protocolErr rootActionError
		if json.Unmarshal(raw, &protocolErr) == nil && protocolErr.Code != "" {
			hint := ""
			if protocolErr.Hint != "" {
				hint = "（" + protocolErr.Hint + "）"
			}
			return rootActionOutput{}, fmt.Errorf("%s: %s%s", protocolErr.Code, protocolErr.Message, hint)
		}
		return rootActionOutput{}, fmt.Errorf("内核 root-action 返回 HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var result rootActionResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return rootActionOutput{}, fmt.Errorf("解析 root-action 响应失败：%w", err)
	}
	return rootActionOutput{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode}, nil
}
