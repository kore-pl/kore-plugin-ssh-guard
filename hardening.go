package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// ssh-guard 一键加固：apply 经内核受控写把 suggest 渲染的片段写进 sshd_config.d，
// rollback 先读 changes.jsonl 核对本插件写入的结构化 purge_op，再经内核受控删除
// 撤销 drop-in（删前内核强制备份 + 登记 file.restore），全程不执行 shell、不碰宿主 /etc/ssh 直写。
//
// 安全边界（ADR-0060 / 方案 DESIGN-SSH-DROPIN §3.3）：
//   - 插件进程永不直接写 /etc/ssh；写/删都经 root-action 通道（ADR-0018/0052/0053）；
//   - 应用只写 drop-in，**不 reload / restart sshd**——下次 sshd 重载/重启才生效；
//   - 回滚只读账本识别本插件条目；账本在 <state>/changes.jsonl（0600，插件可读时），
//     读不到/坏条目一律显式报错，不猜路径、不伪造成功。
const (
	rootActionSSHDWrite  = "sshd-dropin-write"
	rootActionSSHDDelete = "sshd-dropin-delete"
	// dropInFileName 是唯一的 drop-in 文件名（类别层强制 kore-ssh-guard- 前缀 + .conf 后缀）。
	dropInFileName = "kore-ssh-guard-hardening.conf"
	// maxDropInContentBytes 与 info.json 的 file_write.max_bytes 一致（插件侧自收紧，
	// 内核侧还会按协议类别与声明独立复核）。
	maxDropInContentBytes = 64 << 10
	// changesFileName / purge 类型与内核 cmd/kored/changes.go 同源（JSON 形状锁定）。
	changesFileName      = "changes.jsonl"
	purgeKindFileRemove  = "file.remove"
	purgeKindFileRestore = "file.restore"
)

// guardFileWrite / guardFileDelete 是内核受控写/删的调用面；nil = 通道未注入。
// 与 guardRootAction 同口径的注入点，便于单测替身（不碰真实 root 通道）。
var (
	guardFileWrite  fileWriteFunc  = fileWriteFuncFromEnv()
	guardFileDelete fileDeleteFunc = fileDeleteFuncFromEnv()
)

// hardeningHintDetail 是错误 detail 的机器可读形状（显式定形，G-24）。
type hardeningHintDetail struct {
	Hint       string `json:"hint"`
	RootAction string `json:"root_action,omitempty"`
}

// hardeningApplyParams 与 suggestParams 同字段：只复用 suggest 的渲染路径。
type hardeningApplyParams = suggestParams

// hardeningApplyResult 是 apply-hardening 的结构化结果（不回显全文，只回路径/哈希/大小）。
type hardeningApplyResult struct {
	Applied     bool       `json:"applied"`
	File        string     `json:"file"`
	Action      string     `json:"action"`
	SHA256      string     `json:"sha256,omitempty"`
	Size        int        `json:"size,omitempty"`
	Diff        []diffItem `json:"diff_from_current,omitempty"`
	Risk        []riskItem `json:"risk"`
	ReloadHint  string     `json:"reload_hint"`
	SessionHint string     `json:"session_hint"`
	Rollback    string     `json:"rollback"`
}

// hardeningRollbackResult 是 rollback-hardening 的结构化结果。
type hardeningRollbackResult struct {
	RolledBack    bool   `json:"rolled_back"`
	File          string `json:"file"`
	Operation     string `json:"operation"`
	LedgerPurgeOp string `json:"ledger_purge_op"`
	Hint          string `json:"hint"`
}

// changeEntryView 只取回滚需要的账本字段（显式定形，不用 map[string]any，G-24）。
type changeEntryView struct {
	Action     string       `json:"action"`
	Plugin     string       `json:"plugin"`
	Target     string       `json:"target"`
	Reversible bool         `json:"reversible"`
	PurgeOp    *purgeOpView `json:"purge_op,omitempty"`
}

// purgeOpView 与 pluginapi.PurgeOp 的 JSON 形状一致（不引入内核私有类型）。
type purgeOpView struct {
	Kind string   `json:"kind"`
	Args []string `json:"args"`
}

// handleApplyHardening 把 suggest 渲染的 config_text 经受控写写进 drop-in。
// 写后不 reload：返回的 reload_hint / session_hint 必须在 UI 原文展示。
func handleApplyHardening(raw json.RawMessage, call fileWriteFunc, response *pluginapi.Response) *pluginapi.Error {
	var p hardeningApplyParams
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
	if !hasSuggestChange(p) {
		return invalidParam("请至少指定一个加固项（disable_password_auth / disable_root_login / port / max_auth_tries），拒绝写入空建议")
	}
	// 只走 suggest 的渲染函数：apply/suggest 的 config_text 必须逐字节同源。
	content := renderSuggestConfig(p)
	if len(content) > maxDropInContentBytes {
		return invalidParam(fmt.Sprintf("加固片段 %d 字节超过 %d 字节上限", len(content), maxDropInContentBytes))
	}
	if call == nil {
		return hardeningRootUnavailable(rootActionSSHDWrite)
	}
	out, err := call(rootActionSSHDWrite, dropInFileName, content)
	if err != nil {
		return hardeningChannelError(rootActionSSHDWrite, err)
	}
	if out.ExitCode != 0 {
		return &pluginapi.Error{Code: pluginapi.E_UPSTREAM,
			Message: fmt.Sprintf("受控写 %s 失败（exit_code=%d）：%s", rootActionSSHDWrite, out.ExitCode, strings.TrimSpace(out.Stderr)),
			Detail:  hardeningDetail(rootActionSSHDWrite, "查看内核审计与 changes.jsonl 确认是否落盘；失败不要盲目重试覆盖。")}
	}
	_, currentText, readErr := inspectCurrentConfig()
	var diff []diffItem
	if readErr == nil {
		diff = diffFromCurrent(p, currentText)
	}
	response.Result = encode(hardeningApplyResult{
		Applied:     true,
		File:        dropInDir() + dropInFileName,
		Action:      rootActionSSHDWrite,
		Size:        len(content),
		Diff:        diff,
		Risk:        suggestRisks(p),
		ReloadHint:  "应用只写入配置片段，不重载 sshd：新设置下次 sshd 重载/重启后才生效。",
		SessionHint: "请保留当前密钥登录会话、不要关闭终端；另开一个会话验证密钥可登录后再自行 reload。",
		Rollback:    "可在加固面板点「回滚」，核对 changes.jsonl 的结构化 purge_op 后经受控删除撤销本次写入。",
	})
	return nil
}

// handleRollbackHardening 读取 <state>/changes.jsonl，定位本插件 drop-in 写入条目，
// 核对内核运行时生成的结构化 purge_op 形状后，经内核受控删除撤销文件。
//
// 为什么用 file_delete 而不是直接消费 purge_op：purge_op 是内核卸载/运维回滚用的
// 账户本，插件没有以 root 执行 purge 的合法通道；让内核按受控删除原语再走一遍
// 「属主复核 → 强制备份 → 审计 → 账本 file.restore」才是零侵入语义。
func handleRollbackHardening(call fileDeleteFunc, response *pluginapi.Response) *pluginapi.Error {
	stateDir := strings.TrimSpace(os.Getenv("KORE_STATE_DIR"))
	if stateDir == "" {
		return &pluginapi.Error{Code: pluginapi.E_INVALID,
			Message: "读不到 KORE_STATE_DIR，无法定位宿主变更账本，未执行回滚",
			Detail:  hardeningDetail(rootActionSSHDDelete, "请确认插件由 kored 启动（内核会注入 KORE_STATE_DIR）；手工清理请按 changes.jsonl 里的 purge_op 操作。")}
	}
	ledger := filepath.Join(stateDir, changesFileName)
	entries, err := readHardeningEntries(ledger)
	if err != nil {
		return &pluginapi.Error{Code: pluginapi.E_INTERNAL,
			Message: fmt.Sprintf("读取宿主变更账本失败（%s）：%v，未执行回滚", ledger, err),
			Detail:  hardeningDetail(rootActionSSHDDelete, "请确认 kored 以 root 服务运行、账本存在且当前插件用户可读；不要用 rm 绕过账本。")}
	}
	var last *changeEntryView
	for i := range entries {
		entry := &entries[i]
		if entry.Plugin != "ssh-guard" || entry.Action != rootActionSSHDWrite {
			continue
		}
		if !entry.Reversible || entry.PurgeOp == nil {
			return &pluginapi.Error{Code: pluginapi.E_INTERNAL,
				Message: "账本里的 sshd drop-in 写入条目缺少结构化 purge_op，拒绝回滚（不猜回滚动作）",
				Detail:  hardeningDetail(rootActionSSHDDelete, "请人工按 changes.jsonl 的 target 与备份目录处理；不要直接删除文件而不留痕。")}
		}
		if err := validateLedgerPurgeOp(entry.PurgeOp); err != nil {
			return &pluginapi.Error{Code: pluginapi.E_INVALID,
				Message: "账本里的 purge_op 越界，拒绝执行：" + err.Error(),
				Detail:  hardeningDetail(rootActionSSHDDelete, "账本可能被篡改，请以备份恢复后重新应用。")}
		}
		last = entry // 顺序扫描，取最后一条（最近一次写入）
	}
	if last == nil {
		return &pluginapi.Error{Code: pluginapi.E_NOTFOUND,
			Message: "账本里没有本插件的 sshd drop-in 写入记录，未执行回滚",
			Detail:  hardeningDetail(rootActionSSHDDelete, "确认之前是否用过「一键应用」；若 drop-in 是手工写入的，请自行删除并记录。")}
	}
	if call == nil {
		return hardeningRootUnavailable(rootActionSSHDDelete)
	}
	out, err := call(rootActionSSHDDelete, dropInFileName)
	if err != nil {
		return hardeningChannelError(rootActionSSHDDelete, err)
	}
	if out.ExitCode != 0 {
		return &pluginapi.Error{Code: pluginapi.E_UPSTREAM,
			Message: fmt.Sprintf("受控删除 %s 失败（exit_code=%d）：%s", rootActionSSHDDelete, out.ExitCode, strings.TrimSpace(out.Stderr)),
			Detail:  hardeningDetail(rootActionSSHDDelete, "请查看内核审计与 changes.jsonl 确认当前状态；不要手工 rm 绕过账本。")}
	}
	response.Result = encode(hardeningRollbackResult{
		RolledBack:    true,
		File:          dropInDir() + dropInFileName,
		Operation:     rootActionSSHDDelete + "/" + purgeKindFileRestore,
		LedgerPurgeOp: last.PurgeOp.Kind,
		Hint:          "回滚只撤销文件内容，不逆转 sshd 进程状态：下次 sshd 重载/重启才读回旧配置。请保留密钥会话，自行确认是否 reload。",
	})
	return nil
}

// readHardeningEntries 逐行读账本，坏行跳过（与内核 readChanges 同口径）。
func readHardeningEntries(path string) ([]changeEntryView, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	entries := make([]changeEntryView, 0, 8)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var entry changeEntryView
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// validateLedgerPurgeOp 在回滚前 fail-closed 核对账本条目：kind 白名单 + 参数个数 +
// 绝对路径（非根、无 ..）+ 目标必须落在本插件类目目录内。防止被篡改的账本把回滚
// 变成任意路径删除/覆盖的句柄（内核执行 purge 时另有自己的收口，这里是第二道门）。
func validateLedgerPurgeOp(op *purgeOpView) error {
	if op == nil {
		return fmt.Errorf("purge_op 为空")
	}
	args := op.Args
	switch op.Kind {
	case purgeKindFileRemove:
		if len(args) != 1 {
			return fmt.Errorf("file.remove 需要 1 个参数（path），当前 %d 个", len(args))
		}
		if err := validateLedgerPath(args[0]); err != nil {
			return err
		}
		if !strings.HasPrefix(args[0], dropInDir()) || strings.Contains(strings.TrimPrefix(args[0], dropInDir()), "/") {
			return fmt.Errorf("purge 目标 %q 不在 sshd drop-in 目录内", args[0])
		}
		return nil
	case purgeKindFileRestore:
		if len(args) != 2 {
			return fmt.Errorf("file.restore 需要 2 个参数（备份, 目标），当前 %d 个", len(args))
		}
		if err := validateLedgerPath(args[0]); err != nil {
			return err
		}
		if err := validateLedgerPath(args[1]); err != nil {
			return err
		}
		if !strings.HasPrefix(args[1], dropInDir()) || strings.Contains(strings.TrimPrefix(args[1], dropInDir()), "/") {
			return fmt.Errorf("purge 目标 %q 不在 sshd drop-in 目录内", args[1])
		}
		return nil
	default:
		return fmt.Errorf("未知 purge kind %q（仅允许 file.remove / file.restore）", op.Kind)
	}
}

func validateLedgerPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("purge 路径为空")
	}
	if !strings.HasPrefix(path, "/") || filepath.Clean(path) != path {
		return fmt.Errorf("purge 路径必须是规范化绝对路径（禁 .. / 重复分隔符）：%q", path)
	}
	if filepath.Dir(filepath.Clean(path)) == "/" {
		return fmt.Errorf("purge 路径指向根目录：%q", path)
	}
	return nil
}

// dropInDir 是协议类别目录的唯一口径（与 info.json root_actions[].target 一致）。
func dropInDir() string { return "/etc/ssh/sshd_config.d/" }

func hardeningDetail(action, hint string) json.RawMessage {
	b, _ := json.Marshal(hardeningHintDetail{Hint: hint, RootAction: action})
	return b
}

func hardeningRootUnavailable(action string) *pluginapi.Error {
	return &pluginapi.Error{Code: needRootCode,
		Message: "此操作需要内核受控文件通道，当前未注入，未改动任何文件",
		Detail:  hardeningDetail(action, "请用 root 启动 kored 并安装启用本插件；插件进程自身永不提权、不直接读写 /etc/ssh。")}
}

func hardeningChannelError(action string, err error) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL,
		Message: "内核受控文件通道调用失败：" + err.Error(),
		Detail:  hardeningDetail(action, "请查看内核审计与 changes.jsonl 确认是否落盘；失败不要盲目重试。")}
}
