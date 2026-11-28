package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// hardeningChan 是 apply/rollback 单测用的内存替身（不碰真实 UDS / root 通道）。
type hardeningChan struct {
	writeCalls  []fileWriteCall
	deleteCalls []fileDeleteCall
	writeErr    error
	deleteErr   error
	exitCode    int
}

type fileWriteCall struct {
	action, name, content string
}

type fileDeleteCall struct {
	action, name string
}

func (c *hardeningChan) write(action, name, content string) (rootActionOutput, error) {
	c.writeCalls = append(c.writeCalls, fileWriteCall{action, name, content})
	return rootActionOutput{ExitCode: c.exitCode}, c.writeErr
}

func (c *hardeningChan) del(action, name string) (rootActionOutput, error) {
	c.deleteCalls = append(c.deleteCalls, fileDeleteCall{action, name})
	return rootActionOutput{ExitCode: c.exitCode}, c.deleteErr
}

func parseHardeningResult(t *testing.T, resp *pluginapi.Response, target any) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("调用失败: %+v", resp.Error)
	}
	if err := json.Unmarshal(resp.Result, target); err != nil {
		t.Fatalf("解析结果失败: %v, raw=%s", err, string(resp.Result))
	}
}

// TestApplyReusesSuggestRenderAndWritesDropIn 证明 apply 只经 file_write 通道写、文本与 suggest 同源。
func TestApplyReusesSuggestRenderAndWritesDropIn(t *testing.T) {
	stubCurrentConfig(t, "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n", nil)
	ch := &hardeningChan{}
	oldWrite := guardFileWrite
	guardFileWrite = ch.write
	t.Cleanup(func() { guardFileWrite = oldWrite })
	params := json.RawMessage(`{"disable_password_auth":true,"max_auth_tries":3}`)
	resp := invoke(t, "ssh-guard.apply-hardening", "r-apply", params)
	var got hardeningApplyResult
	parseHardeningResult(t, resp, &got)
	if !got.Applied || got.File != dropInDir()+dropInFileName || got.Action != rootActionSSHDWrite {
		t.Fatalf("结果形状不符: %+v", got)
	}
	if len(ch.writeCalls) != 1 {
		t.Fatalf("dispatch 受控写调用次数=%d，期望 1", len(ch.writeCalls))
	}
	call := ch.writeCalls[0]
	if call.action != rootActionSSHDWrite || call.name != dropInFileName {
		t.Fatalf("写请求形状=%+v", call)
	}
	sug := invokeSuggest(t, `{"disable_password_auth":true,"max_auth_tries":3}`)
	if call.content != sug.ConfigText {
		t.Fatalf("apply 正文与 suggest.config_text 不同源：\napply=%q\nsuggest=%q", call.content, sug.ConfigText)
	}
	if !strings.Contains(call.content, "PasswordAuthentication no") || !strings.Contains(call.content, "MaxAuthTries 3") {
		t.Fatalf("渲染内容缺关键指令：%q", call.content)
	}
	if !strings.Contains(got.ReloadHint, "不重载") || !strings.Contains(got.SessionHint, "密钥") {
		t.Fatalf("结果缺不重载/密钥会话提示：%+v", got)
	}
	if pluginapi.DefaultFileWriteOptions().SSHD.MaxDirectives <= 0 {
		t.Fatal("pluginapi v0.4.0 应导出 SSHD 策略")
	}
}

// TestApplyFailClosed 空建议 / 越界参数 / 通道不可用 / 非零退出码都必须拒绝且不写。
func TestApplyFailClosed(t *testing.T) {
	stubCurrentConfig(t, "", os.ErrNotExist)
	cases := []struct {
		name   string
		params string
		call   fileWriteFunc
	}{
		{"空建议", `{}`, func(string, string, string) (rootActionOutput, error) {
			t.Fatal("不应调用通道")
			return rootActionOutput{}, nil
		}},
		{"端口越界", `{"port":70000}`, func(string, string, string) (rootActionOutput, error) {
			t.Fatal("不应调用通道")
			return rootActionOutput{}, nil
		}},
		{"通道未注入", `{"disable_password_auth":true}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := &pluginapi.Response{Type: pluginapi.TypeResponse}
			perr := handleApplyHardening(json.RawMessage(c.params), c.call, resp)
			if perr == nil {
				t.Fatal("期望拒绝，实际成功")
			}
			if resp.Result != nil {
				t.Fatal("拒绝时不应有结果体")
			}
		})
	}
	ch := &hardeningChan{exitCode: 3}
	resp := &pluginapi.Response{Type: pluginapi.TypeResponse}
	if perr := handleApplyHardening(json.RawMessage(`{"disable_password_auth":true}`), ch.write, resp); perr == nil || perr.Code != pluginapi.E_UPSTREAM {
		t.Fatalf("非零退出码应 E_UPSTREAM，得到 %+v", perr)
	}
}

// TestRollbackReadsLedgerAndCallsControlledDelete 回滚必须按账本核对 purge_op 再经 file_delete 撤销。
func TestRollbackReadsLedgerAndCallsControlledDelete(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, changesFileName)
	entry := changeEntryView{
		Plugin: "ssh-guard", Action: rootActionSSHDWrite, Target: dropInDir(), Reversible: true,
		PurgeOp: &purgeOpView{Kind: purgeKindFileRemove, Args: []string{dropInDir() + dropInFileName}},
	}
	b, _ := json.Marshal(entry)
	if err := os.WriteFile(ledger, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KORE_STATE_DIR", dir)
	ch := &hardeningChan{}
	resp := &pluginapi.Response{Type: pluginapi.TypeResponse}
	if perr := handleRollbackHardening(ch.del, resp); perr != nil {
		t.Fatalf("回滚失败: %+v", perr)
	}
	var got hardeningRollbackResult
	parseHardeningResult(t, resp, &got)
	if !got.RolledBack || got.LedgerPurgeOp != purgeKindFileRemove || !strings.Contains(got.Hint, "重载") {
		t.Fatalf("回滚结果不符: %+v", got)
	}
	if len(ch.deleteCalls) != 1 || ch.deleteCalls[0].action != rootActionSSHDDelete || ch.deleteCalls[0].name != dropInFileName {
		t.Fatalf("受控删除调用形状=%+v", ch.deleteCalls)
	}
}

// TestRollbackFailClosed 无账本 / 无条目 / 越界 purge_op / 无通道 均不得删除文件。
func TestRollbackFailClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KORE_STATE_DIR", dir)
	ch := &hardeningChan{}
	check := func(wantCode string) {
		t.Helper()
		resp := &pluginapi.Response{Type: pluginapi.TypeResponse}
		perr := handleRollbackHardening(ch.del, resp)
		if perr == nil || perr.Code != wantCode {
			t.Fatalf("期望 %s，得到 %+v", wantCode, perr)
		}
		if len(ch.deleteCalls) != 0 {
			t.Fatalf("拒绝时不得调用删除通道：%+v", ch.deleteCalls)
		}
	}
	check(pluginapi.E_INTERNAL) // 账本文件不存在
	ledger := filepath.Join(dir, changesFileName)
	if err := os.WriteFile(ledger, []byte("{bad json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(pluginapi.E_NOTFOUND) // 没有本插件条目
	entry := changeEntryView{Plugin: "ssh-guard", Action: rootActionSSHDWrite, Reversible: true,
		PurgeOp: &purgeOpView{Kind: purgeKindFileRemove, Args: []string{"/etc/passwd"}}}
	b, _ := json.Marshal(entry)
	if err := os.WriteFile(ledger, append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	check(pluginapi.E_INVALID) // purge 目标越界
	if err := os.WriteFile(ledger, []byte(`{"plugin":"ssh-guard","action":"sshd-dropin-write","reversible":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check(pluginapi.E_INTERNAL) // 缺 purge_op
}

// TestLedgerPurgeOpValidation 逐条锁定账本回滚的形状判据（第二道门）。
func TestLedgerPurgeOpValidation(t *testing.T) {
	good := []*purgeOpView{
		{Kind: purgeKindFileRemove, Args: []string{dropInDir() + dropInFileName}},
		{Kind: purgeKindFileRestore, Args: []string{"/var/lib/kore/backups/x.conf", dropInDir() + dropInFileName}},
	}
	for _, op := range good {
		if err := validateLedgerPurgeOp(op); err != nil {
			t.Fatalf("合法 purge_op 被拒：%+v: %v", op, err)
		}
	}
	bad := []*purgeOpView{
		nil,
		{Kind: "shell.exec", Args: []string{"rm -rf /"}},
		{Kind: purgeKindFileRemove, Args: []string{"/etc/passwd"}},
		{Kind: purgeKindFileRemove, Args: []string{dropInDir() + "a", dropInDir() + "b"}},
		{Kind: purgeKindFileRestore, Args: []string{"/etc/shadow", "/etc/ssh/sshd_config"}},
	}
	for _, op := range bad {
		if err := validateLedgerPurgeOp(op); err == nil {
			t.Fatalf("非法 purge_op 被放行：%+v", op)
		}
	}
}
