package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// maxLogTailBytes 是日志尾部限读上限：1 MB（约束：日志只读、尾部限读）。
const maxLogTailBytes = 1 << 20

// maxLogReadSeconds 是单次日志源读取（journalctl 子进程）的超时。
const maxLogReadSeconds = 10 * time.Second

// readFileTail 读取文件最后 maxBytes 字节并按行切分；不足 maxBytes 时全量读取。
// 从中间开始时丢弃首个不完整半行；truncated 标记是否发生限读。
func readFileTail(path string, maxBytes int64) (lines []string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	var reader io.Reader = f
	if info.Size() > maxBytes {
		if _, err := f.Seek(info.Size()-maxBytes, io.SeekStart); err != nil {
			return nil, false, err
		}
		br := bufio.NewReader(f)
		// 丢弃被截断的半行。
		if _, err := br.ReadString('\n'); err != nil && err != io.EOF {
			return nil, false, err
		}
		reader = br
		truncated = true
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, truncated, err
	}
	return splitLogLines(data), truncated, nil
}

// splitLogLines 把字节流切成非空行（容忍 \r\n）。
func splitLogLines(data []byte) []string {
	raw := strings.Split(string(data), "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// collectLogLines 按配置的日志源读取 SSH 日志行。
// 返回 source ∈ {"auth","journal","none"}；**源不可用不报错**——返回空行集与
// 说明性 note（降级口径：无 fail2ban 用日志兜底，无日志返回空统计）。
func collectLogLines(g guardConfig, since time.Time) (lines []string, source string, truncated bool, note string) {
	authErr := func() error {
		var err error
		lines, truncated, err = readFileTail(g.LogPath, maxLogTailBytes)
		return err
	}
	switch g.LogSource {
	case "auth":
		if err := authErr(); err != nil {
			return nil, "none", false, "日志源 " + g.LogPath + " 不可读（" + err.Error() + "），返回空统计"
		}
		return lines, "auth", truncated, ""
	case "journal":
		lines, truncated, err := readJournalSince(since, maxLogTailBytes)
		if err != nil {
			return nil, "none", false, "journalctl 不可用（" + err.Error() + "），返回空统计"
		}
		return lines, "journal", truncated, ""
	default: // auto：auth.log 可读则用 auth，否则尝试 journalctl
		if err := authErr(); err != nil {
			lines, truncated, err = readJournalSince(since, maxLogTailBytes)
			if err != nil {
				return nil, "none", false, "auth.log 与 journalctl 均不可用（auth: " + readable(authReason(g)) + "），返回空统计"
			}
			return lines, "journal", truncated, "auth.log 不可读，已降级到 journalctl"
		}
		return lines, "auth", truncated, ""
	}
}

// readable 把错误转成简短可读文本。
func readable(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// authReason 重新探测 auth.log 不可读的原因（仅供 auto 降级时拼 note；非热路径）。
func authReason(g guardConfig) error {
	f, err := os.Open(g.LogPath)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}

// readJournalSince 读取 journal 的 ssh 单元日志（short-iso 格式，便于时间戳解析）。
// 依次尝试 "ssh" 与 "sshd" 单元名（Debian/Ubuntu vs RHEL 系），输出超限时截断。
func readJournalSince(since time.Time, maxBytes int64) (lines []string, truncated bool, err error) {
	var lastErr error
	for _, unit := range []string{"ssh", "sshd"} {
		lines, truncated, err = readJournalUnit(unit, since, maxBytes)
		if err == nil {
			return lines, truncated, nil
		}
		lastErr = err
	}
	return nil, false, lastErr
}

// readJournalUnit 读取单个 systemd 单元的 SSH 日志；输出经 LimitReader 限流。
func readJournalUnit(unit string, since time.Time, maxBytes int64) (lines []string, truncated bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), maxLogReadSeconds)
	defer cancel()
	args := []string{"-u", unit, "-o", "short-iso", "--no-pager"}
	if !since.IsZero() {
		args = append(args, "--since", since.Local().Format("2006-01-02 15:04:05"))
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, false, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, false, fmt.Errorf("journalctl 启动失败: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
	if readErr == nil && int64(len(data)) > maxBytes {
		truncated = true
		data = trimFirstPartialLine(data)
	}
	// 读完剩余输出让子进程正常退出（若已超限则提前截断，Wait 会因超时/管道关闭返回）。
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, truncated, fmt.Errorf("journalctl 读取失败: %w", readErr)
	}
	if len(data) == 0 && waitErr != nil {
		return nil, truncated, fmt.Errorf("journalctl 失败: %v: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return splitLogLines(data), truncated, nil
}

// trimFirstPartialLine 截断后丢弃首个可能不完整的半行。
func trimFirstPartialLine(data []byte) []byte {
	if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
		return data[idx+1:]
	}
	return data
}
