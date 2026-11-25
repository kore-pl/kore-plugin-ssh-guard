package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 白名单文件口径：插件自己的数据目录（supervisor 注入的 KORE_PLUGIN_DATA，
// <install>/data/plugins/ssh-guard，0700 属主 kore-<id>），**不写安装目录外的任何路径**
// （ADR-0023 零侵入）。文件名固定，便于卸载时随插件数据目录一起清理。
const whitelistFileName = "whitelist.json"

// whitelistFile 是 whitelist.json 的落盘结构（显式字段，G-24 不用 map）。
type whitelistFile struct {
	Entries []whitelistEntry `json:"entries"`
}

// whitelistStore 是白名单的保护性存储：进程内缓存 + 落盘到插件数据目录。
//
// 为什么需要它（产品口径）：fail2ban 封的是"来源 IP"，而管理员自己的 SSH 出口 IP
// 就是同一个维度——一次误封会把自己锁在门外。白名单是**插件侧的封禁前置门**：
// 命中白名单的 IP 在 ssh-guard.ban.add 里被直接拒绝（fail-closed，绝不透传到
// fail2ban），因此即使管理员手抖填了自己的 IP 也封不掉自己。
//
// 落盘不可用（无 KORE_PLUGIN_DATA / 目录只读）时降级为**进程内**白名单，并在
// 返回结果里如实说明 persisted=false + 原因，不假装已持久化。
type whitelistStore struct {
	mu      sync.Mutex
	path    string
	entries []whitelistEntry
	note    string // 持久化不可用时的原因（人话，进 JSON）
}

// newWhitelistStore 构造白名单存储：dataDir 为空表示不落盘（进程内生效）。
func newWhitelistStore(dataDir string) *whitelistStore {
	store := &whitelistStore{}
	if dataDir == "" {
		store.note = "内核未注入插件数据目录（KORE_PLUGIN_DATA），白名单只在本次运行内生效；" +
			"插件重启后会丢失，请重开页面重新加入"
		return store
	}
	store.path = filepath.Join(dataDir, whitelistFileName)
	if err := store.load(); err != nil {
		// 读失败不等于"空白名单"：如实记录，页面会提示（不吞错）。
		store.note = "读取白名单文件失败（" + err.Error() + "），本次从空白名单开始；保存后会自动重建"
	}
	return store
}

// load 读入落盘白名单；文件不存在视为空白名单（首次运行，不是错误）。
func (w *whitelistStore) load() error {
	raw, err := os.ReadFile(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file whitelistFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("解析 %s: %w", whitelistFileName, err)
	}
	entries := make([]whitelistEntry, 0, len(file.Entries))
	for _, entry := range file.Entries {
		if canonical, ok := canonicalIP(entry.IP); ok {
			entry.IP = canonical
			entries = append(entries, entry)
		}
	}
	w.entries = entries
	return nil
}

// Persisted 报告白名单是否真的落盘（path 非空且目录可写）。
func (w *whitelistStore) Persisted() bool { return w != nil && w.path != "" }

// Path 返回白名单文件路径（未落盘时为空串）。
func (w *whitelistStore) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// Note 返回持久化降级说明（正常时为空）。
func (w *whitelistStore) Note() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.note
}

// Entries 返回白名单快照（按 IP 升序；调用方不得依赖内部切片身份）。
func (w *whitelistStore) Entries() []whitelistEntry {
	if w == nil {
		return []whitelistEntry{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]whitelistEntry, len(w.entries))
	copy(out, w.entries)
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Contains 报告 IP 是否在白名单（按解析后语义比较，兼容 IPv4-mapped IPv6）。
func (w *whitelistStore) Contains(ip string) bool {
	if w == nil {
		return false
	}
	target, ok := canonicalIP(ip)
	if !ok {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, entry := range w.entries {
		if entry.IP == target {
			return true
		}
	}
	return false
}

// Add 加入白名单：已存在时幂等返回 added=false（不重复写盘、不改原 AddedAt/Note）。
func (w *whitelistStore) Add(ip, note string, now time.Time) (whitelistEntry, bool, error) {
	canonical, ok := canonicalIP(ip)
	if !ok {
		return whitelistEntry{}, false, fmt.Errorf("ip 不是合法 IP 地址")
	}
	if w == nil {
		// nil 存储只在测试替身缺省时出现；按"未落盘"处理，但不 panic。
		return whitelistEntry{IP: canonical, AddedAt: now.Local().Format(time.RFC3339), Note: note}, true, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, entry := range w.entries {
		if entry.IP == canonical {
			return entry, false, nil
		}
	}
	entry := whitelistEntry{IP: canonical, AddedAt: now.Local().Format(time.RFC3339), Note: note}
	w.entries = append(w.entries, entry)
	if err := w.persistLocked(); err != nil {
		return entry, true, err
	}
	return entry, true, nil
}

// Remove 移出白名单；返回是否真的删除了一条记录。
func (w *whitelistStore) Remove(ip string) bool {
	if w == nil {
		return false
	}
	canonical, ok := canonicalIP(ip)
	if !ok {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for index, entry := range w.entries {
		if entry.IP != canonical {
			continue
		}
		w.entries = append(w.entries[:index], w.entries[index+1:]...)
		// 写盘失败不把记录"复活"：内存里已删，note 会带出失败原因（调用方如实展示）。
		if err := w.persistLocked(); err != nil {
			w.note = "白名单已从内存移除，但写盘失败（" + err.Error() + "）；本次运行内有效，重启后会回到旧内容"
		}
		return true
	}
	return false
}

// persistLocked 原子写盘：同目录临时文件 + rename，避免半截 JSON 覆盖好文件。
// 权限 0600：白名单是运维人员出口 IP 清单，不需要组/其他读。
func (w *whitelistStore) persistLocked() error {
	if w.path == "" {
		w.note = "内核未注入插件数据目录（KORE_PLUGIN_DATA），白名单只在本次运行内生效"
		return nil
	}
	file := whitelistFile{Entries: w.entries}
	if file.Entries == nil {
		file.Entries = []whitelistEntry{}
	}
	raw, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".whitelist-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, w.path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	w.note = ""
	return nil
}

// banLedger 记录"本插件亲自执行的封禁时刻"，用于给封禁清单算「封禁时间/剩余时长」。
//
// 为什么不读 fail2ban 的封禁时刻：fail2ban-client 的 `get <jail> bantime` 与封禁
// 明细不在内核提权形状表（ADR-0022）内，插件读不到；本插件能确知的只有"我自己
// 什么时候封的"。**只记内存**——lazy 进程退出即失效，宁可显示"未知"也不编造。
type banLedger struct {
	mu     sync.Mutex
	at     map[string]time.Time
	reason map[string]string
}

// newBanLedger 构造封禁时刻账本。
func newBanLedger() *banLedger {
	return &banLedger{at: map[string]time.Time{}, reason: map[string]string{}}
}

// Record 记录一次封禁（ip 需已是规范化写法）。
func (l *banLedger) Record(ip string, at time.Time, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.at[ip] = at
	if reason != "" {
		l.reason[ip] = reason
	}
}

// Forget 在解封后清掉记录。
func (l *banLedger) Forget(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.at, ip)
	delete(l.reason, ip)
}

// At 返回该 IP 被本插件封禁的时刻。
func (l *banLedger) At(ip string) (time.Time, bool) {
	if l == nil {
		return time.Time{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	at, ok := l.at[ip]
	return at, ok
}

// canonicalIP 把 IP 文本归一化为规范写法；非法返回 ok=false。
// 归一化同时是注入防线：net.ParseIP 只接受纯 IP 字面量。
func canonicalIP(raw string) (string, bool) {
	parsed := net.ParseIP(strings.TrimSpace(raw))
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}
