package main

import (
	"encoding/json"
	"os"
	"testing"
)

// declaredRootAction / declaredManifest 是 info.json 里本仓关心的声明字段（显式定形，
// 不用 map[string]any：G-24）。
type declaredRootAction struct {
	ID           string   `json:"id"`
	Argv         []string `json:"argv"`
	TimeoutS     int      `json:"timeout_s"`
	Description  string   `json:"description"`
	Irreversible bool     `json:"irreversible"`
}

type declaredManifest struct {
	ID           string               `json:"id"`
	Version      string               `json:"version"`
	Protocol     string               `json:"protocol"`
	RequiresKore string               `json:"requires_kore"`
	RequiresRoot bool                 `json:"requires_root"`
	Capabilities []string             `json:"capabilities"`
	RootActions  []declaredRootAction `json:"root_actions"`
}

// loadDeclaredManifest 读取并解析仓根 info.json。
func loadDeclaredManifest(t *testing.T) declaredManifest {
	t.Helper()
	raw, err := os.ReadFile("info.json")
	if err != nil {
		t.Fatalf("读取 info.json: %v", err)
	}
	var m declaredManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析 info.json: %v", err)
	}
	return m
}

// TestFail2banPathsMatchInfoJSON 锁定「唯一路径口径」：每条 fail2ban 声明的 argv[0]
// 必须逐字等于代码里的 fail2banClientPath；声明集合必须与代码常量集合双向相等。
//
// 这条测试同时守护两件事：
//   - 代码不再按 PATH 执行 fail2ban-client（没有第二套口径）；
//   - info.json 不能偷偷加一条代码里没引用的 root action（0.2.0 的 fail2ban-status 债）。
func TestFail2banPathsMatchInfoJSON(t *testing.T) {
	m := loadDeclaredManifest(t)
	if !m.RequiresRoot {
		t.Fatal("声明了 root_actions 时必须 requires_root=true")
	}
	codeIDs := map[string]bool{
		rootActionFail2banStatus:  true,
		rootActionFail2banBanIP:   true,
		rootActionFail2banUnbanIP: true,
	}
	if len(m.RootActions) != len(codeIDs) {
		t.Fatalf("info.json 声明 %d 条 root_actions，代码引用的常量 %d 条（必须一一对应）",
			len(m.RootActions), len(codeIDs))
	}
	for _, action := range m.RootActions {
		if !codeIDs[action.ID] {
			t.Fatalf("声明 %q 在代码中没有对应常量/调用点（声明未使用）", action.ID)
		}
		if len(action.Argv) == 0 {
			t.Fatalf("%s 的 argv 为空", action.ID)
		}
		if action.Argv[0] != fail2banClientPath {
			t.Fatalf("%s 的 argv[0]=%q，与代码唯一路径口径 %q 不一致", action.ID, action.Argv[0], fail2banClientPath)
		}
		if action.TimeoutS < 1 || action.TimeoutS > 300 {
			t.Fatalf("%s 的 timeout_s=%d 超出协议区间 1–300", action.ID, action.TimeoutS)
		}
	}
	// 反向：代码里每个 root action id 常量都必须在 info.json 有声明。
	declared := make(map[string]bool, len(m.RootActions))
	for _, action := range m.RootActions {
		declared[action.ID] = true
	}
	for id := range codeIDs {
		if !declared[id] {
			t.Fatalf("代码常量 %q 未在 info.json 声明", id)
		}
	}
}

// TestIrreversibleSemantics 锁定 confirm 令牌需求集合（ADR-0018）：
//   - fail2ban-banip 不可逆（执行前需一次性 confirm 令牌，可能影响合法访问者）；
//   - fail2ban-unbanip 可逆（恢复性动作，可再次封禁回滚，不再强制 confirm）；
//   - fail2ban-status 只读。
//
// 内核侧语义：pluginapi.RootAction.Irreversible=true 时 privilege.Service.Execute 核销
// 一次性令牌（service.go:86），confirm-token 端点对非不可逆动作拒绝签发（handlers_rootaction.go:105）。
func TestIrreversibleSemantics(t *testing.T) {
	m := loadDeclaredManifest(t)
	want := map[string]bool{
		rootActionFail2banStatus:  false,
		rootActionFail2banBanIP:   true,
		rootActionFail2banUnbanIP: false,
	}
	for _, action := range m.RootActions {
		expected, ok := want[action.ID]
		if !ok {
			t.Fatalf("未预期的 root action %q", action.ID)
		}
		if action.Irreversible != expected {
			t.Fatalf("%s 的 irreversible=%v，期望 %v", action.ID, action.Irreversible, expected)
		}
	}
}

// TestManifestMatchesInfoJSON 防版本 bump 漂移：manifest.json（随二进制内嵌、参与握手）
// 与 info.json 的握手字段必须一致（make dist 也校验，但单测先拦住）。
func TestManifestMatchesInfoJSON(t *testing.T) {
	info := loadDeclaredManifest(t)
	raw, err := os.ReadFile("manifest.json")
	if err != nil {
		t.Fatalf("读取 manifest.json: %v", err)
	}
	var manifest declaredManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("解析 manifest.json: %v", err)
	}
	if manifest.ID != info.ID || manifest.Version != info.Version || manifest.Protocol != info.Protocol ||
		manifest.RequiresKore != info.RequiresKore {
		t.Fatalf("manifest 与 info.json 不一致：manifest=%+v info=%+v", manifest, info)
	}
	if len(manifest.Capabilities) != len(info.Capabilities) {
		t.Fatalf("capabilities 数量不一致：%v vs %v", manifest.Capabilities, info.Capabilities)
	}
	for index := range info.Capabilities {
		if manifest.Capabilities[index] != info.Capabilities[index] {
			t.Fatalf("capabilities[%d]=%q 与 info.json %q 不一致",
				index, manifest.Capabilities[index], info.Capabilities[index])
		}
	}
}
