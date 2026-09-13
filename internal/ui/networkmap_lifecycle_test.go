package ui

import (
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/heymaikol/network-doctor/internal/diagnostic"
)

func lanLifecycleModel(t *testing.T) model {
	t.Helper()
	m := newModel(mustTarget(t, "example.com:443"), false)
	doneResults(&m, "")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("192.168.12.34")
	m.results[diagnostic.ProbeInternet] = r
	m.width, m.height = 100, 40
	m.networkCIDR = "192.168.12.0/24"
	return m
}

func lanSnapshot(at time.Time, status JobStatus, host string) jobState {
	j := jobState{name: lanDiscoveryName, status: status, start: at, dur: 2 * time.Second}
	if host != "" {
		j.lines = []string{"Host: " + host + " ()\tStatus: Up"}
	}
	return j
}

func TestNetworkMapCacheAndRescanLifecycle(t *testing.T) {
	oldLookPath := toolLookPath
	toolLookPath = func(string) (string, error) { return "nmap", nil }
	t.Cleanup(func() { toolLookPath = oldLookPath })

	m := lanLifecycleModel(t)
	u, cmd := m.Update(keyMsg("v"))
	first := asModel(t, u)
	if first.confirmTool == nil || first.confirmTool.Name != lanDiscoveryName || cmd != nil || first.hasJob() {
		t.Fatal("first v must confirm discovery without launching it")
	}
	if slices.Contains(menuNames(m), "Rescan network") {
		t.Error("Rescan must not appear before a LAN scan exists")
	}

	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.FixedZone("CDT", -5*60*60))
	m.cur = lanSnapshot(at, JobDone, "192.168.12.1")
	u, cmd = m.Update(keyMsg("v"))
	cached := asModel(t, u)
	if cmd != nil || !cached.networkMap || cached.confirmTool != nil || cached.cur.start != at || len(cached.otherJobs) != 0 {
		t.Fatalf("cached v changed or relaunched the scan: cur=%+v parked=%d", cached.cur, len(cached.otherJobs))
	}

	if key, ok := menuKey(cached, "Rescan network"); !ok || key != "" {
		t.Fatalf("Rescan network must be a menu-only row, key=%q found=%v", key, ok)
	}
	for _, preset := range presets {
		if keys := preset.preset[ctxList][actRescanNetwork]; len(keys) != 0 {
			t.Errorf("%s gives menu-only Rescan a global binding: %v", preset.name, keys)
		}
	}

	cached.watch = true
	r := cached.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("10.0.0.8")
	cached.results[diagnostic.ProbeInternet] = r
	confirm := sendKey(t, selectMenu(t, cached, "Rescan network"), "enter")
	if confirm.confirmTool == nil || confirm.confirmTool.Name != lanDiscoveryName || !confirm.networkMap {
		t.Fatal("Rescan must use the LAN confirmation without hiding the cached map")
	}
	canceled := sendKey(t, confirm, "esc")
	if canceled.confirmTool != nil || !canceled.networkMap || canceled.cur.start != at || canceled.networkCIDR != "192.168.12.0/24" || len(canceled.otherJobs) != 0 {
		t.Fatal("canceling Rescan must leave the cached scan intact")
	}

	confirm = sendKey(t, selectMenu(t, canceled, "Rescan network"), "enter")
	confirm.confirmTool.Bin = os.Args[0]
	confirm.confirmTool.Timeout = 5 * time.Second
	confirm.confirmTool.Build = func(*diagnostic.Target, net.IP) ([]string, []string, string) {
		return []string{"-test.run=TestHelperProcess"},
			append(os.Environ(), "GO_HELPER=1", "GO_HELPER_MODE=sleep"), "test LAN scan"
	}
	u, cmd = confirm.Update(keyMsg("y"))
	fresh := asModel(t, u)
	if cmd == nil || fresh.cur.active == nil || fresh.cur.name != lanDiscoveryName || !fresh.networkMap || fresh.networkCIDR != "10.0.0.0/24" {
		t.Fatal("confirming Rescan must start a fresh LAN job")
	}
	if len(fresh.otherJobs) != 1 || fresh.otherJobs[0].start != at || len(fresh.otherJobs[0].lines) != 1 {
		t.Fatalf("fresh discovery lost the previous evidence: %+v", fresh.otherJobs)
	}
	fresh.cur.active.cancel()
	_, done := drain(t, fresh.cur.active.ch)
	u, _ = fresh.Update(done)
	fresh = asModel(t, u)
	u, _ = fresh.Update(tea.KeyMsg{Type: tea.KeyTab})
	previous := asModel(t, u)
	if previous.cur.start != at || !slices.Equal(discoveredIPs(previous.cur.lines), []string{"192.168.12.1"}) {
		t.Fatalf("tab cannot reach the previous scan evidence: %+v", previous.cur)
	}
}

func TestNetworkMapAlwaysSelectsNewestScan(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.cur = jobState{name: "ping", status: JobDone, start: base.Add(10 * time.Second)}
	m.otherJobs = []jobState{
		lanSnapshot(base, JobDone, "192.168.12.1"),
		lanSnapshot(base.Add(2*time.Second), JobFailed, "192.168.12.2"),
	}

	for i := 3; i <= 6; i++ {
		m.networkMap = false
		u, cmd := m.Update(keyMsg("v"))
		m = asModel(t, u)
		if cmd != nil || !m.networkMap || !slices.Equal(discoveredIPs(m.cur.lines), []string{fmt.Sprintf("192.168.12.%d", i-1)}) {
			t.Fatalf("v did not select rescan %d as newest: start=%s lines=%v", i-2, m.cur.start, m.cur.lines)
		}
		m.networkMap = false
		m.otherJobs = append(m.otherJobs, lanSnapshot(base.Add(time.Duration(i)*time.Second), JobDone, fmt.Sprintf("192.168.12.%d", i)))
	}
}

func TestNetworkMapShowsCaptureTimeAndTerminalOutcome(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.FixedZone("CDT", -5*60*60))
	for _, status := range []JobStatus{JobDone, JobFailed, JobCanceled, JobTimedOut} {
		t.Run(status.String(), func(t *testing.T) {
			m := lanLifecycleModel(t)
			m.networkMap = true
			m.cur = lanSnapshot(at, status, "192.168.12.50")
			view := ansi.Strip(m.networkMapView())
			if !strings.Contains(view, "Captured: 2026-09-13 12:34:58 CDT") || !strings.Contains(view, "Status: "+status.String()) {
				t.Fatalf("map omits deterministic capture metadata:\n%s", view)
			}
			partial := strings.Contains(view, "partial results")
			if partial != (status != JobDone) {
				t.Errorf("%s partial label=%v:\n%s", status, partial, view)
			}
			if status == JobDone && slices.Contains(menuNames(m), "Rescan network") == false {
				t.Error("a completed scan must offer Rescan")
			}
		})
	}

	for _, status := range []JobStatus{JobFailed, JobCanceled, JobTimedOut} {
		m := lanLifecycleModel(t)
		m.cur = lanSnapshot(at, status, "")
		if !slices.Contains(menuNames(m), "Rescan network") {
			t.Errorf("%s LAN scan cannot be rescanned", status)
		}
	}
	running := lanLifecycleModel(t)
	running.cur = lanSnapshot(at, JobRunning, "")
	running.cur.active = &job{}
	if slices.Contains(menuNames(running), "Rescan network") {
		t.Error("a running LAN scan must not offer another Rescan")
	}
}

func TestNetworkMapSnapshotContextAndNarrowRendering(t *testing.T) {
	at := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	m := lanLifecycleModel(t)
	m.watch, m.networkMap = true, true
	m.cur = lanSnapshot(at, JobFailed, "192.168.12.50")
	r := m.results[diagnostic.ProbeInternet]
	r.Source = net.ParseIP("10.0.0.8")
	m.results[diagnostic.ProbeInternet] = r
	view := ansi.Strip(m.networkMapView())
	if !strings.Contains(view, "192.168.12.0/24") || !strings.Contains(view, "This device now 10.0.0.8") || !strings.Contains(view, "Captured:") {
		t.Fatalf("Watch Mode silently presents old discovery as current:\n%s", view)
	}
	for _, width := range []int{40, 30, 20, 10} {
		m.width = width
		assertFitsWidth(t, m.networkMapView(), width)
	}
}

func TestRescanRowKeepsActionsSelectionIdentity(t *testing.T) {
	m := selectMenu(t, menuModel(t), "Theme")
	if got := highlighted(t, m); got != "Theme" {
		t.Fatalf("menu opened on %q", got)
	}
	m.otherJobs = append(m.otherJobs, lanSnapshot(time.Now(), JobDone, "192.168.1.1"))
	if got := highlighted(t, m); got != "Theme" {
		t.Errorf("Rescan appearing moved the selection to %q", got)
	}
	m.otherJobs[len(m.otherJobs)-1].active = &job{}
	m.otherJobs[len(m.otherJobs)-1].status = JobRunning
	if got := highlighted(t, m); got != "Theme" {
		t.Errorf("Rescan disappearing moved the selection to %q", got)
	}
	if run := sendKey(t, m, "enter"); !run.theming {
		t.Error("enter no longer ran the visibly selected Theme action")
	}
}

func TestLANScanEvictionKeepsNewestMeasurementAndRestartDropsAll(t *testing.T) {
	base := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	m := lanLifecycleModel(t)
	for i := maxParkedJobs; i >= 0; i-- {
		m.otherJobs = append(m.otherJobs, lanSnapshot(base.Add(time.Duration(i)*time.Second), JobDone, "192.168.12.1"))
	}
	m.trimJobs()
	if len(m.otherJobs) != maxParkedJobs {
		t.Fatalf("ring has %d jobs, want %d", len(m.otherJobs), maxParkedJobs)
	}
	newest, _ := m.newestJob(lanDiscoveryName)
	if newest == nil || !newest.start.Equal(base.Add(maxParkedJobs*time.Second)) {
		t.Fatalf("eviction lost the newest LAN measurement: %+v", newest)
	}
	u, cmd := m.Update(keyMsg("v"))
	m = asModel(t, u)
	if cmd != nil || !m.networkMap || !m.cur.start.Equal(base.Add(maxParkedJobs*time.Second)) {
		t.Fatal("v fell back to an older LAN scan after ring eviction")
	}
	u, _ = m.retest()
	m = asModel(t, u)
	if m.hasJob() || len(m.otherJobs) != 0 || m.networkMap || m.networkCIDR != "" {
		t.Fatal("Retest/restart must discard cached LAN scan state")
	}
}
