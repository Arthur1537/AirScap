package scanner

// A2: the real Scanner (discovery, pairing, heartbeat, data channel) against
// the VENS simulator on 127.0.0.2. No hardware, no network beyond loopback.
// The tests share the fixed client ports 55264/55265 and run sequentially.

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"image/jpeg"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/testlock"
	"github.com/mzyy94/airscap/internal/vens"
	"github.com/mzyy94/airscap/internal/vens/vensim"
)

const simIP = "127.0.0.2"

func simulated(t *testing.T, profile vensim.Profile) (*vensim.Simulator, *Scanner) {
	t.Helper()
	testlock.VENSPorts(t)
	sim, err := vensim.Start(context.Background(), vensim.Config{IP: simIP, Serial: "iX500-SIM0001"}, profile)
	if err != nil {
		t.Skipf("simulator needs 127.0.0.2 and the VENS ports: %v", err)
	}
	t.Cleanup(sim.Close)
	identity, _ := vens.ComputeIdentity(vens.PasswordFromSerial("iX500-SIM0001"))
	sc := New(simIP, vens.DefaultDataPort, vens.DefaultControlPort, identity)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sc.Connect(ctx); err != nil {
		t.Fatalf("connect to simulator: %v", err)
	}
	t.Cleanup(sc.Disconnect)
	if !sim.Paired() || !sc.Online() {
		t.Fatal("not paired")
	}
	return sim, sc
}

func dataRequests(sim *vensim.Simulator) string {
	var ops []string
	for _, r := range sim.Requests() {
		if op, ok := strings.CutPrefix(r, "data:"); ok {
			ops = append(ops, op)
		}
	}
	return strings.Join(ops, " ")
}

func captureSimLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

func stage(t *testing.T, sc *Scanner, a *RecordingAuthorizer, cfg vens.ScanConfig) (ScanManifest, string, error) {
	t.Helper()
	sc.SetAuthorizer(a)
	root := t.TempDir()
	os.Chmod(root, 0700)
	m, err := StageButtonScan(context.Background(), sc, cfg, root)
	return m, root, err
}

func TestSimulatorPairingNeedsTheRightIdentity(t *testing.T) {
	testlock.VENSPorts(t)
	sim, err := vensim.Start(context.Background(), vensim.Config{IP: simIP, Password: "1234"}, vensim.Profile{})
	if err != nil {
		t.Skipf("simulator unavailable: %v", err)
	}
	defer sim.Close()
	wrong, _ := vens.ComputeIdentity("9999")
	sc := New(simIP, vens.DefaultDataPort, vens.DefaultControlPort, wrong)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sc.Connect(ctx); err == nil || !strings.Contains(err.Error(), "pairing rejected") {
		t.Fatalf("got %v", err)
	}
	if sim.Paired() {
		t.Fatal("paired with a wrong identity")
	}
}

func TestSimulatedButtonScanStagesAllPages(t *testing.T) {
	for _, duplex := range []bool{false, true} {
		name := map[bool]string{false: "simplex", true: "duplex"}[duplex]
		t.Run(name, func(t *testing.T) {
			sim, sc := simulated(t, vensim.Profile{Sheets: 3, ChunkSize: 4096})
			cfg := scanConfig()
			cfg.Duplex = duplex
			a := &RecordingAuthorizer{}
			m, root, err := stage(t, sc, a, cfg)
			if err != nil {
				t.Fatal(err)
			}
			want := 3
			if duplex {
				want = 6
			}
			if m.Pages != want || len(a.Finishes) != 1 || !a.Finishes[0] {
				t.Fatalf("pages %d, finishes %v", m.Pages, a.Finishes)
			}
			z, err := zip.OpenReader(filepath.Join(root, m.ReservationID+".scan"))
			if err != nil {
				t.Fatal(err)
			}
			z.Close()
			// The scan used the documented sequence and ended with END SCAN.
			seq := dataRequests(sim)
			if !strings.Contains(seq, "D8 D4 D5 C2 E0 28") || !strings.HasSuffix(seq, "C2 E0 C2 03 D6") {
				t.Fatalf("sequence %s", seq)
			}
		})
	}
}

func TestSimulatedScannerStates(t *testing.T) {
	cases := []struct {
		name    string
		profile vensim.Profile
		pages   int    // pages handed out before the failure
		kind    string // expected error text
	}{
		{"no paper", vensim.Profile{Sheets: 0}, 0, "no paper in ADF"},
		{"cover open", vensim.Profile{Sheets: 2, CoverOpen: true}, 0, "ADF cover open"},
		{"jam on sheet 2", vensim.Profile{Sheets: 3, JamAtSheet: 2}, 2, "paper jam"},
		{"multi-feed on sheet 1", vensim.Profile{Sheets: 2, MultiFeedAt: 1}, 1, "multi-feed detected"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, sc := simulated(t, c.profile)
			a := &RecordingAuthorizer{}
			sc.SetAuthorizer(a)
			session, err := sc.StartScan(context.Background(), authz.SourceButton, scanConfig())
			pages := 0
			if err == nil {
				for {
					_, e := session.NextPage()
					if e == io.EOF {
						break
					}
					if e != nil {
						err = e
						break
					}
					pages++
				}
				session.Close()
			}
			if err == nil || !strings.Contains(err.Error(), c.kind) {
				t.Fatalf("got %v", err)
			}
			if pages > c.pages {
				t.Fatalf("%d pages handed out, at most %d expected", pages, c.pages)
			}
			// Every failure releases the reservation as a failure, never as success.
			for _, ok := range a.Finishes {
				if ok {
					t.Fatalf("finishes %v", a.Finishes)
				}
			}
		})
	}
}

// Review E: the four end-of-document behaviours. The current strict check
// accepts only H0 (with NO SENSE or scan-complete sense); the diagnostics
// name the field for every rejection.
func TestSimulatedEndOfDocumentProfiles(t *testing.T) {
	cases := []struct {
		terminal vensim.Terminal
		accepted bool
		field    string
	}{
		{vensim.TerminalClean, true, ""},
		{vensim.TerminalScanComplete, true, ""},
		{vensim.TerminalPending, false, "error field 0x00000003 (code 0x0003"},
		{vensim.TerminalUpperBits, false, "error field 0x00010000 (code 0x0000, upper 0x0001)"},
		{vensim.TerminalStateBits, false, "scan state 0x00000081"},
	}
	for _, c := range cases {
		t.Run(string(c.terminal), func(t *testing.T) {
			logs := captureSimLogs(t)
			_, sc := simulated(t, vensim.Profile{Sheets: 1, Terminal: c.terminal})
			a := &RecordingAuthorizer{}
			m, _, err := stage(t, sc, a, scanConfig())
			if c.accepted {
				if err != nil || m.Pages != 1 {
					t.Fatalf("pages %d, %v", m.Pages, err)
				}
				return
			}
			var terminal *vens.TerminalStatusError
			if !errors.As(err, &terminal) || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("got %v", err)
			}
			if len(a.Finishes) != 1 || a.Finishes[0] {
				t.Fatalf("a rejected end must finish as failure: %v", a.Finishes)
			}
			// The field observation of the hardware tests: 0x00000080 just before the wait.
			for _, want := range []string{"status=0x00000080", "phase=before_wait", "phase=terminal", "phase=after_sense"} {
				if !strings.Contains(logs.String(), want) {
					t.Fatalf("log lacks %q", want)
				}
			}
		})
	}
}

func TestSimulatedPagesAreTheScannersJPEGs(t *testing.T) {
	_, sc := simulated(t, vensim.Profile{Sheets: 1, ChunkSize: 1000, PageWidth: 400})
	a := &RecordingAuthorizer{}
	sc.SetAuthorizer(a)
	session, err := sc.StartScan(context.Background(), authz.SourceButton, scanConfig())
	if err != nil {
		t.Fatal(err)
	}
	page, err := session.NextPage()
	session.Close()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(page.JPEG))
	if err != nil || cfg.Width != 400 || len(page.JPEG) <= 1000 {
		t.Fatalf("page %d bytes, %v, %v (must span several chunks)", len(page.JPEG), cfg, err)
	}
}

func TestSimulatorOfflineAndBack(t *testing.T) {
	sim, sc := simulated(t, vensim.Profile{Sheets: 1})
	sim.GoOffline()
	sc.healthCheck()
	if sc.Online() {
		t.Fatal("scanner still online after the simulator went away")
	}
	if err := sim.GoOnline(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := sc.Connect(ctx); err != nil || !sc.Online() {
		t.Fatalf("reconnect: %v", err)
	}
}

func TestSimulatedButtonPressReachesTheListener(t *testing.T) {
	sim, _ := simulated(t, vensim.Profile{Sheets: 1})
	pressed := make(chan struct{}, 1)
	listener := NewButtonListener(simIP, func() { pressed <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listener.Start(ctx); err != nil {
		t.Skipf("notify port busy: %v", err)
	}
	defer listener.Stop()
	if err := sim.PressButton(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pressed:
	case <-time.After(5 * time.Second):
		t.Fatal("button event not received")
	}
}
