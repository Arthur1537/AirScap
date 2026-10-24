package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenPrinting/go-mfp/abstract"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/vens"
)

func scanConfig() vens.ScanConfig {
	return SettingsToScanConfig(config.DefaultSettings())
}

func TestScanWithoutGrantSendsNoScanCommand(t *testing.T) {
	for name, authorizer := range map[string]authz.Authorizer{
		"no authorizer configured": nil,
		"deny":                     authz.Deny{},
		"refused by control":       &RecordingAuthorizer{Refuse: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, sim := newSimulated(authorizer, 3)

			pages, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil)
			if !errors.Is(err, authz.ErrNotAuthorized) {
				t.Fatalf("err = %v, want ErrNotAuthorized", err)
			}
			if len(pages) != 0 || sim.Opened != 0 {
				t.Errorf("scan started without grant: pages=%d opened=%d", len(pages), sim.Opened)
			}
			if _, err := s.StartScan(context.Background(), authz.SourceESCL, scanConfig()); !errors.Is(err, authz.ErrNotAuthorized) {
				t.Errorf("StartScan err = %v", err)
			}
			if sim.Opened != 0 {
				t.Errorf("StartScan opened a scan session")
			}
		})
	}
}

func TestDenyOverRealDataChannelMakesNoConnection(t *testing.T) {
	// No simulation: the real data channel would connect to this port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	s := New("127.0.0.1", port, port, "")
	s.connected = true

	if _, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d connection(s) to the scanner without grant", n)
	}
}

func TestOfflineScannerAsksForNoReservation(t *testing.T) {
	a := &RecordingAuthorizer{}
	s, sim := newSimulated(a, 1)
	s.connected = false

	if _, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil); err == nil {
		t.Fatal("offline scan succeeded")
	}
	if len(a.Sources) != 0 || sim.Opened != 0 {
		t.Errorf("reservation or scan while offline: sources=%v opened=%d", a.Sources, sim.Opened)
	}
}

func TestAuthorizedScanReportsActivityAndSuccess(t *testing.T) {
	a := &RecordingAuthorizer{}
	s, sim := newSimulated(a, 3)

	pages, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != 3 || sim.Opened != 1 || sim.Closed != 1 {
		t.Fatalf("pages=%d opened=%d closed=%d", len(pages), sim.Opened, sim.Closed)
	}
	if len(a.Sources) != 1 || a.Sources[0] != authz.SourceButton {
		t.Errorf("sources = %v", a.Sources)
	}
	// Before every page and before the final end-of-document read.
	if a.Activities != 4 {
		t.Errorf("activities = %d, want 4", a.Activities)
	}
	if len(a.Finishes) != 1 || !a.Finishes[0] {
		t.Errorf("finishes = %v, want [true]", a.Finishes)
	}
}

func TestLostAuthorizationStopsScanAndFails(t *testing.T) {
	a := &RecordingAuthorizer{LoseAt: 2} // session expires before page 2
	s, sim := newSimulated(a, 5)

	pages, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil)
	if !errors.Is(err, authz.ErrAuthorizationLost) || !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v, want ErrAuthorizationLost", err)
	}
	if sim.Served != 1 {
		t.Errorf("served %d pages, want 1: scanning continued without grant", sim.Served)
	}
	if sim.Closed != 1 {
		t.Errorf("scan not ended (EndScan): closed=%d", sim.Closed)
	}
	if len(a.Finishes) != 1 || a.Finishes[0] {
		t.Errorf("finishes = %v, want [false]", a.Finishes)
	}
	if len(pages) != 1 {
		t.Errorf("pages = %d", len(pages))
	}
}

func TestLostAuthorizationEndsScanImmediately(t *testing.T) {
	// eSCL clients hold the session; the scan must end when the grant is
	// lost, not when the client eventually closes it.
	a := &RecordingAuthorizer{LoseAt: 2}
	s, sim := newSimulated(a, 5)
	session, err := s.StartScan(context.Background(), authz.SourceESCL, scanConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NextPage(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.NextPage(); !errors.Is(err, authz.ErrAuthorizationLost) {
		t.Fatalf("err = %v", err)
	}
	if sim.Closed != 1 || len(a.Finishes) != 1 || a.Finishes[0] {
		t.Errorf("after loss: closed=%d finishes=%v", sim.Closed, a.Finishes)
	}
	if _, err := session.NextPage(); err == nil || sim.Served != 1 {
		t.Errorf("page after loss: err=%v served=%d", err, sim.Served)
	}
}

func TestESCLSessionOutlivesScanJobsRequest(t *testing.T) {
	// go-mfp calls Scan with the context of the POST ScanJobs request and
	// fetches the pages with later NextDocument requests, after that
	// context has ended.
	a := &RecordingAuthorizer{}
	s, sim := newSimulated(a, 2)
	adapter := NewESCLAdapter(s, 8080, nil, nil)
	ctx, endRequest := context.WithCancel(context.Background())
	doc, err := adapter.Scan(ctx, abstract.ScannerRequest{
		Input: abstract.InputADF, ADFMode: abstract.ADFModeSimplex,
		ColorMode: abstract.ColorModeColor, DocumentFormat: "image/jpeg",
	})
	endRequest()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := doc.Next(); err != nil {
			t.Fatalf("page %d: %v", i+1, err)
		}
	}
	if _, err := doc.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("end: %v", err)
	}
	doc.Close()
	if sim.Served != 2 || len(a.Finishes) != 1 || !a.Finishes[0] {
		t.Errorf("served=%d finishes=%v", sim.Served, a.Finishes)
	}
}

func TestScannerErrorAndOpenErrorFinishUnsuccessfully(t *testing.T) {
	a := &RecordingAuthorizer{}
	s, sim := newSimulated(a, 3)
	sim.FailAt = 2
	if _, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil); err == nil {
		t.Fatal("expected scanner error")
	}

	sim2 := &SimulatedScanner{OpenErr: errors.New("prepare failed")}
	s.openSession = sim2.open
	if _, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil); err == nil {
		t.Fatal("expected open error")
	}
	if len(a.Finishes) != 2 || a.Finishes[0] || a.Finishes[1] {
		t.Errorf("finishes = %v, want [false false]", a.Finishes)
	}
}

func TestSessionCloseIsIdempotentAndFinishesOnce(t *testing.T) {
	a := &RecordingAuthorizer{}
	s, sim := newSimulated(a, 2)
	session, err := s.StartScan(context.Background(), authz.SourceESCL, scanConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.NextPage(); err != nil {
		t.Fatal(err)
	}
	// Client stops early (SelectSinglePage): not a complete document.
	session.Close()
	session.Close()
	if _, err := session.NextPage(); err == nil {
		t.Error("page after close")
	}
	if sim.Closed != 1 || a.FinishCalls() != 1 || len(a.Finishes) != 1 || a.Finishes[0] {
		t.Errorf("closed=%d finishCalls=%d finishes=%v", sim.Closed, a.FinishCalls(), a.Finishes)
	}
}

func TestButtonJobSavesNothingWithoutOrAfterLosingGrant(t *testing.T) {
	for name, a := range map[string]*RecordingAuthorizer{
		"refused":   {Refuse: true},
		"lost":      {LoseAt: 2},
		"lost late": {LoseAt: 3},
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := newSimulated(a, 4)
			dir := t.TempDir()

			pages, err := RunSaveJob(s, scanConfig(), "image/jpeg", dir, nil)
			if !errors.Is(err, authz.ErrNotAuthorized) {
				t.Fatalf("err = %v", err)
			}
			entries, _ := os.ReadDir(dir)
			if pages != 0 || len(entries) != 0 {
				t.Errorf("saved %d pages, files %v", pages, entries)
			}
		})
	}
}

func TestButtonJobWithGrantSaves(t *testing.T) {
	a := &RecordingAuthorizer{}
	s, _ := newSimulated(a, 2)
	dir := t.TempDir()

	pages, err := RunSaveJob(s, scanConfig(), "image/jpeg", dir, nil)
	if err != nil || pages != 2 {
		t.Fatalf("pages=%d err=%v", pages, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 2 {
		t.Errorf("files = %v", files)
	}
	if len(a.Sources) != 1 || a.Sources[0] != authz.SourceButton {
		t.Errorf("sources = %v", a.Sources)
	}
}

func TestESCLScanNeedsGrant(t *testing.T) {
	a := &RecordingAuthorizer{Refuse: true}
	s, sim := newSimulated(a, 1)
	adapter := NewESCLAdapter(s, 8080, nil, nil)
	req := abstract.ScannerRequest{
		Input: abstract.InputADF, ADFMode: abstract.ADFModeSimplex,
		ColorMode: abstract.ColorModeColor, DocumentFormat: "image/jpeg",
	}

	if _, err := adapter.Scan(context.Background(), req); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v", err)
	}
	if sim.Opened != 0 || len(a.Sources) != 1 || a.Sources[0] != authz.SourceESCL {
		t.Errorf("opened=%d sources=%v", sim.Opened, a.Sources)
	}

	// An incompatible format is rejected before any reservation or scan.
	req.DocumentFormat = "image/tiff"
	if _, err := adapter.Scan(context.Background(), req); err == nil || errors.Is(err, authz.ErrNotAuthorized) {
		t.Fatalf("err = %v, want format error", err)
	}
	if len(a.Sources) != 1 || sim.Opened != 0 {
		t.Errorf("format error after reservation: sources=%v opened=%d", a.Sources, sim.Opened)
	}
}
