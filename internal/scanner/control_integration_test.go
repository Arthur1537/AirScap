//go:build integration

package scanner

// Cross-repository integration with a real ScanSnap Control internal API
// (app/scanner_internal.py). Only the data channel is simulated. Run with
//
//	AIRSCAP_IT_CONTROL_URL=http://127.0.0.1:PORT \
//	AIRSCAP_IT_CONTROL_TOKEN=<scanner token> \
//	AIRSCAP_IT_CONTROL_HELPER="python3 control_it.py" AIRSCAP_IT_CONTROL_DB=<db> \
//	go test -tags integration -run ControlIntegration ./internal/scanner/
//
// The helper manipulates the throwaway Control database (reset, expire,
// close, restart, dump); see docs/scan-authorization.md.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/authz"
)

type controlIT struct {
	t       *testing.T
	control *authz.Control
}

func newControlIT(t *testing.T) *controlIT {
	url := os.Getenv("AIRSCAP_IT_CONTROL_URL")
	if url == "" {
		t.Skip("AIRSCAP_IT_CONTROL_URL not set")
	}
	c, err := authz.NewControl(url, os.Getenv("AIRSCAP_IT_CONTROL_TOKEN"), nil)
	if err != nil {
		t.Fatal(err)
	}
	it := &controlIT{t: t, control: c}
	it.helper("reset")
	return it
}

func (it *controlIT) helper(action string) string {
	it.t.Helper()
	args := strings.Fields(os.Getenv("AIRSCAP_IT_CONTROL_HELPER"))
	args = append(args, action, os.Getenv("AIRSCAP_IT_CONTROL_DB"))
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		it.t.Fatalf("helper %s: %v\n%s", action, err, out)
	}
	return string(out)
}

type controlState struct {
	Reservations [][]string `json:"reservations"` // job_id, status, source
	Audit        []string   `json:"audit"`
}

func (it *controlIT) state() controlState {
	var s controlState
	if err := json.Unmarshal([]byte(it.helper("dump")), &s); err != nil {
		it.t.Fatal(err)
	}
	return s
}

func (it *controlIT) lastReservation() []string {
	s := it.state()
	if len(s.Reservations) == 0 {
		it.t.Fatal("no reservation recorded")
	}
	return s.Reservations[len(s.Reservations)-1]
}

func refusedWith(t *testing.T, err error, reason string) {
	t.Helper()
	if !errors.Is(err, authz.ErrNotAuthorized) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("err = %v, want refusal %q", err, reason)
	}
}

func TestControlIntegrationButtonScan(t *testing.T) {
	it := newControlIT(t)
	s, sim := newSimulated(it.control, 3)
	pages, err := s.Scan(context.Background(), authz.SourceButton, scanConfig(), nil)
	if err != nil || len(pages) != 3 {
		t.Fatalf("pages=%d err=%v", len(pages), err)
	}
	if r := it.lastReservation(); r[0] != "it-job" || r[1] != "finished" || r[2] != "button" {
		t.Errorf("reservation = %v", r)
	}
	st := it.state()
	if n := strings.Count(strings.Join(st.Audit, ","), "scanner_activity"); n != 4 {
		t.Errorf("activity events = %d (%v)", n, st.Audit)
	}
	if sim.Opened != 1 {
		t.Errorf("opened = %d", sim.Opened)
	}
}

func TestControlIntegrationRemoteSourcesRefusedByDefault(t *testing.T) {
	it := newControlIT(t)
	s, sim := newSimulated(it.control, 1)
	for _, source := range []authz.Source{authz.SourceESCL, authz.SourcePreview} {
		_, err := s.StartScan(context.Background(), source, scanConfig())
		refusedWith(t, err, "scan source not permitted")
	}
	if sim.Opened != 0 || len(it.state().Reservations) != 0 {
		t.Errorf("opened=%d reservations=%v", sim.Opened, it.state().Reservations)
	}
}

func TestControlIntegrationParallelScanRefused(t *testing.T) {
	it := newControlIT(t)
	first, _ := newSimulated(it.control, 2)
	second, sim2 := newSimulated(it.control, 2)

	session, err := first.StartScan(context.Background(), authz.SourceButton, scanConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, err = second.StartScan(context.Background(), authz.SourceButton, scanConfig())
	refusedWith(t, err, "scanner busy")
	if sim2.Opened != 0 {
		t.Error("second scan started while the scanner is reserved")
	}
	session.Close() // incomplete: released as failed
	if r := it.lastReservation(); r[1] != "failed" {
		t.Errorf("reservation = %v", r)
	}
	if _, err := second.Scan(context.Background(), authz.SourceButton, scanConfig(), nil); err != nil {
		t.Fatalf("scan after release: %v", err)
	}
}

func lostWith(t *testing.T, it *controlIT, action, reason, status string) {
	t.Helper()
	s, sim := newSimulated(it.control, 4)
	session, err := s.StartScan(context.Background(), authz.SourceButton, scanConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err := session.NextPage(); err != nil {
		t.Fatal(err)
	}
	it.helper(action)
	_, err = session.NextPage()
	if !errors.Is(err, authz.ErrAuthorizationLost) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("err = %v, want lost: %s", err, reason)
	}
	if sim.Served != 1 || sim.Closed != 1 {
		t.Errorf("served=%d closed=%d", sim.Served, sim.Closed)
	}
	if r := it.lastReservation(); r[1] != status {
		t.Errorf("reservation = %v, want %s", r, status)
	}
}

func TestControlIntegrationExpiredSessionStopsScan(t *testing.T) {
	lostWith(t, newControlIT(t), "expire", "session expired", "failed")
}

func TestControlIntegrationClosedSessionStopsScan(t *testing.T) {
	lostWith(t, newControlIT(t), "close", "session not active", "failed")
}

func TestControlIntegrationRestartStopsScanAndBlocks(t *testing.T) {
	it := newControlIT(t)
	lostWith(t, it, "restart", "invalid reservation", "recovery_required")
	s, sim := newSimulated(it.control, 1)
	_, err := s.StartScan(context.Background(), authz.SourceButton, scanConfig())
	refusedWith(t, err, "scanner busy")
	if sim.Opened != 0 {
		t.Error("scan after restart without recovery")
	}
}

func TestControlIntegrationNoSessionOrWrongToken(t *testing.T) {
	it := newControlIT(t)
	it.helper("close")
	s, sim := newSimulated(it.control, 1)
	_, err := s.StartScan(context.Background(), authz.SourceButton, scanConfig())
	refusedWith(t, err, "no active session")

	it.helper("reset")
	wrong, err := authz.NewControl(os.Getenv("AIRSCAP_IT_CONTROL_URL"), strings.Repeat("w", 40), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(wrong)
	_, err = s.StartScan(context.Background(), authz.SourceButton, scanConfig())
	refusedWith(t, err, "HTTP 401")
	if sim.Opened != 0 || len(it.state().Reservations) != 0 {
		t.Errorf("opened=%d reservations=%v", sim.Opened, it.state().Reservations)
	}
}

func TestControlIntegrationSessionOutlivesStartingRequest(t *testing.T) {
	// eSCL: the pages are fetched after the starting request has ended.
	it := newControlIT(t)
	s, sim := newSimulated(it.control, 2)
	ctx, endRequest := context.WithCancel(context.Background())
	session, err := s.StartScan(ctx, authz.SourceButton, scanConfig())
	endRequest()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := session.NextPage(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("after %d pages: %v", sim.Served, err)
		}
	}
	session.Close()
	if r := it.lastReservation(); r[1] != "finished" || sim.Served != 2 {
		t.Errorf("reservation=%v served=%d", r, sim.Served)
	}
}
