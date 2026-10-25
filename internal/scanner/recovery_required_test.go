package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
)

// A1: ScanSnap Control (contract 2) did not accept a scan reported as
// complete. Close reports ErrRecoveryRequired, so nothing is staged, and
// the log says why instead of "reservation release failed".
func TestRecoveryRequiredAfterCompleteScan(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	a := &RecordingAuthorizer{FinishErr: &authz.RecoveryRequiredError{Reason: "browser_authority_lost"}}
	sc, _ := newSimulated(a, 2)
	session, err := sc.StartScan(context.Background(), authz.SourceButton, vens.ScanConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := session.NextPage(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	err = session.Close()
	if !errors.Is(err, authz.ErrRecoveryRequired) {
		t.Fatalf("close: %v", err)
	}
	if len(a.Finishes) != 1 || !a.Finishes[0] {
		t.Fatalf("finishes %v: the complete scan must be reported as success", a.Finishes)
	}
	if !strings.Contains(logs.String(), "scan not accepted; reservation blocked for operator recovery") ||
		strings.Contains(logs.String(), "reservation release failed") {
		t.Fatalf("logs:\n%s", logs.String())
	}
}
