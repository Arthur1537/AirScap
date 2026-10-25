package vens

// A5: side effects of the terminal-status diagnostics. After a rejection
// the session sends REQUEST SENSE and GET_STATUS once more (diagnostics
// only), then the usual END SCAN. These tests pin that nothing else is
// sent, that the extra time is bounded and that a lost connection keeps
// the rejection.

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

type endRun struct {
	err     error
	close   error
	logs    string
	elapsed time.Duration
	seen    []byte
}

// runEnd drives the end of a document against f and, if closeAfter, the
// session close. wrap may add a handler (e.g. RedactingHandler).
func runEnd(t *testing.T, f *fakeScanner, closeAfter bool, wrap func(slog.Handler) slog.Handler) endRun {
	t.Helper()
	var logs bytes.Buffer
	var handler slog.Handler = slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})
	if wrap != nil {
		handler = wrap(handler)
	}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(previous)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); f.serve(t, server) }()
	s := &ScanSession{conn: client, physicalSheet: 1, sidesPerSheet: 2}
	start := time.Now()
	_, err := s.NextPage()
	run := endRun{err: err, elapsed: time.Since(start)}
	if closeAfter {
		run.close = s.Close()
	} else {
		client.Close()
	}
	<-done
	run.logs, run.seen = logs.String(), f.seen
	return run
}

func clean() fakeScanner {
	return fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0}, sense: senseReply(SenseKeyNoSense, 0, 0)}
}

func TestDiagnosticsSendOnlyKnownRequests(t *testing.T) {
	accepted := clean()
	run := runEnd(t, &accepted, true, nil)
	if run.err != io.EOF || run.close != nil {
		t.Fatalf("clean end: %v, close %v", run.err, run.close)
	}
	if !bytes.Equal(run.seen, []byte{opGetStatus, opWaitForScan, opGetStatus, opRequestSense, opEndScan}) {
		t.Fatalf("clean sequence %X", run.seen)
	}
	rejected := clean()
	rejected.terminal = [2]uint32{0x80, 0x00010000}
	run = runEnd(t, &rejected, true, nil)
	var terminal *TerminalStatusError
	if !errors.As(run.err, &terminal) || run.close != nil {
		t.Fatalf("rejected end: %v, close %v", run.err, run.close)
	}
	// Exactly one REQUEST SENSE and one GET_STATUS more, then END SCAN.
	if !bytes.Equal(run.seen, []byte{opGetStatus, opWaitForScan, opGetStatus, opRequestSense, opGetStatus, opEndScan}) {
		t.Fatalf("rejected sequence %X", run.seen)
	}
}

func TestDiagnosticsBoundedWhenScannerStopsAnswering(t *testing.T) {
	previous := endConfirmationTimeout
	endConfirmationTimeout = 200 * time.Millisecond
	defer func() { endConfirmationTimeout = previous }()
	f := clean()
	f.terminal = [2]uint32{0x81, 0}
	f.hangAfterTerminal = time.Second
	run := runEnd(t, &f, false, nil)
	var terminal *TerminalStatusError
	if !errors.As(run.err, &terminal) {
		t.Fatalf("got %v", run.err)
	}
	// One unanswered diagnostic request: one timeout, no second request.
	if run.elapsed > 2*endConfirmationTimeout+500*time.Millisecond {
		t.Fatalf("diagnostics took %v", run.elapsed)
	}
	if !bytes.Equal(run.seen, []byte{opGetStatus, opWaitForScan, opGetStatus, opRequestSense}) {
		t.Fatalf("sequence %X", run.seen)
	}
}

func TestDiagnosticsKeepRejectionAfterConnectionLoss(t *testing.T) {
	f := clean()
	f.terminal = [2]uint32{0x80, 0x00000001}
	f.dropAfterTerminal = true
	run := runEnd(t, &f, true, nil)
	var terminal *TerminalStatusError
	if !errors.As(run.err, &terminal) || terminal.ErrorField != 1 {
		t.Fatalf("got %v", run.err)
	}
	if run.close == nil {
		t.Fatal("close on a lost connection must report the failure")
	}
	if !strings.Contains(run.logs, "terminal status rejected") || strings.Contains(run.logs, "phase=after_sense") {
		t.Fatalf("logs:\n%s", run.logs)
	}
}
