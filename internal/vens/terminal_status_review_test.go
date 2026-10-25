package vens

// Review 2026-10-24: real iX500 scans ended with "terminal status is not
// clean no-paper" after every page had arrived (test 1: one page, test 2:
// front and back), with "scan status 0x00000080" logged just before the
// final WAIT_FOR_SCAN. These tests reproduce every field combination that
// yields this error, show which of them the pre-wait check lets through,
// and pin the decision itself: diagnostics must not change it.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	opGetStatus    = 0xC2
	opWaitForScan  = 0xE0
	opRequestSense = 0x03
	opEndScan      = 0xD6
)

// statusReply builds the documented 72-byte GET_STATUS response.
func statusReply(state, errorField uint32) []byte {
	p := response(72)
	binary.BigEndian.PutUint32(p[StatusRespScanStatusOffset:], state)
	binary.BigEndian.PutUint32(p[StatusRespErrorOffset:], errorField)
	return p
}

// senseReply builds a 58-byte REQUEST SENSE response (fixed format 0x70).
func senseReply(key, asc, ascq byte) []byte {
	p := response(58)
	p[SenseDataOffset] = 0x70
	p[SenseDataOffset+2] = key
	p[SenseDataOffset+7] = 10
	p[SenseDataOffset+12] = asc
	p[SenseDataOffset+13] = ascq
	return p
}

// fakeScanner answers the end-of-document sequence by SCSI opcode (CDB at
// request offset 48). Until the first REQUEST SENSE after the terminal wait,
// GET_STATUS reports pendingError instead of terminalError (contingent
// allegiance: a condition is pending until its sense has been read).
type fakeScanner struct {
	before       [2]uint32 // state, error field before the wait
	terminal     [2]uint32 // after the wait (status 2)
	pendingError uint32    // error field while the sense is unread; 0 = none
	sense        []byte
	// After the terminal status: drop the connection, or read the next
	// request and never answer it (A5 side-effect tests).
	dropAfterTerminal bool
	hangAfterTerminal time.Duration
	terminalReply     []byte // raw terminal status, if set
	terminalSent      bool
	waited            bool
	senseRead         bool
	seen              []byte
}

func (f *fakeScanner) serve(t *testing.T, server net.Conn) {
	defer server.Close()
	for {
		var length [4]byte
		if _, err := io.ReadFull(server, length[:]); err != nil {
			return
		}
		request := make([]byte, binary.BigEndian.Uint32(length[:]))
		copy(request, length[:])
		if _, err := io.ReadFull(server, request[4:]); err != nil || len(request) < 49 {
			return
		}
		op := request[48]
		f.seen = append(f.seen, op)
		var reply []byte
		switch op {
		case opGetStatus:
			switch {
			case !f.waited:
				reply = statusReply(f.before[0], f.before[1])
			case f.pendingError != 0 && !f.senseRead:
				reply = statusReply(f.terminal[0], f.pendingError)
			case f.terminalReply != nil && !f.terminalSent:
				reply = f.terminalReply
			default:
				reply = statusReply(f.terminal[0], f.terminal[1])
			}
		case opWaitForScan:
			f.waited = true
			reply = response(40)
			binary.BigEndian.PutUint32(reply[WaitRespStatusOffset:], 2)
		case opRequestSense:
			f.senseRead = true
			reply = f.sense
		case opEndScan:
			reply = response(40)
		default:
			t.Errorf("unexpected opcode 0x%02X", op)
			return
		}
		if f.terminalSent && f.hangAfterTerminal > 0 {
			time.Sleep(f.hangAfterTerminal)
			return
		}
		if _, err := server.Write(reply); err != nil {
			return
		}
		if op == opGetStatus && f.waited && !f.terminalSent {
			f.terminalSent = true
			if f.dropAfterTerminal {
				return
			}
		}
	}
}

func endOfDocument(t *testing.T, f *fakeScanner) (error, string) {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); f.serve(t, server) }()
	s := &ScanSession{conn: client, physicalSheet: 1, sidesPerSheet: 2}
	_, err := s.NextPage()
	client.Close()
	<-done
	return err, logs.String()
}

var scanComplete = []byte{SenseKeyMediumError, VendorASC, ASCQScanComplete}

func TestReviewTerminalStatusReproduction(t *testing.T) {
	cases := []struct {
		name     string
		f        fakeScanner
		accepted bool
		field    string // what the error must name
	}{
		{"clean, sense no-sense", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, true, ""},
		{"clean, sense scan-complete", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0},
			sense: senseReply(scanComplete[0], scanComplete[1], scanComplete[2])}, true, ""},
		// H2: bits in the upper half of the error field. The documented error
		// code is the lower 16 bits; the pre-wait check reads only those.
		{"H2 upper error bits", fakeScanner{before: [2]uint32{0x80, 0x00010000}, terminal: [2]uint32{0x80, 0x00010000},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, false, "error field 0x00010000 (code 0x0000, upper 0x0001)"},
		{"lower error code", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0x0001},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, false, "error field 0x00000001 (code 0x0001"},
		// H3: the scan state after the wait is not exactly 0x80.
		{"H3 extra unknown state bit", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x81, 0},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, false, "scan state 0x00000081 (expected 0x00000080, unknown bits 0x00000001)"},
		{"H3 no-paper bit clear", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x00, 0},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, false, "scan state 0x00000000"},
		// H1: the wait left a condition pending; GET_STATUS is sent before
		// the REQUEST SENSE that the protocol names for status 2.
		{"H1 pending condition before sense", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0},
			pendingError: 0x00000003, sense: senseReply(scanComplete[0], scanComplete[1], scanComplete[2])}, false,
			"error field 0x00000003"},
		// Real faults stay faults.
		{"jam", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x8080, 0},
			sense: senseReply(SenseKeyMediumError, VendorASC, ASCQPaperJam)}, false, "scan state 0x00008080"},
		{"cover open", fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0xA0, 0},
			sense: senseReply(SenseKeyNoSense, 0, 0)}, false, "scan state 0x000000A0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.f
			err, logs := endOfDocument(t, &f)
			if c.accepted {
				if err != io.EOF {
					t.Fatalf("clean end refused: %v", err)
				}
				if !strings.Contains(logs, "terminal sense") {
					t.Fatal("clean end leaves no sense record in the log")
				}
				return
			}
			var terminal *TerminalStatusError
			if !errors.As(err, &terminal) {
				t.Fatalf("got %v, want TerminalStatusError", err)
			}
			if !strings.HasPrefix(err.Error(), "terminal status is not clean no-paper: ") || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("error does not name the field: %q", err)
			}
			// Both fields appear separately in the log of the rejection, plus
			// the sense and the status after it (diagnostics only).
			for _, want := range []string{"terminal status rejected", "phase=terminal", "state=0x", "error_field=0x",
				"error_code=0x", "error_upper=0x", "unknown_state_bits=0x", "terminal status rejected: sense", "phase=after_sense"} {
				if !strings.Contains(logs, want) {
					t.Fatalf("log lacks %q:\n%s", want, logs)
				}
			}
			// H1 is told apart on hardware by the status after the sense.
			if c.f.pendingError != 0 && !strings.Contains(logs[strings.Index(logs, "phase=after_sense"):], "error_field=0x00000000") {
				t.Fatalf("status after sense not recorded:\n%s", logs)
			}
		})
	}
}

// The field observation (0x00000080 before the wait, no "scanner error")
// is compatible with H1, H2 and H3: the pre-wait check passes in all three.
func TestReviewPreWaitCheckPassesForAllHypotheses(t *testing.T) {
	for _, before := range [][2]uint32{{0x80, 0}, {0x80, 0x00010000}, {0x80, 0xFFFF0000}} {
		f := fakeScanner{before: before, terminal: [2]uint32{0x80, 0}, sense: senseReply(SenseKeyNoSense, 0, 0)}
		err, logs := endOfDocument(t, &f)
		var scanErr *ScanError
		if errors.As(err, &scanErr) {
			t.Fatalf("pre-wait check refused 0x%08X: %v", before[1], err)
		}
		if !strings.Contains(logs, "phase=before_wait") || !strings.Contains(logs, "status=0x00000080") {
			t.Fatalf("pre-wait fields not logged:\n%s", logs)
		}
	}
}

// The H1 run shows the order of requests: status first, sense second.
func TestReviewTerminalRequestOrder(t *testing.T) {
	f := fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{0x80, 0}, sense: senseReply(SenseKeyNoSense, 0, 0)}
	if err, _ := endOfDocument(t, &f); err != io.EOF {
		t.Fatal(err)
	}
	if got := f.seen; !bytes.Equal(got, []byte{opGetStatus, opWaitForScan, opGetStatus, opRequestSense}) {
		t.Fatalf("request order %X", got)
	}
}

// The decision is exactly the original predicate for every value pair:
// diagnostics neither accept more nor refuse more.
func TestReviewTerminalDecisionUnchanged(t *testing.T) {
	values := []uint32{0, 1, 0x20, 0x7F, 0x80, 0x81, 0xA0, 0xC0, 0x180, 0x8000, 0x8080, 0xFFFF, 0x10000, 0x10080, 0x800080, 0xFFFFFFFF}
	r := rand.New(rand.NewSource(20261024))
	for i := 0; i < 24; i++ {
		values = append(values, r.Uint32())
	}
	for _, state := range values {
		for _, field := range values {
			f := fakeScanner{before: [2]uint32{0x80, 0}, terminal: [2]uint32{state, field}, sense: senseReply(SenseKeyNoSense, 0, 0)}
			err, _ := endOfDocument(t, &f)
			if want := state == ADFPaperMask && field == 0; (err == io.EOF) != want {
				t.Fatalf("state 0x%08X field 0x%08X: accepted=%v want %v (%v)", state, field, err == io.EOF, want, err)
			}
		}
	}
}
