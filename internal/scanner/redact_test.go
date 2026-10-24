package scanner

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/vens"
)

const (
	testSerial   = "iX500-QZ9TEST7K3W"
	testPassword = "7K3W"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestDisplaySerialMasksPassword(t *testing.T) {
	s := newTestScanner(nil)
	s.serial = testSerial

	if got := s.DisplaySerial(); got != "iX500-****" {
		t.Errorf("DisplaySerial = %q, want %q", got, "iX500-****")
	}
	// eSCL capabilities are served to every LAN client.
	caps := (&ESCLAdapter{scanner: s, listenPort: 8080}).buildCapabilities()
	if strings.Contains(caps.SerialNumber, testPassword) {
		t.Errorf("eSCL SerialNumber %q discloses the password", caps.SerialNumber)
	}
}

func TestNewLogsNoTokenOrIdentity(t *testing.T) {
	buf := captureLogs(t)
	identity, err := vens.ComputeIdentity(testPassword)
	if err != nil {
		t.Fatal(err)
	}

	s := New("127.0.0.1", vens.DefaultDataPort, vens.DefaultControlPort, identity)

	out := buf.String()
	for name, secret := range map[string]string{
		"identity":     identity,
		"token":        hex.EncodeToString(s.token[:]),
		"token prefix": hex.EncodeToString(s.token[:6]),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked: %s", name, out)
		}
	}
	// The token is registered for RedactingHandler.
	if got := vens.ScrubSecrets(hex.EncodeToString(s.token[:])); got != vens.Redacted {
		t.Errorf("token not registered: %q", got)
	}
}

func TestPaperlessErrorBoundedWithoutToken(t *testing.T) {
	const token = "paperless-token-QZ9-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A misbehaving server echoes the request header and more.
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("denied for " + r.Header.Get("Authorization") + "\n\x1b[31m" + strings.Repeat("x", 5000)))
	}))
	defer server.Close()

	err := uploadToPaperless(server.URL, token, "scan.pdf", []byte("%PDF-1.7"))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, token) {
		t.Errorf("token in error: %q", msg)
	}
	if len(msg) > maxErrorBody+32 {
		t.Errorf("error not bounded: %d bytes", len(msg))
	}
	if strings.ContainsAny(msg, "\x1b\n") {
		t.Errorf("control characters in error: %q", msg)
	}
	if !strings.HasPrefix(msg, "HTTP 403: denied for Token "+vens.Redacted) {
		t.Errorf("diagnosis lost: %q", msg)
	}
}

func TestRedactURLDropsUserInfo(t *testing.T) {
	got := redactURL("http://scan:QZ9pass@paperless.local:8000/")
	if strings.Contains(got, "QZ9pass") {
		t.Errorf("password in %q", got)
	}
	if !strings.Contains(got, "paperless.local:8000") {
		t.Errorf("host lost: %q", got)
	}
}
