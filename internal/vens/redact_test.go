package vens

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// Test secrets: distinctive so that an accidental match is impossible.
const (
	testSerial   = "iX500-QZ9TEST7K3W"
	testPassword = "7K3W" // PasswordFromSerial(testSerial)
)

var testToken = [8]byte{0xde, 0xc0, 0xad, 0x5e, 0xc7, 0x31}

func testIdentity(t *testing.T) string {
	t.Helper()
	identity, err := ComputeIdentity(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// captureLogs routes slog's default logger into a buffer at debug level.
// The handler is a plain TextHandler: secrets must be absent at the source,
// not only removed by RedactingHandler.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func secretForms(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"serial":       testSerial,
		"password":     testPassword,
		"identity":     testIdentity(t),
		"token":        hex.EncodeToString(testToken[:]),
		"token prefix": hex.EncodeToString(testToken[:6]),
		"token upper":  strings.ToUpper(hex.EncodeToString(testToken[:6])),
	}
}

func assertNoSecrets(t *testing.T, output string, forms map[string]string) {
	t.Helper()
	for name, secret := range forms {
		if strings.Contains(output, secret) {
			t.Errorf("%s %q leaked in output:\n%s", name, secret, output)
		}
	}
}

func TestPasswordIsTailOfSerial(t *testing.T) {
	// Precondition of the whole redaction: a full serial discloses the
	// default password.
	if got := PasswordFromSerial(testSerial); got != testPassword {
		t.Fatalf("PasswordFromSerial = %q, want %q", got, testPassword)
	}
}

func TestRedactSerial(t *testing.T) {
	cases := map[string]string{
		testSerial:            "iX500-****",
		"iX500-AK6ABB0700":    "iX500-****",
		"iX1600-AB12\x00\x00": "iX1600-****",
		"AK6ABB0700":          "****",
		"iX500-":              "****",
		"-0700":               "****",
		"":                    "",
	}
	for serial, want := range cases {
		got := RedactSerial(serial)
		if got != want {
			t.Errorf("RedactSerial(%q) = %q, want %q", serial, got, want)
		}
		if tail := PasswordFromSerial(serial); len(tail) == 4 && strings.Contains(got, tail) {
			t.Errorf("RedactSerial(%q) = %q contains the password %q", serial, got, tail)
		}
	}
}

func TestPacketSummaryOmitsPayload(t *testing.T) {
	identity := testIdentity(t)
	packet := MarshalReserveRequest(testToken, "192.168.0.238", ClientNotifyPort, identity, time.Now())
	buf := captureLogs(t)

	slog.Debug("control send", "packet", PacketSummary(packet))

	out := buf.String()
	assertNoSecrets(t, out, secretForms(t))
	if strings.Contains(out, hex.EncodeToString(packet[16:])) {
		t.Errorf("raw packet bytes in output: %s", out)
	}
	for _, want := range []string{"packet.bytes=384", "packet.magic=VENS",
		fmt.Sprintf("packet.command=0x%X", CmdReserve)} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata %q missing: %s", want, out)
		}
	}
}

func TestPacketSummaryShortAndBinary(t *testing.T) {
	buf := captureLogs(t)
	slog.Debug("short", "packet", PacketSummary([]byte{1, 2, 3}))
	slog.Debug("binary", "packet", PacketSummary([]byte{0, 0, 0, 16, 0xff, 0, 1, 2}))
	out := buf.String()
	if !strings.Contains(out, "packet.bytes=3") || !strings.Contains(out, "packet.magic=binary") {
		t.Errorf("unexpected summary: %s", out)
	}
}

type stringer string

func (s stringer) String() string { return string(s) }

func TestRedactingHandlerScrubsRegisteredSecrets(t *testing.T) {
	identity := testIdentity(t)
	RegisterSecret(testSerial)
	RegisterSecret(testPassword)
	RegisterSecret(identity)
	RegisterToken(testToken)

	var buf bytes.Buffer
	logger := slog.New(NewRedactingHandler(
		slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}),
	))

	// Every way a secret could reach a record, at debug level.
	logger.Debug("message with "+identity, "serial", testSerial)
	logger.Info("error", "err", fmt.Errorf("pairing failed for identity %s", identity))
	logger.Warn("group", slog.Group("scanner", "password", testPassword,
		"token", hex.EncodeToString(testToken[:])))
	logger.Error("stringer", "value", stringer("serial "+testSerial))
	logger.With("identity", identity).WithGroup("g").Info("with", "x", testPassword)
	logger.Debug("bytes", "raw", []byte(testSerial))
	logger.Debug("any", "struct", struct{ Serial string }{testSerial})
	logger.Debug("wrapped", "err", errors.Join(errors.New("a"), errors.New(testPassword)))

	out := buf.String()
	assertNoSecrets(t, out, secretForms(t))
	if got := strings.Count(out, Redacted); got < 10 {
		t.Errorf("expected redaction markers, got %d:\n%s", got, out)
	}
	// Non-secret values stay readable.
	if !strings.Contains(out, "pairing failed for identity") {
		t.Errorf("message context lost: %s", out)
	}
}

func TestRegisterSecretIgnoresShortValues(t *testing.T) {
	RegisterSecret("")
	RegisterSecret("ab")
	for _, s := range registeredSecrets() {
		if len(s) < minSecretLength {
			t.Errorf("short secret %q registered", s)
		}
	}
	if got := ScrubSecrets("ab"); got != "ab" {
		t.Errorf("short value scrubbed: %q", got)
	}
}

func TestComputeIdentityErrorOmitsPassword(t *testing.T) {
	secret := "QZ9-very-long-password-123"
	_, err := ComputeIdentity(secret)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), fmt.Sprint(len(secret))) {
		t.Errorf("error discloses the password or its length: %v", err)
	}
}
