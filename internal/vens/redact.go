package vens

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Secrets of the VENS protocol and how they must not leak:
//
//   - The default password is the last four characters of the serial
//     (PasswordFromSerial). A full serial in a log, an API response or
//     the eSCL capabilities therefore discloses the password.
//   - The pairing identity is derived from the password (ComputeIdentity)
//     and travels in the reserve request.
//   - Every control and data packet carries the session token.
//
// Packets are logged only as PacketSummary (length, magic, command), never
// as raw bytes. Serials are shown as RedactSerial. As a second line of
// defence, RedactingHandler replaces registered secrets in every log record,
// including error messages produced by other packages.

// Redacted replaces a secret in log output.
const Redacted = "[REDACTED]"

// RedactSerial keeps the model prefix of a serial (up to the last '-') and
// masks the rest, which contains the default password. A serial without a
// model prefix is masked completely.
func RedactSerial(serial string) string {
	s := strings.TrimRight(serial, " \x00")
	if s == "" {
		return ""
	}
	if i := strings.LastIndex(s, "-"); i > 0 && i < len(s)-1 {
		return s[:i+1] + "****"
	}
	return "****"
}

// PacketSummary describes a TCP control or data packet without its payload:
// declared size, received length, magic and the command word at [8:12].
// The token at [16:24] and any payload (identity, scan data) are omitted.
type PacketSummary []byte

// LogValue implements slog.LogValuer.
func (p PacketSummary) LogValue() slog.Value {
	attrs := []slog.Attr{slog.Int("bytes", len(p))}
	if len(p) >= 8 {
		attrs = append(attrs, slog.String("magic", printableMagic(p[4:8])))
	}
	if len(p) >= 12 {
		attrs = append(attrs, slog.String("command",
			fmt.Sprintf("0x%X", binary.BigEndian.Uint32(p[8:12]))))
	}
	return slog.GroupValue(attrs...)
}

func printableMagic(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "binary"
		}
	}
	return string(b)
}

// secretRegistry holds the secrets RedactingHandler scrubs.
var secretRegistry struct {
	mu      sync.RWMutex
	secrets []string
}

// minSecretLength avoids scrubbing very short strings that would make every
// log line unreadable; such secrets are protected by not logging them.
const minSecretLength = 3

// RegisterSecret adds a value that must never appear in log output.
func RegisterSecret(secret string) {
	secret = strings.TrimRight(secret, " \x00")
	if len(secret) < minSecretLength {
		return
	}
	secretRegistry.mu.Lock()
	defer secretRegistry.mu.Unlock()
	for _, known := range secretRegistry.secrets {
		if known == secret {
			return
		}
	}
	secretRegistry.secrets = append(secretRegistry.secrets, secret)
}

// RegisterToken registers the hex forms of a session token.
func RegisterToken(token [8]byte) {
	RegisterSecret(hex.EncodeToString(token[:]))
	RegisterSecret(strings.ToUpper(hex.EncodeToString(token[:])))
	RegisterSecret(hex.EncodeToString(token[:6]))
}

func registeredSecrets() []string {
	secretRegistry.mu.RLock()
	defer secretRegistry.mu.RUnlock()
	return append([]string(nil), secretRegistry.secrets...)
}

// ScrubSecrets replaces every registered secret in s.
func ScrubSecrets(s string) string {
	for _, secret := range registeredSecrets() {
		s = strings.ReplaceAll(s, secret, Redacted)
	}
	return s
}

// RedactingHandler wraps a slog.Handler and replaces registered secrets in
// the message and in every attribute value, also inside groups and in
// values that are errors, Stringers or LogValuers.
type RedactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler wraps inner.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled implements slog.Handler.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *RedactingHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, ScrubSecrets(record.Message), record.PC)
	record.Attrs(func(a slog.Attr) bool {
		clean.AddAttrs(scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, clean)
}

// WithAttrs implements slog.Handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = scrubAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(clean)}
}

// WithGroup implements slog.Handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

func scrubAttr(a slog.Attr) slog.Attr {
	a.Value = scrubValue(a.Value.Resolve())
	return a
}

func scrubValue(v slog.Value) slog.Value {
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(ScrubSecrets(v.String()))
	case slog.KindGroup:
		group := v.Group()
		clean := make([]slog.Attr, len(group))
		for i, a := range group {
			clean[i] = scrubAttr(a)
		}
		return slog.GroupValue(clean...)
	case slog.KindAny:
		switch x := v.Any().(type) {
		case error:
			return slog.StringValue(ScrubSecrets(x.Error()))
		case fmt.Stringer:
			return slog.StringValue(ScrubSecrets(x.String()))
		case []byte:
			return slog.StringValue(ScrubSecrets(string(x)))
		default:
			return slog.StringValue(ScrubSecrets(fmt.Sprintf("%+v", x)))
		}
	default:
		return v
	}
}
