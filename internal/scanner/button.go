package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// ButtonListener listens for scanner button press events on UDP:55265.
type ButtonListener struct {
	conn      *net.UDPConn
	callback  func()
	done      chan struct{}
	scannerIP net.IP
	lastEvent time.Time
}

// NewButtonListener creates a ButtonListener that calls callback on button press.
func NewButtonListener(scannerHost string, callback func()) *ButtonListener {
	return &ButtonListener{callback: callback, scannerIP: net.ParseIP(scannerHost)}
}

// Start begins listening for button press events. Blocks until ctx is cancelled.
func (b *ButtonListener) Start(ctx context.Context) error {
	if b.scannerIP == nil {
		return fmt.Errorf("explicit scanner IP required for button events")
	}
	addr := &net.UDPAddr{Port: int(vens.ClientNotifyPort)}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen UDP:%d: %w", vens.ClientNotifyPort, err)
	}
	b.conn = conn
	b.done = make(chan struct{})
	slog.Info("button listener started", "port", vens.ClientNotifyPort)

	go b.loop(ctx)
	return nil
}

// Stop closes the listener and waits for the goroutine to exit.
func (b *ButtonListener) Stop() {
	if b.conn != nil {
		b.conn.Close()
	}
	if b.done != nil {
		<-b.done
	}
}

func (b *ButtonListener) loop(ctx context.Context) {
	defer close(b.done)
	buf := make([]byte, 256)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, remote, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			// Stop closed the socket: every further read fails at once, so
			// keep reading only on transient errors.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Debug("button listener read error", "err", err)
			continue
		}

		eventType, eventData, err := vens.ParseEventNotification(buf[:n])
		if err != nil {
			slog.Debug("ignoring non-VENS packet", "remote", remote, "err", err)
			continue
		}

		if !b.acceptEvent(remote, eventType, eventData, time.Now()) {
			continue
		}
		slog.Info("scanner event received", "type", eventType, "data", eventData, "remote", remote)
		if b.callback != nil {
			b.callback()
		}
	}
}

// The wire protocol does not authenticate UDP notifications. This filter
// reduces spoof/replay exposure; the QNAP reservation remains mandatory.
func (b *ButtonListener) acceptEvent(remote *net.UDPAddr, kind, data uint32, now time.Time) bool {
	if remote == nil || b.scannerIP == nil || !remote.IP.Equal(b.scannerIP) || kind != 1 || data != 0x02000000 {
		return false
	}
	previous := b.lastEvent
	b.lastEvent = now // Every notification extends the quiet period.
	if !previous.IsZero() && now.Sub(previous) < 2*time.Second {
		return false
	}
	return true
}
