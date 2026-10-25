package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/vens"
)

func scanResultCode(err error) string {
	if err == nil {
		return "staged"
	}
	var terminal *vens.TerminalStatusError
	if errors.As(err, &terminal) {
		return "terminal_status_rejected"
	}
	if errors.Is(err, authz.ErrNotAuthorized) || errors.Is(err, authz.ErrRecoveryRequired) {
		return "authorization_lost"
	}
	var problem *vens.ScanError
	if errors.As(err, &problem) {
		switch problem.Kind {
		case vens.ScanErrNoPaper:
			return "no_paper"
		case vens.ScanErrPaperJam:
			return "paper_jam"
		case vens.ScanErrMultiFeed:
			return "multi_feed"
		case vens.ScanErrCoverOpen:
			return "cover_open"
		}
	}
	return "scanner_failure"
}

// The same mutex covers physical buttons and browser commands for the entire
// scan, including Close/receipt. It has no deadline that could admit a second
// scan while the first goroutine is still running. Control is a second gate.
func browserCommandLoop(ctx context.Context, control *authz.Control, sc *scanner.Scanner,
	gate *sync.Mutex, cfg func() vens.ScanConfig, intake string, status *scanner.ScanJobStatus) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !gate.TryLock() {
				continue
			}
			func() {
				defer gate.Unlock()
				command, err := control.NextBrowserCommand(ctx)
				if err != nil {
					slog.Debug("browser command polling unavailable")
					return
				}
				if command == nil {
					return
				}
				status.SetScanning(true)
				manifest, err := scanner.StageButtonScan(authz.WithBrowserCommand(ctx, *command), sc, cfg(), intake)
				code := scanResultCode(err)
				status.SetResult(err, manifest.Pages, "private emergency intake; manual review required")
				if err != nil {
					slog.Warn("browser scan failed; no document released", "reason", code, "err", err)
				}
				if err := control.CompleteBrowserCommand(context.WithoutCancel(ctx), command.ID, code); err != nil {
					slog.Warn("browser scan outcome unconfirmed; operator recovery required")
				}
			}()
		}
	}
}
