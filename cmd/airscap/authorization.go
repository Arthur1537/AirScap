package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/mzyy94/airscap/internal/authz"
)

// scanAuthorizer builds the scan authorization from AIRSCAP_CONTROL_URL
// and AIRSCAP_CONTROL_TOKEN_FILE. Neither set: every scan is refused.
// Only one set, an unreadable or group/world-accessible token file, or an
// invalid URL: error (AirScap does not start).
func scanAuthorizer(controlURL, tokenFile string) (authz.Authorizer, error) {
	if controlURL == "" && tokenFile == "" {
		slog.Warn("scan authorization not configured: all scans are refused " +
			"(set AIRSCAP_CONTROL_URL and AIRSCAP_CONTROL_TOKEN_FILE)")
		return authz.Deny{}, nil
	}
	if controlURL == "" || tokenFile == "" {
		return nil, errors.New("AIRSCAP_CONTROL_URL and AIRSCAP_CONTROL_TOKEN_FILE must be set together")
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("scanner token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("scanner token file must be a regular file accessible by its owner only")
	}
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("scanner token file: %w", err)
	}
	control, err := authz.NewControl(controlURL, strings.TrimSpace(string(data)), nil)
	if err != nil {
		return nil, err
	}
	slog.Info("scan authorization: ScanSnap Control reservations required")
	return control, nil
}
