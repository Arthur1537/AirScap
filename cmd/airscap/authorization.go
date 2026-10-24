package main

import (
	"errors"
	"log/slog"
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
	data, err := readOwnerOnlyFile(tokenFile, "scanner token file")
	if err != nil {
		return nil, err
	}
	control, err := authz.NewControl(controlURL, strings.TrimSpace(string(data)), nil)
	if err != nil {
		return nil, err
	}
	slog.Info("scan authorization: ScanSnap Control reservations required")
	return control, nil
}
