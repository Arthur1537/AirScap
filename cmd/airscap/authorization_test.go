package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/authz"
)

const validToken = "scanner-token-cfg-0123456789abcdefghijk"

func tokenFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scanner.token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanAuthorizerUnconfiguredDeniesEverything(t *testing.T) {
	a, err := scanAuthorizer("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Authorize(context.Background(), authz.SourceButton); !errors.Is(err, authz.ErrNotAuthorized) {
		t.Errorf("unconfigured authorizer granted a scan: %v", err)
	}
}

func TestScanAuthorizerRejectsMisconfiguration(t *testing.T) {
	good := tokenFile(t, validToken+"\n", 0o600)
	for name, tc := range map[string]struct{ url, file string }{
		"url only":           {"http://127.0.0.1:18082", ""},
		"token only":         {"", good},
		"missing file":       {"http://127.0.0.1:18082", filepath.Join(t.TempDir(), "missing")},
		"directory":          {"http://127.0.0.1:18082", t.TempDir()},
		"group readable":     {"http://127.0.0.1:18082", tokenFile(t, validToken, 0o640)},
		"world readable":     {"http://127.0.0.1:18082", tokenFile(t, validToken, 0o604)},
		"short token":        {"http://127.0.0.1:18082", tokenFile(t, "short\n", 0o600)},
		"empty token":        {"http://127.0.0.1:18082", tokenFile(t, "", 0o600)},
		"invalid url":        {"ftp://127.0.0.1", good},
		"credentials in url": {"http://u:p@127.0.0.1", good},
	} {
		t.Run(name, func(t *testing.T) {
			if a, err := scanAuthorizer(tc.url, tc.file); err == nil {
				t.Fatalf("accepted, authorizer %T", a)
			}
		})
	}
}

func TestScanAuthorizerHalfConfigurationNamesBothVariables(t *testing.T) {
	for _, tc := range [][2]string{{"http://127.0.0.1:18082", ""}, {"", tokenFile(t, validToken, 0o600)}} {
		_, err := scanAuthorizer(tc[0], tc[1])
		if err == nil || !strings.Contains(err.Error(), "must be set together") {
			t.Errorf("%q: err = %v", tc, err)
		}
	}
}

func TestScanAuthorizerConfigured(t *testing.T) {
	a, err := scanAuthorizer("http://127.0.0.1:18082", tokenFile(t, "  "+validToken+"\n", 0o400))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.(*authz.Control); !ok {
		t.Fatalf("authorizer = %T", a)
	}
}
