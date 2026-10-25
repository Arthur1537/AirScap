package main

import (
	"fmt"
	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
	"testing"
)

func TestBrowserFailureCodesDoNotContainScannerSecrets(t *testing.T) {
	if scanResultCode(nil) != "staged" {
		t.Fatal("complete scan not staged")
	}
	if scanResultCode(fmt.Errorf("wrapped: %w", &vens.TerminalStatusError{State: 0x81})) != "terminal_status_rejected" {
		t.Fatal("terminal error lost")
	}
	if scanResultCode(authz.ErrAuthorizationLost) != "authorization_lost" {
		t.Fatal("authority loss lost")
	}
	if scanResultCode(fmt.Errorf("synthetic-private-data")) != "scanner_failure" {
		t.Fatal("unbounded error exposed")
	}
}
