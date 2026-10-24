package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScannerTargetRequiresExplicitAddressAndPasswordFile(t *testing.T) {
	good := tokenFile(t, "s3cret-pw\n", 0o600)
	for name, tc := range map[string]struct{ ip, password, file, reason string }{
		"no address (broadcast discovery)": {"", "", good, "AIRSCAP_SCANNER_IP"},
		"broadcast address":                {"255.255.255.255", "", good, "AIRSCAP_SCANNER_IP"},
		"unspecified":                      {"0.0.0.0", "", good, "AIRSCAP_SCANNER_IP"},
		"loopback":                         {"127.0.0.1", "", good, "AIRSCAP_SCANNER_IP"},
		"multicast":                        {"224.0.0.251", "", good, "AIRSCAP_SCANNER_IP"},
		"host name":                        {"scanner.local", "", good, "AIRSCAP_SCANNER_IP"},
		"ipv6":                             {"fe80::1", "", good, "AIRSCAP_SCANNER_IP"},
		"password in environment":          {"192.168.0.210", "0700", good, "AIRSCAP_PASSWORD is not accepted"},
		"no password (serial default)":     {"192.168.0.210", "", "", "AIRSCAP_PASSWORD_FILE is required"},
		"missing file":                     {"192.168.0.210", "", filepath.Join(t.TempDir(), "none"), "scanner password file"},
		"group readable":                   {"192.168.0.210", "", tokenFile(t, "pw", 0o640), "owner only"},
		"world readable":                   {"192.168.0.210", "", tokenFile(t, "pw", 0o604), "owner only"},
		"directory":                        {"192.168.0.210", "", t.TempDir(), "owner only"},
		"empty":                            {"192.168.0.210", "", tokenFile(t, " \n", 0o600), "empty"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := scannerTarget(tc.ip, tc.password, tc.file)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want %q", err, tc.reason)
			}
		})
	}
}

func TestScannerTargetAccepted(t *testing.T) {
	ip, password, err := scannerTarget("192.168.0.210", "", tokenFile(t, "  s3cret-pw\n", 0o400))
	if err != nil || ip != "192.168.0.210" || password != "s3cret-pw" {
		t.Fatalf("ip=%q password=%q err=%v", ip, password, err)
	}
}
