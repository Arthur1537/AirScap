package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// scannerTarget returns the scanner address and password. Both must be
// configured explicitly (ScanSnap Control fork):
//
//   - Without an address, broadcast discovery takes the first host that
//     answers; AirScap would pair with it and send the identity, which is a
//     reversible encoding of the scanner password.
//   - The default password (last four characters of the serial) is not
//     derived: every host that sees a discovery reply knows the serial.
//   - The password comes only from an owner-only file, not from the
//     environment (EnvironmentFile is typically world-readable).
func scannerTarget(address, password, passwordFile string) (string, string, error) {
	ip := net.ParseIP(address).To4()
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return "", "", errors.New("AIRSCAP_SCANNER_IP must be the scanner's IPv4 address")
	}
	if password != "" {
		return "", "", errors.New("AIRSCAP_PASSWORD is not accepted; use AIRSCAP_PASSWORD_FILE (owner-only file)")
	}
	if passwordFile == "" {
		return "", "", errors.New("AIRSCAP_PASSWORD_FILE is required (the serial-derived default password is not used)")
	}
	data, err := readOwnerOnlyFile(passwordFile, "scanner password file")
	if err != nil {
		return "", "", err
	}
	password = strings.TrimSpace(string(data))
	if password == "" {
		return "", "", errors.New("scanner password file is empty")
	}
	return ip.String(), password, nil
}

// readOwnerOnlyFile reads a regular file that group and others cannot access.
func readOwnerOnlyFile(path, what string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be a regular file accessible by its owner only", what)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return data, nil
}
