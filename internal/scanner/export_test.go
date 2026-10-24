package scanner

import "github.com/mzyy94/airscap/internal/authz"

// NewSimulatedForTest is available to package scanner_test only (test
// build): an online scanner whose data channel is simulated. The
// authorization checkpoint in StartScan is the production one.
func NewSimulatedForTest(a authz.Authorizer, pages int) (*Scanner, *SimulatedScanner) {
	return newSimulated(a, pages)
}
