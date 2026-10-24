package authz

// ScanSettings are chosen per job in ScanSnap Control and travel with the
// grant; AirScap applies them before the first sheet is fed. The values are
// exactly what the iX500 accepts over VENS (dpi 0 = automatic).
type ScanSettings struct {
	Sides        string `json:"sides"` // "duplex" or "simplex"
	Color        string `json:"color"` // "auto", "color", "gray" or "bw"
	DPI          int    `json:"dpi"`   // 0, 150, 200 or 300
	BleedThrough bool   `json:"bleed_through"`
}

// Valid reports whether every field holds a supported value.
func (s ScanSettings) Valid() bool {
	switch s.Sides {
	case "duplex", "simplex":
	default:
		return false
	}
	switch s.Color {
	case "auto", "color", "gray", "bw":
	default:
		return false
	}
	switch s.DPI {
	case 0, 150, 200, 300:
		return true
	}
	return false
}

// SettingsGrant is a grant that carries the job's scan settings. Grants from
// ScanSnap Control always do; Authorize refuses a reservation without them.
type SettingsGrant interface {
	Grant
	ScanSettings() ScanSettings
}
