package config

// Profile holds device-specific default tuning values.
type Profile struct {
	Name           string
	ZRAMPercent    int
	Swappiness     int
	GPUMemMB       int // 0 = skip gpu_mem in config.txt (e.g. Pi 5)
	EvictionHard   string
	TestedInV01    bool
}

// profiles is the built-in device profile registry.
var profiles = map[string]Profile{
	"rpi3": {
		Name:         "rpi3",
		ZRAMPercent:  50,
		Swappiness:   60,
		GPUMemMB:     16,
		EvictionHard: "memory.available<100Mi",
		TestedInV01:  true,
	},
	"rpi3b-plus": {
		Name:         "rpi3b-plus",
		ZRAMPercent:  50,
		Swappiness:   60,
		GPUMemMB:     16,
		EvictionHard: "memory.available<100Mi",
		TestedInV01:  true,
	},
	"rpi4": {
		Name:         "rpi4",
		ZRAMPercent:  25,
		Swappiness:   30,
		GPUMemMB:     16,
		EvictionHard: "memory.available<200Mi",
		TestedInV01:  false,
	},
	"rpi5": {
		Name:         "rpi5",
		ZRAMPercent:  0,
		Swappiness:   10,
		GPUMemMB:     0, // Pi 5 does not use gpu_mem
		EvictionHard: "memory.available<500Mi",
		TestedInV01:  false,
	},
}

// GetProfile returns the profile for the given name.
// Returns the profile and true if found, zero value and false otherwise.
func GetProfile(name string) (Profile, bool) {
	p, ok := profiles[name]
	return p, ok
}

// KnownProfiles returns a sorted list of all known profile names plus "auto".
func KnownProfiles() []string {
	return []string{"auto", "rpi3", "rpi3b-plus", "rpi4", "rpi5"}
}

// DetectProfile maps a /proc/device-tree/model string to a profile name.
// Returns "unknown" if the model is not recognized.
func DetectProfile(model string) string {
	switch {
	case contains(model, "Raspberry Pi 3 Model B Plus"):
		return "rpi3b-plus"
	case contains(model, "Raspberry Pi 3 Model B"):
		return "rpi3"
	case contains(model, "Raspberry Pi 4"):
		return "rpi4"
	case contains(model, "Raspberry Pi 5"):
		return "rpi5"
	default:
		return "unknown"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && indexString(s, substr) >= 0)
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
