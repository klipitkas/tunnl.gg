package subdomain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

var adjectives = []string{
	"happy", "sunny", "swift", "calm", "bold", "bright", "cool", "warm",
	"quick", "clever", "brave", "gentle", "kind", "proud", "wise", "keen",
	"fresh", "crisp", "pure", "clear", "wild", "free", "silent", "quiet",
	"golden", "silver", "coral", "amber", "jade", "ruby", "pearl", "onyx",
}

var nouns = []string{
	"tiger", "eagle", "wolf", "bear", "hawk", "fox", "deer", "owl",
	"river", "mountain", "forest", "ocean", "meadow", "valley", "canyon", "island",
	"star", "moon", "cloud", "storm", "wind", "flame", "wave", "stone",
	"maple", "cedar", "pine", "oak", "willow", "birch", "aspen", "elm",
}

// Generate creates a random memorable subdomain in the format adjective-noun-hex.
func Generate() (string, error) {
	// 1 byte for adjective index, 1 byte for noun index, 4 bytes for hex suffix
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	adj := adjectives[int(buf[0])%len(adjectives)]
	noun := nouns[int(buf[1])%len(nouns)]
	hexSuffix := hex.EncodeToString(buf[2:])

	return fmt.Sprintf("%s-%s-%s", adj, noun, hexSuffix), nil
}

// IsValid checks if a subdomain matches the expected format:
//   - 3-part: adjective-noun-hex (base subdomain)
//   - 4-part: adjective-noun-hex-port (port-suffixed subdomain)
func IsValid(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 && len(parts) != 4 {
		return false
	}

	if !contains(adjectives, parts[0]) {
		return false
	}
	if !contains(nouns, parts[1]) {
		return false
	}

	// Validate hex suffix: exactly 8 lowercase hex characters (4 bytes)
	if !isLowercaseHex(parts[2], 8) {
		return false
	}

	// Validate optional port suffix
	if len(parts) == 4 {
		port, err := strconv.Atoi(parts[3])
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}

	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isLowercaseHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// WithPort returns a port-suffixed subdomain: base-{port}.
func WithPort(base string, port uint32) string {
	return fmt.Sprintf("%s-%d", base, port)
}

// BaseSubdomain extracts the adj-noun-hex base from either a 3-part or 4-part subdomain.
func BaseSubdomain(s string) string {
	parts := strings.Split(s, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], "-")
	}
	return s
}
