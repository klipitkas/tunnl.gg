package subdomain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

// Generate creates a random memorable subdomain in the format adjective-noun-hex
func Generate() (string, error) {
	adjIdx := make([]byte, 1)
	nounIdx := make([]byte, 1)
	hexBytes := make([]byte, 4) // 4 bytes = 8 hex characters for better entropy

	if _, err := rand.Read(adjIdx); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	if _, err := rand.Read(nounIdx); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	if _, err := rand.Read(hexBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	adj := adjectives[int(adjIdx[0])%len(adjectives)]
	noun := nouns[int(nounIdx[0])%len(nouns)]
	hexSuffix := hex.EncodeToString(hexBytes)

	return fmt.Sprintf("%s-%s-%s", adj, noun, hexSuffix), nil
}

// IsValid checks if a subdomain matches the expected format (adjective-noun-hex)
func IsValid(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}

	// Check adjective
	adjValid := false
	for _, adj := range adjectives {
		if parts[0] == adj {
			adjValid = true
			break
		}
	}
	if !adjValid {
		return false
	}

	// Check noun
	nounValid := false
	for _, noun := range nouns {
		if parts[1] == noun {
			nounValid = true
			break
		}
	}
	if !nounValid {
		return false
	}

	// Check hex suffix (8 characters)
	if len(parts[2]) != 8 {
		return false
	}
	for _, c := range parts[2] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}

	return true
}
