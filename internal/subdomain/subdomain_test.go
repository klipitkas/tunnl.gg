package subdomain

import (
	"testing"
)

func TestGenerate(t *testing.T) {
	t.Run("format", func(t *testing.T) {
		sub, err := Generate()
		if err != nil {
			t.Fatalf("Generate() error: %v", err)
		}
		if !IsValid(sub) {
			t.Errorf("Generate() produced invalid subdomain: %q", sub)
		}
	})

	t.Run("uniqueness", func(t *testing.T) {
		seen := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			sub, err := Generate()
			if err != nil {
				t.Fatalf("Generate() error on iteration %d: %v", i, err)
			}
			if _, ok := seen[sub]; ok {
				t.Fatalf("Generate() produced duplicate subdomain %q on iteration %d", sub, i)
			}
			seen[sub] = struct{}{}
		}
	})
}

func TestIsValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid subdomain", "happy-tiger-abcdef01", true},
		{"valid subdomain 2", "bold-ocean-12345678", true},
		{"empty string", "", false},
		{"no hyphens", "happytigerabcdef01", false},
		{"too few parts", "happy-tiger", false},
		{"too many parts", "happy-tiger-abcd-ef01", false},
		{"invalid adjective", "bogus-tiger-abcdef01", false},
		{"invalid noun", "happy-bogus-abcdef01", false},
		{"hex too short", "happy-tiger-abcdef0", false},
		{"hex too long", "happy-tiger-abcdef012", false},
		{"uppercase hex", "happy-tiger-ABCDEF01", false},
		{"non-hex chars", "happy-tiger-ghijklmn", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValid(tt.input); got != tt.want {
				t.Errorf("IsValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
