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
		{"five parts", "happy-tiger-abcd-ef01-extra", false},
		{"invalid adjective", "bogus-tiger-abcdef01", false},
		{"invalid noun", "happy-bogus-abcdef01", false},
		{"hex too short", "happy-tiger-abcdef0", false},
		{"hex too long", "happy-tiger-abcdef012", false},
		{"uppercase hex", "happy-tiger-ABCDEF01", false},
		{"non-hex chars", "happy-tiger-ghijklmn", false},
		// Port-suffixed subdomains
		{"valid with port 80", "happy-tiger-abcdef01-80", true},
		{"valid with port 3000", "bold-ocean-12345678-3000", true},
		{"valid with port 65535", "happy-tiger-abcdef01-65535", true},
		{"valid with port 1", "happy-tiger-abcdef01-1", true},
		{"invalid port 0", "happy-tiger-abcdef01-0", false},
		{"invalid port 65536", "happy-tiger-abcdef01-65536", false},
		{"invalid port negative", "happy-tiger-abcdef01--1", false},
		{"invalid port non-numeric", "happy-tiger-abcdef01-abc", false},
		{"invalid port empty", "happy-tiger-abcdef01-", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValid(tt.input); got != tt.want {
				t.Errorf("IsValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestWithPort(t *testing.T) {
	tests := []struct {
		name string
		base string
		port uint32
		want string
	}{
		{"port 80", "happy-tiger-abcdef01", 80, "happy-tiger-abcdef01-80"},
		{"port 3000", "happy-tiger-abcdef01", 3000, "happy-tiger-abcdef01-3000"},
		{"port 65535", "happy-tiger-abcdef01", 65535, "happy-tiger-abcdef01-65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithPort(tt.base, tt.port); got != tt.want {
				t.Errorf("WithPort(%q, %d) = %q, want %q", tt.base, tt.port, got, tt.want)
			}
		})
	}
}

func TestBaseSubdomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"3-part base", "happy-tiger-abcdef01", "happy-tiger-abcdef01"},
		{"4-part with port", "happy-tiger-abcdef01-3000", "happy-tiger-abcdef01"},
		{"4-part with port 80", "bold-ocean-12345678-80", "bold-ocean-12345678"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BaseSubdomain(tt.input); got != tt.want {
				t.Errorf("BaseSubdomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
