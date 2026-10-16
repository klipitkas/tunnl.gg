package serve

import (
	"strings"
	"testing"

	"github.com/klipitkas/tunnl.gg/pkg/config"
)

func TestPositiveCapacityEnvironment(t *testing.T) {
	defaults := config.Default()
	for name, fallback := range map[string]int{
		"MAX_TOTAL_TUNNELS":         defaults.MaxTotalTunnels,
		"MAX_IN_FLIGHT_PER_VISITOR": defaults.MaxInFlightPerVisitor,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				value string
				want  int
			}{
				{"", fallback}, {"1", 1}, {"1024", 1024},
				{"0", 0}, {"-1", 0}, {"1.5", 0}, {"invalid", 0},
				{"999999999999999999999999999999", 0},
			} {
				t.Run(tc.value, func(t *testing.T) {
					t.Setenv(name, tc.value)
					got, err := positiveIntEnv(name, fallback)
					if tc.want == 0 {
						if err == nil || !strings.Contains(err.Error(), name) {
							t.Fatalf("value %q: expected an error naming %s, got %v", tc.value, name, err)
						}
					} else if err != nil || got != tc.want {
						t.Fatalf("value %q: got %d, %v; want %d", tc.value, got, err, tc.want)
					}
				})
			}
		})
	}
}
