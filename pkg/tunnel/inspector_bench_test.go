package tunnel

import (
	"testing"
	"time"
)

func BenchmarkInspectorAdd(b *testing.B) {
	for _, size := range []int{0, MaxInspectedBody} {
		name := "headers"
		if size > 0 {
			name = "bodies"
		}
		b.Run(name, func(b *testing.B) {
			i := NewInspector()
			e := Exchange{Time: time.Now(), Method: "GET", Target: "/test", Status: 200,
				ResponseBody: Body{Data: make([]byte, size), Size: int64(size)}}
			for range InspectorSize {
				i.Add(e)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				i.Add(e)
			}
		})
	}
}
