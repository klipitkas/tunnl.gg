package server

import "testing"

func TestConnLimiter(t *testing.T) {
	c := newConnLimiter(2)

	for i := 0; i < 2; i++ {
		if !c.acquire("a") {
			t.Fatalf("acquire() #%d should succeed up to the limit", i+1)
		}
	}
	if c.acquire("a") {
		t.Error("acquire() should fail at the limit")
	}
	if !c.acquire("b") {
		t.Error("keys should be limited independently")
	}

	c.release("a")
	if !c.acquire("a") {
		t.Error("acquire() should succeed after release")
	}

	c.release("a")
	c.release("a")
	c.release("b")
	if len(c.counts) != 0 {
		t.Errorf("released keys should be removed, got %v", c.counts)
	}
}
