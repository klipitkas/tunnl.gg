package server

import "testing"

func TestConnLimiter(t *testing.T) {
	c := newConnLimiter(2)

	if !c.acquire("a") || !c.acquire("a") {
		t.Fatal("acquire() should succeed up to the limit")
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
