package server

import "sync"

const proxyBufferSize = 32 * 1024

// ReverseProxy otherwise allocates a new 32 KiB copy buffer for every response.
// Share idle buffers across tunnels; sync.Pool lets the runtime reclaim them.
// Only bytes returned by Read are forwarded, so contents from a previous
// response cannot be sent to another visitor.
type proxyBufferPool struct {
	pool sync.Pool
}

func (p *proxyBufferPool) Get() []byte {
	if b, ok := p.pool.Get().(*[proxyBufferSize]byte); ok {
		return b[:]
	}
	return make([]byte, proxyBufferSize)
}

func (p *proxyBufferPool) Put(b []byte) {
	if cap(b) == proxyBufferSize {
		p.pool.Put((*[proxyBufferSize]byte)(b[:proxyBufferSize]))
	}
}

var responseBuffers proxyBufferPool
