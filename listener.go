package h2transport

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
)

type listener struct {
	l net.Listener

	addr  net.Addr
	laddr ma.Multiaddr

	closed   chan struct{}
	incoming chan *Conn
	t        *H2Transport
}

func (l *listener) Close() error {
	if l.l != nil {
		return l.l.Close()
	}
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.addr
}

func (l *listener) serve() {
	if l.l == nil {
		return
	}
	defer close(l.closed)
	_ = http.Serve(l.l, l)
}

func (l *listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// The upgrader writes a response for us.
		return
	}

	select {
	case l.incoming <- NewConn(c):
	case <-l.closed:
		c.Close()
	}
	// The connection has been hijacked, it's safe to return.
}

func (l *listener) Accept() (transport.CapableConn, error) {
	select {
	case c, ok := <-l.incoming:
		if !ok {
			return nil, fmt.Errorf("listener is closed")
		}
		return l.t.NewCapableConn(context.Background(), c, true, "")
	case <-l.closed:
		return nil, fmt.Errorf("listener is closed")
	}
}

func (l *listener) Multiaddr() ma.Multiaddr {
	return l.laddr
}
