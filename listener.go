package h2transport

import (
	"context"
	"fmt"
	"net"
	"net/http"

	n "github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
)

type listener struct {
	l net.Listener

	addr  net.Addr
	laddr ma.Multiaddr

	closed   chan struct{}
	incoming chan transport.CapableConn
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

func (l *listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// The upgrader writes a response for us.
		return
	}

	cc, err := l.t.NewCapableConn(context.Background(), NewConn(c), true, "")
	if err != nil {
		c.Close()
		return
	}
	select {
	case l.incoming <- cc:
		// WS connection sent to accept after handshake, to allow results.
	case <-l.closed:
		c.Close()
	}
	// The connection has been hijacked, it's safe to return.
}


func (l *listener) Accept() (transport.CapableConn, error) {
	for {
		select {
			case c, ok := <-l.incoming:

				if !ok {
					return nil, fmt.Errorf("listener is closed")
				}

				if l.t.Gater != nil && !(l.t.Gater.InterceptAccept(c) && l.t.Gater.InterceptSecured(n.DirInbound, c.RemotePeer(), c)) {
					c.Close()
					continue
				}
				return c, nil
			case <-l.closed:
				return nil, fmt.Errorf("listener is closed")
			}
		}
}


func (l *listener) Multiaddr() ma.Multiaddr {
	return l.laddr
}
