package h2transport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"

	ci "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

// Forked from go-libp2p-tls/transport.go

// TLS 1.3 is opt-in in Go 1.12
// Activate it by setting the tls13 GODEBUG flag.
func init() {
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")
}


// SecureInbound runs the TLS handshake as a server.
func (c *SPDYConn) SecureInbound(ctx context.Context, insecure net.Conn) (*tls.Conn, error) {
	config, keyCh := c.t.ConfigForAny()
	cs, err := c.handshake(ctx, tls.Server(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

// SecureOutbound runs the TLS handshake as a client.
// Note that SecureOutbound will not return an error if the server doesn't
// accept the certificate. This is due to the fact that in TLS 1.3, the client
// sends its certificate and the ClientFinished in the same flight, and can send
// application data immediately afterwards.
// If the handshake fails, the server will close the connection. The client will
// notice this after 1 RTT when calling Read.
func (t *SPDYConn) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (*tls.Conn, error) {
	config, keyCh := t.t.ConfigForPeer(p)
	cs, err := t.handshake(ctx, tls.Client(insecure, config), keyCh)
	if err != nil {
		insecure.Close()
	}
	return cs, err
}

func (t *SPDYConn) handshake(
	ctx context.Context,
	tlsConn *tls.Conn,
	keyCh <-chan ci.PubKey,
) (*tls.Conn, error) {
	t.tls = tlsConn

	// There's no way to pass a context to tls.Conn.Handshake().
	// See https://github.com/golang/go/issues/18482.
	// Close the connection instead.
	select {
	case <-ctx.Done():
		tlsConn.Close()
	default:
	}

	done := make(chan struct{})
	var wg sync.WaitGroup

	// Ensure that we do not return before
	// either being done or having a context
	// cancellation.
	defer wg.Wait()
	defer close(done)

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-done:
		case <-ctx.Done():
			tlsConn.Close()
		}
	}()

	if err := tlsConn.Handshake(); err != nil {
		// if the context was canceled, return the context error
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}

	// Should be ready by this point, don't block.
	var remotePubKey ci.PubKey
	select {
	case remotePubKey = <-keyCh:
	default:
	}
	if remotePubKey == nil {
		return nil, errors.New("go-libp2p-tls BUG: expected remote pub key to be set")
	}

	t.remotePub = remotePubKey
	return tlsConn, nil
}
