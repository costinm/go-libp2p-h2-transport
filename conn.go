package h2transport

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/docker/spdystream"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// StreamQueueLen is the length of the stream queue.
const StreamQueueLen = 10
// errClosed is returned when trying to accept a stream from a closed connection
var errClosed = errors.New("conn closed")

// Conn is a connection to a remote peer,
// implements CapableConn (	MuxedConn, network.ConnSecurity, network.ConnMultiaddrs
// Transport())
//
// implements MuxedConn (OpenStream/AcceptStream, Close/IsClosed)
type SPDYConn struct {
	sc *spdystream.Connection

	streamQueue chan *spdystream.Stream

	closed chan struct{}

	// Original con, with remote/local addr
	wsCon     net.Conn
	tls *tls.Conn

	LastSeen    time.Time
	ConnectTime time.Time

	// Includes the private key of this node
	t         *H2Transport // transport.Transport

	remotePub ic.PubKey

	stat network.Stat

}


func (c *SPDYConn) spdyConn() *spdystream.Connection {
	return c.sc
}

func (c *SPDYConn) Close() error {
	err := c.spdyConn().CloseWait()
	if !c.IsClosed() {
		close(c.closed)
	}
	return err
}

func (c *SPDYConn) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	case <-c.sc.CloseChan():
		return true
	default:
		return false
	}
}

// OpenStream creates a new stream.
func (c *SPDYConn) OpenStream() (mux.MuxedStream, error) {
	s, err := c.spdyConn().CreateStream(http.Header{
		":method": []string{"POST"},
		":path":   []string{"/"},
	}, nil, false)
	if err != nil {
		return nil, err
	}

	// wait for a response before writing. for some reason
	// spdystream does not make forward progress unless you do this.
	s.Wait()
	return &stream{ spdystream: s, con: c}, nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *SPDYConn) AcceptStream() (mux.MuxedStream, error) {
	if c.IsClosed() {
		return nil, errClosed
	}

	select {
	case <-c.closed:
		return nil, errClosed
	case <-c.sc.CloseChan():
		return nil, errClosed
	case s := <-c.streamQueue:
		return &stream{ spdystream: s, con: c}, nil
	}
}

// serve accepts incoming streams and places them in the streamQueue
func (c *SPDYConn) serve() {
	c.spdyConn().Serve(func(s *spdystream.Stream) {
		// Flow control and backpressure of Opening streams is broken.
		// I believe that spdystream has one set of workers that both send
		// data AND accept new streams (as it's just more data). there
		// is a problem where if the new stream handlers want to throttle,
		// they also eliminate the ability to read/write data, which makes
		// forward-progress impossible. Thus, throttling this function is
		// -- at this moment -- not the solution. Either spdystream must
		// change, or we must throttle another way. go-peerstream handles
		// every new stream in its own goroutine.
		err := s.SendReply(http.Header{
			":status": []string{"200"},
		}, false)
		if err != nil {
			// this _could_ error out. not sure how to handle this failure.
			// don't return, and let the caller handle a broken stream.
			// better than _hiding_ an error.
			// return
		}
		c.streamQueue <- s
	})
}

func (c *SPDYConn) LocalPeer() peer.ID {
	p, _ := peer.IDFromPrivateKey(c.t.Key)
	return p
}

func (c *SPDYConn) LocalPrivateKey() ic.PrivKey {
	return c.t.Key
}

func (c *SPDYConn) RemotePeer() peer.ID {
	p, _ := peer.IDFromPublicKey(c.RemotePublicKey())
	return p
}

func (c *SPDYConn) RemotePublicKey() ic.PubKey {
	//c.tls.ConnectionState().PeerCertificates
	return c.remotePub
}

func (c *SPDYConn) LocalMultiaddr() ma.Multiaddr {
	r, _ := manet.FromNetAddr(c.wsCon.LocalAddr())
	return r
}

func (c *SPDYConn) RemoteMultiaddr() ma.Multiaddr {
	udpMA, err := manet.FromNetAddr(c.wsCon.RemoteAddr())
	if err != nil {
		return nil
	}
	//r, _ := manet.FromNetAddr(c.wsCon.RemoteAddr())
	udpMA = udpMA.Encapsulate(wsMA)
	return udpMA
}

func (c *SPDYConn) Transport() transport.Transport {
	return c.t
}

// The transport can also implements directly the network.Conn

func (c *SPDYConn) ID() string {
	return ""
}

func (c *SPDYConn) GetStreams() []network.Stream {
	return nil
}

// Replaces/uses OpenStream used in transport MuxedStream.
func (c *SPDYConn) NewStream() (network.Stream, error) {
	return nil, nil
}

// Return Stat directly - for metadata.
func (c *SPDYConn) Stat() network.Stat {
	return c.stat
}
