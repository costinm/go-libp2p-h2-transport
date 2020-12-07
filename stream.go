package h2transport

import (
	"net"
	"time"

	"github.com/docker/spdystream"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/protocol"
)


// Implements MuxedStream AND net.Conn
// Also implements ssh.Channel - add SendRequest and Stderr, as well as CloseWrite
type stream struct {
	spdystream *spdystream.Stream
	stat network.Stat
	con *SPDYConn
}

func (s *stream) CloseWrite() error {
	return s.Close()
}

func (s *stream) CloseRead() error {
	return s.Close()
}

func (s *stream) spdyStream() *spdystream.Stream {
	return s.spdystream
}

func (s *stream) Read(buf []byte) (int, error) {
	return s.spdyStream().Read(buf)
}

func (s *stream) Write(buf []byte) (int, error) {
	return s.spdyStream().Write(buf)
}

func (s *stream) Close() error {
	// Reset is spdystream's full bidirectional close.
	// We expose bidirectional close as our `Close`.
	// To close only half of the connection, and use other
	// spdystream options, just get the stream with:
	//  ssStream := (*ss.Stream)(stream)
	return s.spdyStream().Close()
}

func (s *stream) Reset() error {
	return s.spdyStream().Reset()
}

func (s *stream) SetDeadline(t time.Time) error {
	return s.spdystream.SetDeadline(t)
}

func (s *stream) SetReadDeadline(t time.Time) error {
	return s.spdystream.SetReadDeadline(t)
}

func (s *stream) SetWriteDeadline(t time.Time) error {
	return s.spdystream.SetWriteDeadline(t)
}


// net.Conn only
func (c *stream) LocalAddr() net.Addr {
	// MultiAddr doesn't implement 'Network', and the format is not
	// portable.
	return c.con.wsCon.LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.con.wsCon.RemoteAddr()
}

func (c *stream) Stat() network.Stat {
	return c.stat
}

func (c *stream) Conn() network.Conn {
	return c.con
}

func (c *stream) Protocol() protocol.ID {
	return ""
}

func (c *stream) ID() string {
	return ""
}

func (c *stream) SetProtocol(id protocol.ID) {
}


