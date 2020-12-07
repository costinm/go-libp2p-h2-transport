package h2transport

import (
	"fmt"
	"net"
	"net/url"

	mafmt "github.com/multiformats/go-multiaddr-fmt"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)

// WsFmt is multiaddr formatter for WsProtocol
var WsFmt = mafmt.And(mafmt.TCP, mafmt.Base(ma.P_HTTPS))

// WsCodec is the multiaddr-net codec definition for the websocket transport
var WsCodec = &manet.NetCodec{
	NetAddrNetworks:  []string{"h2"},
	ProtocolName:     "h2",
	ConvertMultiaddr: ConvertWebsocketMultiaddrToNetAddr,
	ParseNetAddr:     ParseWebsocketNetAddr,
}

// This is _not_ WsFmt because we want the transport to stick to dialing fully
// resolved addresses.
var dialMatcher = mafmt.And(mafmt.IP, mafmt.Base(ma.P_TCP), mafmt.Base(ma.P_HTTPS))

func init() {
	manet.RegisterNetCodec(WsCodec)

	ma.AddProtocol(ma.Protocol{
		Name:  "h2",
		Code:  ma.P_HTTPS,
		VCode: ma.CodeToVarint(ma.P_HTTPS),
	})
}

// Addr is an implementation of net.Addr for WebSocket.
type Addr struct {
	*url.URL
}

var _ net.Addr = (*Addr)(nil)
var wsMA ma.Multiaddr

func init() {
	var err error
	wsMA, err = ma.NewMultiaddr("/ws")
	if err != nil {
		panic(err)
	}
}

// Network returns the network type for a WebSocket, "websocket".
func (addr *Addr) Network() string {
	return "ws"
}

// NewAddr creates a new Addr using the given host string
func NewAddr(host string) *Addr {
	return &Addr{
		URL: &url.URL{
			Host: host,
		},
	}
}

func ConvertWebsocketMultiaddrToNetAddr(maddr ma.Multiaddr) (net.Addr, error) {
	_, host, err := manet.DialArgs(maddr)
	if err != nil {
		return nil, err
	}

	return NewAddr(host), nil
}

func ParseWebsocketNetAddr(a net.Addr) (ma.Multiaddr, error) {
	wsa, ok := a.(*Addr)
	if !ok {
		return nil, fmt.Errorf("not a websocket address")
	}

	tcpaddr, err := net.ResolveTCPAddr("tcp", wsa.Host)
	if err != nil {
		return nil, err
	}

	tcpma, err := manet.FromNetAddr(tcpaddr)
	if err != nil {
		return nil, err
	}

	wsma, err := ma.NewMultiaddr("/h2")
	if err != nil {
		return nil, err
	}

	return tcpma.Encapsulate(wsma), nil
}

func parseMultiaddr(a ma.Multiaddr) (string, error) {
		_, host, err := manet.DialArgs(a)
		if err != nil {
			return "", err
		}

		return "https://" + host, nil
}
