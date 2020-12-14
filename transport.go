package h2transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/docker/spdystream"
	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	n "github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/soheilhy/cmux"
	"golang.org/x/net/http2"
)


var _ transport.Transport = (*H2Transport)(nil)

var ports = map[string]*PortListeners{}

type PortListeners struct {
	l    net.Listener
	m    cmux.CMux
	grpc net.Listener
	http net.Listener
	h2   net.Listener
	tls  net.Listener
	ws   net.Listener
}

// WsFmt is multiaddr formatter for WsProtocol
var WsFmt = mafmt.And(mafmt.TCP, mafmt.Base(ma.P_HTTPS))

func init() {
	// Multi-address protocol for H2.
	ma.AddProtocol(ma.Protocol{
		Name:  "h2",
		Code:  ma.P_HTTPS,
		VCode: ma.CodeToVarint(ma.P_HTTPS),
	})
}

// Start the cmuxListen on the port.
// Will create multiple listeners depending on detection.
func (p *PortListeners) cmuxListen(port string) error {
	l, err := net.Listen("tcp", port)
	if err != nil {
		return err
	}
	p.l = l

	p.m = cmux.New(l)

	p.grpc = p.m.Match(cmux.HTTP2HeaderField("content-type", "application/grpc"))
	p.ws = p.m.Match(cmux.PrefixMatcher("CONNECT"))
	p.http = p.m.Match(cmux.HTTP1Fast())
	p.h2 = p.m.Match(cmux.HTTP2())

	p.tls = p.m.Match(cmux.TLS())

	go p.m.Serve()

	return nil
}

func portMux(port string) (*PortListeners, error) {
	p := ports[port]
	if p != nil {
		return p, nil
	}

	p = &PortListeners{}
	err := p.cmuxListen(port)
	if err != nil {
		return nil, err
	}
	ports[port] = p
	return p, nil
}

// H2Transport implements libp2p Transport.
// It also implements http.Handler, and can be registered with a HTTP/2 or HTTP/1 server.
// For HTTP/1 it will use websocket, with standard TLS and SPDY for crypto or mux.
// For HTTP/2 it will the normal connection if mTLS was negotiated.
// Otherwise will do a TLS+SPDY handshake for the POST method.
type H2Transport struct {
	Prefix string
	Mux    *http.ServeMux

	Gater     connmgr.ConnectionGater
	Psk       pnet.PSK
	Key       ic.PrivKey
	localPeer peer.ID
	config tls.Config
}

func NewH2Transport(key ic.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater) (*H2Transport, error) {
	id, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}

	cert, err := keyToCertificate(key)
	if err != nil {
		return nil, err
	}

	return &H2Transport{
		Key: key,
		localPeer: id,
		config: tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: preferServerCipherSuites(),
			InsecureSkipVerify:       true, // This is not insecure here. We will verify the cert chain ourselves.
			ClientAuth:               tls.RequireAnyClientCert,
			Certificates:             []tls.Certificate{*cert},
			VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
				panic("tls config not specialized for peer")
			},
			NextProtos:             []string{alpn},
			SessionTicketsDisabled: true,
		},
		Psk: psk,
		Gater: gater,
	}, nil
}

// This is _not_ WsFmt because we want the transport to stick to dialing fully
// resolved addresses.
var dialMatcherHttps = mafmt.And(mafmt.IP, mafmt.Base(ma.P_TCP),
	mafmt.Base(ma.P_HTTPS))
var dialMatcherWS = mafmt.And(mafmt.IP, mafmt.Base(ma.P_TCP),
	mafmt.Base(ma.P_WS))

func (t *H2Transport) CanDial(a ma.Multiaddr) bool {
	return dialMatcherHttps.Matches(a) || dialMatcherWS.Matches(a)
}

// Returns the list of protocol codes handled by this transport, using the int code
// from the registry.
func (t *H2Transport) Protocols() []int {
	return []int{ma.P_WS, ma.P_HTTPS}
}

// True for relay - currently not implemented.
func (t *H2Transport) Proxy() bool {
	return false
}

// Dial creates a secure multiplexed CapableConn to the peer identified by a public key,
// using an address. The ID is derived from the proto-representation of the key - either
// SHA256 or the actual key if len <= 42
func (t *H2Transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	ps := raddr.Protocols()
	if len(ps) < 3 {
		return nil, errors.New("Unexpected len of protocols")
	}


	// Implemented in one of the WS libraries. Need to find the most efficient.
	cc, err := t.wsDial(ctx, raddr, p)
	if err != nil {
		return nil, err
	}
	if t.Gater != nil && !t.Gater.InterceptSecured(n.DirOutbound, p, cc) {
		cc.Close()
		return nil, fmt.Errorf("secured connection gated")
	}

	return cc, err
}

func (t *H2Transport) Listen(a ma.Multiaddr) (transport.Listener, error) {
	ps := a.Protocols()
	if len(ps) < 3 {
		return nil, errors.New("Unexpected len of protocols")
	}
	_, lnaddr, err := manet.DialArgs(a)
	if err != nil {
		return nil, err
	}

	pmux, err := portMux(lnaddr)

	if err != nil {
		return nil, err
	}

	laddr, err := manet.FromNetAddr(pmux.l.Addr())
	if err != nil {
		return nil, err
	}


	malist := &listener {
		t: t,
		incoming: make(chan transport.CapableConn),
		closed:   make(chan struct{}),
	}

	switch ps[2].Name {
	case "ws": {
		malist.l = pmux.ws
		wsma, err := ma.NewMultiaddr("/ws")
		if err != nil {
			return nil, err
		}
		laddr = laddr.Encapsulate(wsma)
		malist.laddr = laddr
		go func() {
			defer close(malist.closed)
			_ = http.Serve(malist.l, malist)
		}()

	}
	case "http": {
		malist.l = pmux.h2
		wsma, err := ma.NewMultiaddr("/http")
		if err != nil {
			return nil, err
		}
		laddr = laddr.Encapsulate(wsma)
		malist.laddr = laddr
		go func() {
			conn, err := malist.l.Accept()
			if err != nil {
				return
			}

			h2Server := &http2.Server{}
			go h2Server.ServeConn(
				conn,
				&http2.ServeConnOpts{
					Handler: malist})
		}()

	}
	case "https": {
		malist.l = pmux.tls
		wsma, err := ma.NewMultiaddr("/https")
		if err != nil {
			return nil, err
		}
		laddr = laddr.Encapsulate(wsma)
		malist.laddr = laddr
		go func() {
			conn, err := malist.l.Accept()
			if err != nil {
				return
			}

			go func() {

				h2Server := &http2.Server{}
				h2Server.ServeConn(
					conn, //&FakeTLSConn{conn},
					&http2.ServeConnOpts{
						Handler: malist})
			}()
		}()
	}
	default:
		return nil, errors.New("Unexpected " + ps[2].Name)
	}

	return malist, nil
}

func (t *H2Transport) NewCapableConn(ctx context.Context, unsec net.Conn, isServer bool, p peer.ID) (*SPDYConn, error) {
	c := &SPDYConn{
		closed: make(chan struct{}),
		t: t,
		wsCon: unsec,
	}
	var mnc *tls.Conn
	var err error
	if isServer {
		mnc, err = t.SecureInbound(ctx, c, unsec)
		if err != nil {
			return nil, err
		}
	} else {
		mnc, err = c.SecureOutbound(ctx, unsec, p)
		if err != nil {
			return nil, err
		}
	}
	sc, err := spdystream.NewConnection(mnc, isServer)
	if err != nil {
		return nil, err
	}
	c.sc = sc

	c.streamQueue = make(chan *spdystream.Stream, StreamQueueLen)
	go c.serve()
	return c, nil
}


var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

const (
	nameTypeEmail = 1
	nameTypeDNS   = 2
	nameTypeURI   = 6
	nameTypeIP    = 7
)

func getSANExtension(c *x509.Certificate) []byte {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtensionSubjectAltName) {
			return e.Value
		}
	}
	return nil
}

func GetSAN(c *x509.Certificate) ([]string, error) {
	extension := getSANExtension(c)
	dns := []string{}
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return dns, err
	} else if len(rest) != 0 {
		return dns, errors.New("x509: trailing data after X.509 extension")
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return dns, asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return dns, err
		}

		if v.Tag == nameTypeDNS {
			dns = append(dns, string(v.Bytes))
		}
	}
	return dns, nil
}

