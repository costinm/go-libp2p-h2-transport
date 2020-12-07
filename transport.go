package h2transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"net/http"

	"github.com/docker/spdystream"
	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
)


var _ transport.Transport = (*H2Transport)(nil)

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

func (t *H2Transport) CanDial(a ma.Multiaddr) bool {
	return dialMatcher.Matches(a)
}

func (t *H2Transport) Protocols() []int {
	return []int{ma.P_WS}
}

func (t *H2Transport) Proxy() bool {
	return false
}

// Dial creates a secure multiplexed CapableConn to the peer identified by a public key,
// using an address. The ID is derived from the proto-representation of the key - either
// SHA256 or the actual key if len <= 42
func (t *H2Transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {


	// Implemented in one of the WS libraries. Need to find the most efficient.
	return t.maDial(ctx, raddr, p)
}

func (t *H2Transport) Listen(a ma.Multiaddr) (transport.Listener, error) {
	ps := a.Protocols()
	if len(ps) < 3 {
		return nil, errors.New("Unexpected len of protocols")
	}
	lnet, lnaddr, err := manet.DialArgs(a)
	if err != nil {
		return nil, err
	}

	nl, err := net.Listen(lnet, lnaddr)
	if err != nil {
		return nil, err
	}
	laddr, err := manet.FromNetAddr(nl.Addr())
	if err != nil {
		return nil, err
	}


	malist := &listener {
		t: t,
		l: nl,
		incoming: make(chan *Conn),
		closed:   make(chan struct{}),
	}

	switch ps[2].Name {
	case "ws": {
		wsma, err := ma.NewMultiaddr("/ws")
		if err != nil {
			return nil, err
		}
		laddr = laddr.Encapsulate(wsma)
		malist.laddr = laddr


	}
	case "http": {
	}
	case "https": {
	}
	default:
		return nil, errors.New("Unexpected " + ps[2].Name)
	}

	go malist.serve()

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
		mnc, err = c.SecureInbound(ctx, unsec)
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

