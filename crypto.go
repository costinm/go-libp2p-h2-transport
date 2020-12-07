package h2transport

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"

	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/sys/cpu"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
)

// Forked from go-libp2p-tls:
// - use normal SANs
// - use normal ALPN (H2)
// - not used with upgrader or ipfs negotiation - using standard protocols
//


const certValidityPeriod = 100 * 365 * 24 * time.Hour // ~100 years
const alpn string = "libp2p"

// ConfigForAny is a short-hand for ConfigForPeer("").
func (i *H2Transport) ConfigForAny() (*tls.Config, <-chan ic.PubKey) {
	return i.ConfigForPeer("")
}

// ConfigForPeer creates a new single-use tls.Config that verifies the peer's
// certificate chain and returns the peer's public key via the channel. If the
// peer ID is empty, the returned config will accept any peer.
//
// It should be used to create a new tls.Config before securing either an
// incoming or outgoing connection.
func (i *H2Transport) ConfigForPeer(remote peer.ID) (*tls.Config, <-chan ic.PubKey) {
	keyCh := make(chan ic.PubKey, 1)
	// We need to check the peer ID in the VerifyPeerCertificate callback.
	// The tls.Config it is also used for listening, and we might also have concurrent dials.
	// Clone it so we can check for the specific peer ID we're dialing here.
	conf := i.config.Clone()
	// We're using InsecureSkipVerify, so the verifiedChains parameter will always be empty.
	// We need to parse the certificates ourselves from the raw certs.
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		defer close(keyCh)

		chain := make([]*x509.Certificate, len(rawCerts))
		for i := 0; i < len(rawCerts); i++ {
			cert, err := x509.ParseCertificate(rawCerts[i])
			if err != nil {
				return err
			}
			chain[i] = cert
		}

		pubKey, err := PubKeyFromCertChain(chain)
		if err != nil {
			return err
		}
		if remote != "" && !remote.MatchesPublicKey(pubKey) {
			return errors.New("peer IDs don't match")
		}
		keyCh <- pubKey
		return nil
	}
	return conf, keyCh
}

// PubKeyFromCertChain verifies the certificate chain and extract the remote's public key.
func PubKeyFromCertChain(chain []*x509.Certificate) (ic.PubKey, error) {
	//if len(chain) != 1 {
  //		return nil, errors.New("expected one certificates in the chain")
	//}
	cert := chain[0]

	// Self-signed certificate
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		// If we return an x509 error here, it will be sent on the wire.
		// Wrap the error to avoid that.
		return nil, fmt.Errorf("certificate verification failed: %s", err)
	}

	// IPFS uses a key embedded in a custom extension, and verifies the public key of the cert is signed
	// with the node public key
	key := cert.PublicKey
	if ec, ok := key.(*ecdsa.PublicKey); ok {
		// starts with 0x04 == uncompressed curve
		//pubbytes := elliptic.Marshal(ec.Curve, ec.X, ec.Y)
		// ipfs expects PKIX/ASN1
		pubbytes, _ := x509.MarshalPKIXPublicKey(ec)
		return ic.UnmarshalECDSAPublicKey(pubbytes)
	}
	if rsak, ok := key.(*rsa.PublicKey); ok {
		pubbytes := x509.MarshalPKCS1PublicKey(rsak)
		return ic.UnmarshalRsaPublicKey(pubbytes)
	}
	if ed, ok := key.(ed25519.PublicKey); ok {
		//return []byte(ed)
		return ic.UnmarshalEd25519PublicKey(ed)
	}

	return nil, errors.New("Unknown public key")
}

func keyToCertificate(sk ic.PrivKey) (*tls.Certificate, error) {
	//certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//if err != nil {
	//	return nil, err
	//}


	keyBytes, err := sk.Raw()
	if err != nil {
		return nil, err
	}

	certKey := ed25519.PrivateKey(keyBytes)

	//certKeyPub, err := x509.MarshalPKIXPublicKey(certKey.Public())
	//if err != nil {
	//	return nil, err
	//}
	//signature, err := sk.Sign(append([]byte(certificatePrefix), certKeyPub...))
	//if err != nil {
	//	return nil, err
	//}
	//value, err := asn1.Marshal(signedKey{
	//	PubKey:    keyBytes,
	//	Signature: signature,
	//})
	//if err != nil {
	//	return nil, err
	//}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		NotBefore:    time.Time{},
		NotAfter:     time.Now().Add(certValidityPeriod),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, certKey.Public(), certKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}, nil
}

// We want nodes without AES hardware (e.g. ARM) support to always use ChaCha.
// Only if both nodes have AES hardware support (e.g. x86), AES should be used.
// x86->x86: AES, ARM->x86: ChaCha, x86->ARM: ChaCha and ARM->ARM: Chacha
// This function returns true if we don't have AES hardware support, and false otherwise.
// Thus, ARM servers will always use their own cipher suite preferences (ChaCha first),
// and x86 servers will aways use the client's cipher suite preferences.
func preferServerCipherSuites() bool {
	// Copied from the Go TLS implementation.

	// Check the cpu flags for each platform that has optimized GCM implementations.
	// Worst case, these variables will just all be false.
	var (
		hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
		hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
		// Keep in sync with crypto/aes/cipher_s390x.go.
		hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

		hasGCMAsm = hasGCMAsmAMD64 || hasGCMAsmARM64 || hasGCMAsmS390X
	)
	return !hasGCMAsm
}
