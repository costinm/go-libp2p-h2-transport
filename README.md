# go-libp2p-h2-transport

HTTP/2 based transport, using libp2p interfaces.

The primary goal is compatibility with standards and existing infrastructure, including external load balancers.
The transport can listen on 'https', using real or self-signed certificates. The server may be started in the
calling app - the transport will only act as a POST handler.

It is also possible to start in plain text mode, with an external proxy handling TLS or mTLS.

In either case, the transport will get a HTTP/2 POST request, creating a binary stream that is upgraded with a
normal TLS+H2. This is 'http/2 over http/2' - with the external http/2 not trusted, used only to create a stream.


- TODO: if the infrastructure doesn't support H2 POST, fallback to http/2-over-websocket.

- TODO: support CONNECT as well (Istio-like)

- TODO: if the HTTP/2 connection is using the node identity (cert) and is authenticated with mTLS (or JWT in future),
a H2 MUX will be configured.

In the 'ideal' case, the host will use the identity with mTLS or JWT on the outer HTTP/2, avoiding the second http/2.
This is only posible if the transport is directly accepting - regular HTTP/2 does not allow 'reverse' connections.

The code violates (or extends) to the HTTP/2 standard, which only allow server-originated PUSH without a client strea - instead
is using the same model as QUIC and libp2p where both sides can start streams.
The docker/spdystream library is used - x/net doesn't seem to allow this.
