# Contexts

We've separated out CONNECT vs Forward Proxy requests into their own context
processors. Having both sets of logic in the OpsiHTTPProxy itself cluttered
and confused the source code.

# Forward Request Context (Typically Used for Normal Requests)

A "normal" HTTP proxy request that isn't a CONNECT request is typically called a: "forward proxy request"

Forward proxy (non-CONNECT) request: A standard HTTP request like GET http://example.com/index.html HTTP/1.1, where the full URL is included in the request line (as opposed to just the path, like in origin servers).

# CONNECT/Tunnel (Typically Used With TLS/SSL)

A http proxy request that does use CONNECT is called a: "http tunneling request"

CONNECT request: Used to establish a tunnel, typically for HTTPS (e.g., CONNECT example.com:443 HTTP/1.1). After this, the proxy just forwards raw TCP bytes back and forth.
