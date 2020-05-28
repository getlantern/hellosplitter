package hellosplitter

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
)

func Example() {
	s, err := startTLSHandshakeServer()
	if err != nil {
		panic(err)
	}
	tcpConn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		panic(err)
	}
	tcpConn = Wrap(tcpConn, func(b []byte) [][]byte {
		splits := make([][]byte, 2)
		splits[0], splits[1] = b[:len(b)/2], b[len(b)/2:]
		return splits
	})
	tlsConn := tls.Client(tcpConn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		panic(err)
	}
}

// Conducts a handshake with any incoming TLS client connections.
type tlsHandshakeServer struct {
	l net.Listener
}

func startTLSHandshakeServer() (*tlsHandshakeServer, error) {
	l, err := tls.Listen("tcp", "", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		return nil, fmt.Errorf("failed to start TLS listener: %w", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				fmt.Fprintln(os.Stderr, "server: accept error:", err)
				return
			}
			if err := conn.(*tls.Conn).Handshake(); err != nil {
				fmt.Fprintln(os.Stderr, "server: handshake error:", err)
			}
			conn.Close()
		}
	}()
	return &tlsHandshakeServer{l}, nil
}

func (ths tlsHandshakeServer) Addr() string {
	return ths.l.Addr().String()
}

func (ths tlsHandshakeServer) Close() error {
	return ths.l.Close()
}

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}
