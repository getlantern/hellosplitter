package hellosplitter

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
)

// TLS record types.
type recordType uint8

// Constants copied from crypto/tls.
const (
	// tcpMSSEstimate is a conservative estimate of the TCP maximum segment
	// size (MSS). A constant is used, rather than querying the kernel for
	// the actual MSS, to avoid complexity. The value here is the IPv6
	// minimum MTU (1280 bytes) minus the overhead of an IPv6 header (40
	// bytes) and a TCP header with timestamps (32 bytes).
	tcpMSSEstimate = 1208

	maxPlaintext       = 16384        // maximum plaintext payload length
	maxCiphertext      = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13 = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen    = 5            // record header length
	maxHandshake       = 65536        // maximum handshake we support (protocol max is 16 MB)

	recordTypeChangeCipherSpec recordType = 20
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

func readRecord(
	r io.Reader, buf *bytes.Buffer, cs *connectionState,
	secret [52]byte, iv [16]byte, expectedType recordType) ([]byte, int, error) {

	n64, err := readFromUntil(r, buf, recordHeaderLen)
	n := int(n64)
	if err != nil {
		// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
		// is an error, but popular web sites seem to do this, so we accept it
		// if and only if at the record boundary.
		if err == io.ErrUnexpectedEOF && buf.Len() == 0 {
			err = io.EOF
		}
		return nil, n, err
	}

	hdr := buf.Bytes()[:recordHeaderLen]
	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	payloadLen := int(hdr[3])<<8 | int(hdr[4])
	if cs.version != tls.VersionTLS13 && vers != cs.version {
		return nil, n, fmt.Errorf("received record with version %x when expecting version %x", vers, cs.version)
	}
	if cs.version == tls.VersionTLS13 && payloadLen > maxCiphertextTLS13 || payloadLen > maxCiphertext {
		return nil, n, fmt.Errorf("oversized record received with length %d", payloadLen)
	}
	n64, err = readFromUntil(r, buf, recordHeaderLen+payloadLen)
	n += int(n64)
	if err != nil {
		return nil, n, err
	}

	// Process message.
	cipher, mac := cs.cipherSuite.getCipher(secret, iv, true, cs.version)
	data, typ, err := cs.decrypt(buf.Next(recordHeaderLen+payloadLen), cipher, mac)
	if err != nil {
		return nil, n, &net.OpError{Op: "local error", Err: err}
	}
	if len(data) > maxPlaintext {
		return nil, n, &net.OpError{Op: "local error", Err: errors.New("record overflow")}
	}

	if typ != expectedType {
		return nil, n, fmt.Errorf("unexpected record type: %d (expected %d)", typ, expectedType)
	}
	// Application Data messages are always protected.
	if cipher == nil && typ == recordTypeApplicationData {
		return nil, n, &net.OpError{Op: "local error", Err: errors.New("unexpected message")}
	}

	return data, n, nil
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func readFromUntil(r io.Reader, buf *bytes.Buffer, n int) (int64, error) {
	if buf.Len() >= n {
		return 0, nil
	}
	needs := n - buf.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	buf.Grow(needs + bytes.MinRead)
	return buf.ReadFrom(&atLeastReader{r, int64(needs)})
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}
