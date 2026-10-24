package vens

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func response(size int) []byte {
	p := make([]byte, size)
	binary.BigEndian.PutUint32(p, uint32(size))
	copy(p[4:8], []byte("VENS"))
	return p
}
func receiveRequest(c net.Conn) error {
	var length [4]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(length[:])
	_, err := io.CopyN(io.Discard, c, int64(size)-4)
	return err
}
func TestTerminalWaitNeedsCleanStatusAndFullSense(t *testing.T) {
	for _, kind := range []string{"clean", "jam", "short-sense", "unknown-wait"} {
		t.Run(kind, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				status := response(48)
				binary.BigEndian.PutUint32(status[40:], ADFPaperMask)
				if receiveRequest(server) != nil {
					return
				}
				server.Write(status)
				if receiveRequest(server) != nil {
					return
				}
				wait := response(40)
				binary.BigEndian.PutUint32(wait[12:], 2)
				if kind == "unknown-wait" {
					binary.BigEndian.PutUint32(wait[12:], 7)
				}
				server.Write(wait)
				if kind == "unknown-wait" {
					return
				}
				if receiveRequest(server) != nil {
					return
				}
				if kind == "jam" {
					binary.BigEndian.PutUint32(status[44:], 1)
				}
				server.Write(status)
				if kind == "jam" {
					return
				}
				if receiveRequest(server) != nil {
					return
				}
				sense := response(58)
				sense[40] = 0x70
				sense[47] = 10
				if kind == "short-sense" {
					sense = response(40)
				}
				server.Write(sense)
			}()
			s := &ScanSession{conn: client, physicalSheet: 3, sidesPerSheet: 1}
			_, err := s.NextPage()
			if kind == "clean" {
				if err != io.EOF {
					t.Fatal(err)
				}
			} else if err == nil || err == io.EOF {
				t.Fatal("ambiguous end accepted", kind, err)
			}
		})
	}
}
func TestOversizedVENSResponseRejectedBeforeAllocation(t *testing.T) {
	if _, err := readResponse(bytes.NewReader([]byte{255, 255, 255, 255})); err == nil {
		t.Fatal("unbounded response")
	}
}
