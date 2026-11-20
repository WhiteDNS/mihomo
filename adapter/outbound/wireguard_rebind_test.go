package outbound

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

// A WireGuard socket opened before Android's VPN protector exists must be replaced after
// RebindWireGuardOutbounds, so the peer sees handshakes from a new source port.
func TestRebindWireGuardOutboundsOpensNewSocket(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	var mu sync.Mutex
	ports := map[int]bool{}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := server.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			ports[from.Port] = true
			mu.Unlock()
		}
	}()
	seen := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(ports)
	}
	key := func() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}

	w, err := NewWireGuard(WireGuardOption{
		Name:       "rebind-test",
		Ip:         "10.7.0.2",
		PrivateKey: key(),
		MTU:        1280,
		WireGuardPeerOption: WireGuardPeerOption{
			Server:    "127.0.0.1",
			Port:      server.LocalAddr().(*net.UDPAddr).Port,
			PublicKey: key(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Keep generating traffic until the peer sees a handshake; a single short dial can end
	// before the userspace stack emits its first packet on a loaded machine.
	waitFor := func(want int) bool {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, _ = w.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 80})
			cancel()
			if seen() >= want {
				return true
			}
		}
		return false
	}

	if !waitFor(1) {
		t.Fatal("no handshake reached the peer")
	}
	RebindWireGuardOutbounds()
	if !waitFor(2) {
		t.Fatalf("handshakes still come from %d source port(s); the socket was not reopened", seen())
	}
}
