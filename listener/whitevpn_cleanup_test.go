package listener

import (
	"net"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
)

func TestWhiteVPNShutdownClosesPatchedSockets(t *testing.T) {
	for name, stop := range map[string]func(){"stop": StopListener, "shutdown": Cleanup} {
		t.Run(name, func(t *testing.T) {
			defer Cleanup()
			inbound, err := ParseListener(map[string]any{"name": "test", "type": "http", "listen": "127.0.0.1", "port": 0})
			if err != nil {
				t.Fatal(err)
			}
			PatchInboundListeners(map[string]C.InboundListener{"test": inbound}, nil, true)
			PatchTunnel([]LC.Tunnel{{Network: []string{"tcp", "udp"}, Address: "127.0.0.1:0", Target: "127.0.0.1:1", Proxy: "DIRECT"}}, nil)
			if len(inboundListeners) != 1 || len(tunnelTCPListeners) != 1 || len(tunnelUDPListeners) != 1 {
				t.Fatal("test sockets did not open")
			}
			var tcp, udp string
			for _, listener := range tunnelTCPListeners {
				tcp = listener.Address()
			}
			for _, listener := range tunnelUDPListeners {
				udp = listener.Address()
			}
			stop()
			if len(inboundListeners)+len(tunnelTCPListeners)+len(tunnelUDPListeners) != 0 {
				t.Fatal("listener retained after shutdown")
			}
			l, err := net.Listen("tcp", tcp)
			if err != nil {
				t.Fatal(err)
			}
			l.Close()
			p, err := net.ListenPacket("udp", udp)
			if err != nil {
				t.Fatal(err)
			}
			p.Close()
			stop() // Repeated stop must be safe.
		})
	}
}
