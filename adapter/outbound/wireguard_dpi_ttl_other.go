//go:build !linux && !android

package outbound

import "net"

func writeWireGuardUDPWithTTL(
	_ *net.UDPConn,
	_ []byte,
	_ *net.UDPAddr,
	_ int,
) (int, error, bool) {
	return 0, nil, false
}
