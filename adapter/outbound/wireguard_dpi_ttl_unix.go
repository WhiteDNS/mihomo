//go:build linux || android

package outbound

import (
	"net"
	"syscall"
	"unsafe"
)

func writeWireGuardUDPWithTTL(
	connection *net.UDPConn,
	payload []byte,
	destination *net.UDPAddr,
	ttl int,
) (int, error, bool) {
	remote := destination
	if remote == nil {
		remote, _ = connection.RemoteAddr().(*net.UDPAddr)
	}
	if remote == nil || ttl < 1 || ttl > 255 {
		return 0, nil, false
	}

	control := make([]byte, syscall.CmsgSpace(4))
	header := (*syscall.Cmsghdr)(unsafe.Pointer(&control[0]))
	if remote.IP.To4() == nil {
		header.Level = syscall.IPPROTO_IPV6
		header.Type = syscall.IPV6_HOPLIMIT
	} else {
		header.Level = syscall.IPPROTO_IP
		header.Type = syscall.IP_TTL
	}
	header.SetLen(syscall.CmsgLen(4))
	*(*int32)(unsafe.Pointer(&control[syscall.CmsgLen(0)])) = int32(ttl)
	n, _, err := connection.WriteMsgUDP(payload, control, destination)
	return n, err, true
}
