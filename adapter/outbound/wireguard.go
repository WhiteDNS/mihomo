package outbound

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/slowdown"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	amneziav3 "github.com/metacubex/amneziawg-go/device"
	amnezia "github.com/metacubex/amneziawg-go/device_v1"
	amneziaawg "github.com/metacubex/amneziawg-go/device_v1/awg"
	"github.com/metacubex/mipstack"
	wireguard "github.com/metacubex/sing-wireguard"
	wgconn "github.com/metacubex/wireguard-go/conn"
	"github.com/metacubex/wireguard-go/device"
	"github.com/metacubex/wireguard-go/tun"

	"github.com/metacubex/sing/common/debug"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	ipStackAuto   = "auto"
	ipStackGVisor = "gvisor"
	ipStackMips   = "mips"
)

type wireguardGoDevice interface {
	Close()
	IpcSet(uapiConf string) error
}

const (
	wireGuardHandshakeInitiationSize = 148
	maxWireGuardDPIFakeCount         = 20
	maxWireGuardDPIFakeSize          = 1280
	maxWireGuardDPIFakeTTL           = 255
	wireGuardDefaultDPIFakeTTL       = 3
)

type wireGuardDPIStrategy uint32

const (
	wireGuardDPIStrategyBurst wireGuardDPIStrategy = iota
	wireGuardDPIStrategyPairedDuplicates
	wireGuardDPIStrategyInterleavedDuplicates
	wireGuardDPIStrategyTTL
	wireGuardDPIStrategyCount
)

type wireGuardDPIBind struct {
	wgconn.Bind
	option    WireGuardDPIOption
	pattern   wireGuardInitiationPattern
	control   *wireGuardDPIWriteControl
	identity  string
	rotations map[string]uint32
	mutex     sync.Mutex
}

type WireGuardDPIOption struct {
	FakeCount   int `proxy:"fake-count,omitempty"`
	FakeMinSize int `proxy:"fake-min-size,omitempty"`
	FakeMaxSize int `proxy:"fake-max-size,omitempty"`
	FakeTTL     int `proxy:"fake-ttl,omitempty"`
}

type wireGuardInitiationPattern struct {
	size       int
	typeOffset int
	typeMin    uint32
	typeMax    uint32
}

type wireGuardDPIWriteControl struct {
	ttl int
}

type wireGuardDPIDialer struct {
	N.Dialer
	control *wireGuardDPIWriteControl
}

type wireGuardDPIUDPConn struct {
	*net.UDPConn
	control *wireGuardDPIWriteControl
}

var (
	_ wgconn.Bind    = (*wireGuardDPIBind)(nil)
	_ N.Dialer       = (*wireGuardDPIDialer)(nil)
	_ net.Conn       = (*wireGuardDPIUDPConn)(nil)
	_ net.PacketConn = (*wireGuardDPIUDPConn)(nil)
)

func (o WireGuardDPIOption) enabled() bool {
	return o.FakeCount != 0 || o.FakeMinSize != 0 || o.FakeMaxSize != 0 || o.FakeTTL != 0
}

func (o WireGuardDPIOption) validate() error {
	if o.FakeCount < 1 || o.FakeCount > maxWireGuardDPIFakeCount {
		return E.New("wireguard dpi fake-count must be between 1 and ", maxWireGuardDPIFakeCount)
	}
	if o.FakeMinSize < 1 || o.FakeMaxSize > maxWireGuardDPIFakeSize || o.FakeMinSize > o.FakeMaxSize {
		return E.New("wireguard dpi sizes must satisfy 1 <= fake-min-size <= fake-max-size <= ", maxWireGuardDPIFakeSize)
	}
	if o.FakeTTL < 0 || o.FakeTTL > maxWireGuardDPIFakeTTL {
		return E.New("wireguard dpi fake-ttl must be between 0 and ", maxWireGuardDPIFakeTTL)
	}
	return nil
}

func (p wireGuardInitiationPattern) matches(packet []byte) bool {
	if len(packet) != p.size || p.typeOffset < 0 || p.typeOffset+4 > len(packet) {
		return false
	}
	messageType := binary.LittleEndian.Uint32(packet[p.typeOffset : p.typeOffset+4])
	return messageType >= p.typeMin && messageType <= p.typeMax
}

func newWireGuardInitiationPattern(option *AmneziaWGOption) (wireGuardInitiationPattern, error) {
	pattern := wireGuardInitiationPattern{
		size:    wireGuardHandshakeInitiationSize,
		typeMin: 1,
		typeMax: 1,
	}
	if option == nil || !option.hasHandshakeChanges() {
		return pattern, nil
	}
	if option.S1 < 0 {
		return pattern, E.New("wireguard dpi cannot match a negative amnezia s1")
	}
	pattern.size += option.S1
	pattern.typeOffset = option.S1
	if option.H1 == "" {
		return pattern, nil
	}
	header, err := amneziaawg.ParseMagicHeader("h1", option.H1)
	if err != nil {
		return pattern, E.Cause(err, "parse amnezia h1 for wireguard dpi")
	}
	if header.Min > 4 {
		pattern.typeMin = header.Min
		pattern.typeMax = header.Max
	}
	return pattern, nil
}

func (b *wireGuardDPIBind) Send(bufs [][]byte, endpoint wgconn.Endpoint) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if len(bufs) != 1 || !b.pattern.matches(bufs[0]) {
		return b.send(bufs, endpoint, 0)
	}

	strategy := b.nextStrategy(endpoint)
	for _, fake := range b.fakePlan(strategy) {
		ttl := 0
		if strategy == wireGuardDPIStrategyTTL {
			ttl = b.option.FakeTTL
		}
		if err := b.send([][]byte{fake}, endpoint, ttl); err != nil {
			break
		}
	}
	// Every strategy is fail-open and leaves the authenticated packet untouched.
	return b.send(bufs, endpoint, 0)
}

func (b *wireGuardDPIBind) nextStrategy(endpoint wgconn.Endpoint) wireGuardDPIStrategy {
	endpointKey := ""
	if endpoint != nil {
		endpointKey = endpoint.DstToString()
	}
	attempt := b.rotations[endpointKey]
	b.rotations[endpointKey] = attempt + 1
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(b.identity + "|" + endpointKey))
	return wireGuardDPIStrategy((hash.Sum32() + attempt) % uint32(wireGuardDPIStrategyCount))
}

func (b *wireGuardDPIBind) fakePlan(strategy wireGuardDPIStrategy) [][]byte {
	if strategy != wireGuardDPIStrategyPairedDuplicates && strategy != wireGuardDPIStrategyInterleavedDuplicates {
		fakes := make([][]byte, 0, b.option.FakeCount)
		for len(fakes) < b.option.FakeCount {
			if fake := b.randomFakePacket(); fake != nil {
				fakes = append(fakes, fake)
			} else {
				break
			}
		}
		return fakes
	}

	unique := make([][]byte, 0, (b.option.FakeCount+1)/2)
	for len(unique) < cap(unique) {
		if fake := b.randomFakePacket(); fake != nil {
			unique = append(unique, fake)
		} else {
			break
		}
	}
	plan := make([][]byte, 0, b.option.FakeCount)
	if strategy == wireGuardDPIStrategyPairedDuplicates {
		for _, fake := range unique {
			plan = append(plan, fake)
			if len(plan) < b.option.FakeCount {
				plan = append(plan, fake)
			}
		}
		return plan
	}
	plan = append(plan, unique...)
	for _, fake := range unique {
		if len(plan) == b.option.FakeCount {
			break
		}
		plan = append(plan, fake)
	}
	return plan
}

func (b *wireGuardDPIBind) randomFakePacket() []byte {
	size := b.option.FakeMinSize
	if span := b.option.FakeMaxSize - b.option.FakeMinSize + 1; span > 1 {
		var sample [2]byte
		if _, err := rand.Read(sample[:]); err == nil {
			size += int(binary.LittleEndian.Uint16(sample[:])) % span
		}
	}
	fake := make([]byte, size)
	if _, err := rand.Read(fake); err != nil {
		return nil
	}
	if b.pattern.typeOffset+4 <= len(fake) {
		binary.LittleEndian.PutUint32(fake[b.pattern.typeOffset:b.pattern.typeOffset+4], 0)
	} else {
		fake[0] = 0
	}
	return fake
}

func (b *wireGuardDPIBind) send(bufs [][]byte, endpoint wgconn.Endpoint, ttl int) error {
	b.control.ttl = ttl
	defer func() { b.control.ttl = 0 }()
	return b.Bind.Send(bufs, endpoint)
}

func (d *wireGuardDPIDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	connection, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	if udpConn, ok := connection.(*net.UDPConn); ok {
		return &wireGuardDPIUDPConn{UDPConn: udpConn, control: d.control}, nil
	}
	return connection, nil
}

func (d *wireGuardDPIDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, err := d.Dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	if udpConn, ok := packetConn.(*net.UDPConn); ok {
		return &wireGuardDPIUDPConn{UDPConn: udpConn, control: d.control}, nil
	}
	return packetConn, nil
}

func (c *wireGuardDPIUDPConn) Write(payload []byte) (int, error) {
	if c.control.ttl > 0 {
		if n, err, supported := writeWireGuardUDPWithTTL(c.UDPConn, payload, nil, c.control.ttl); supported && (err == nil || n > 0) {
			return n, err
		}
	}
	return c.UDPConn.Write(payload)
}

func (c *wireGuardDPIUDPConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	udpDestination, isUDP := destination.(*net.UDPAddr)
	if c.control.ttl > 0 && isUDP {
		if n, err, supported := writeWireGuardUDPWithTTL(c.UDPConn, payload, udpDestination, c.control.ttl); supported && (err == nil || n > 0) {
			return n, err
		}
	}
	return c.UDPConn.WriteTo(payload, destination)
}

type WireGuard struct {
	*Base
	bind      *wireguard.ClientBind
	device    wireguardGoDevice
	tunDevice wireguardDevice
	resolver  resolver.Resolver

	initOk        atomic.Bool
	initMutex     sync.Mutex
	initErr       error
	option        WireGuardOption
	connectAddr   M.Socksaddr
	localPrefixes []netip.Prefix

	serverAddrMap   map[M.Socksaddr]netip.AddrPort
	serverAddrTime  atomic.TypedValue[time.Time]
	serverAddrMutex sync.Mutex
}

type WireGuardOption struct {
	BasicOption
	WireGuardPeerOption
	Name                string `proxy:"name"`
	Ip                  string `proxy:"ip,omitempty"`
	Ipv6                string `proxy:"ipv6,omitempty"`
	PrivateKey          string `proxy:"private-key"`
	Workers             int    `proxy:"workers,omitempty"`
	MTU                 int    `proxy:"mtu,omitempty"`
	UDP                 bool   `proxy:"udp,omitempty"`
	PersistentKeepalive int    `proxy:"persistent-keepalive,omitempty"`

	IPStack IPStackOption `proxy:"ip-stack,omitempty"`

	AmneziaWGOption *AmneziaWGOption    `proxy:"amnezia-wg-option,omitempty"`
	DPIOption       *WireGuardDPIOption `proxy:"wireguard-dpi-option,omitempty"`

	Peers []WireGuardPeerOption `proxy:"peers,omitempty"`

	RemoteDnsResolve bool     `proxy:"remote-dns-resolve,omitempty"`
	Dns              []string `proxy:"dns,omitempty"`

	RefreshServerIPInterval int `proxy:"refresh-server-ip-interval,omitempty"`
}

type WireGuardPeerOption struct {
	Server       string   `proxy:"server,omitempty"`
	Port         int      `proxy:"port,omitempty"`
	PublicKey    string   `proxy:"public-key,omitempty"`
	PreSharedKey string   `proxy:"pre-shared-key,omitempty"`
	Reserved     []uint8  `proxy:"reserved,omitempty"`
	AllowedIPs   []string `proxy:"allowed-ips,omitempty"`
}

type AmneziaWGOption struct {
	Version int `proxy:"version,omitempty"` // Only version 3 uses the v3 implementation; all other values use the legacy implementation.

	JC   int `proxy:"jc,omitempty"`
	JMin int `proxy:"jmin,omitempty"`
	JMax int `proxy:"jmax,omitempty"`
	S1   int `proxy:"s1,omitempty"`
	S2   int `proxy:"s2,omitempty"`
	S3   int `proxy:"s3,omitempty"` // AmneziaWG v1.5+
	S4   int `proxy:"s4,omitempty"` // AmneziaWG v1.5+

	// H1-H4 accept uint32 values in v1.x and uint32 values or ranges in v2+.
	// WeaklyTypedInput accepts both numeric and string representations.
	H1 string `proxy:"h1,omitempty"`
	H2 string `proxy:"h2,omitempty"`
	H3 string `proxy:"h3,omitempty"`
	H4 string `proxy:"h4,omitempty"`

	I1 string `proxy:"i1,omitempty"` // AmneziaWG v1.5+
	I2 string `proxy:"i2,omitempty"` // AmneziaWG v1.5+
	I3 string `proxy:"i3,omitempty"` // AmneziaWG v1.5+
	I4 string `proxy:"i4,omitempty"` // AmneziaWG v1.5+
	I5 string `proxy:"i5,omitempty"` // AmneziaWG v1.5+

	J1    string `proxy:"j1,omitempty"`    // AmneziaWG v1.5 only (removed in v2+)
	J2    string `proxy:"j2,omitempty"`    // AmneziaWG v1.5 only (removed in v2+)
	J3    string `proxy:"j3,omitempty"`    // AmneziaWG v1.5 only (removed in v2+)
	Itime int64  `proxy:"itime,omitempty"` // AmneziaWG v1.5 only (removed in v2+)

	// AmneziaWG v3+ only. Version must be 3, and these options cannot be combined with the v1.5-only options above.
	HeaderProtectionKey    string `proxy:"header-protection-key,omitempty"`
	ContentPaddingAddition string `proxy:"content-padding-addition,omitempty"`
	RekeyAfterTime         string `proxy:"rekey-after-time,omitempty"`
	RekeyTimeout           string `proxy:"rekey-timeout,omitempty"`
	RejectAfterTime        string `proxy:"reject-after-time,omitempty"`
	KeepaliveTimeout       string `proxy:"keepalive-timeout,omitempty"`
	MaxHandshakeAttempts   string `proxy:"max-handshake-attempts,omitempty"`
	RandomTrailers         bool   `proxy:"random-trailers,omitempty"` // AmneziaWG v3.1+
	DisableCookies         bool   `proxy:"disable-cookies,omitempty"` // AmneziaWG v3.1+
}

type IPStackOption struct {
	Mode                 string `proxy:"mode,omitempty"`
	CongestionController string `proxy:"congestion-controller,omitempty"`
}

func (o *IPStackOption) normalize() {
	o.Mode = strings.ToLower(o.Mode)
	if o.Mode == "" {
		o.Mode = ipStackAuto
	}
	o.CongestionController = strings.ToLower(o.CongestionController)
}

func (o IPStackOption) validate() error {
	switch o.Mode {
	case ipStackAuto, ipStackMips:
	case ipStackGVisor:
		if !features.WithGVisor {
			return errors.New("gVisor IP stack requires the with_gvisor build tag")
		}
	default:
		return fmt.Errorf("invalid IP stack mode %q; expected auto, gvisor, or mips", o.Mode)
	}
	switch mipstack.CongestionControl(o.CongestionController) {
	case "", mipstack.CongestionControlCUBIC, mipstack.CongestionControlReno, mipstack.CongestionControlBBR, mipstack.CongestionControlBBR3:
		return nil
	default:
		return fmt.Errorf("invalid IP stack congestion controller %q; expected cubic, reno, bbr, or bbr3", o.CongestionController)
	}
}

// ipStack is the mihomo IP stack's packet and socket surface, adapted from
// sing-wireguard only for gVisor.
type ipStack interface {
	Start() error
	DialTCP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	DialUDP(ctx context.Context, network string, source, destination netip.AddrPort) (net.Conn, error)
	ListenUDP(ctx context.Context, network string, local netip.AddrPort) (net.PacketConn, error)
	Read(buffers [][]byte, sizes []int, offset int) (int, error)
	Write(buffers [][]byte, offset int) (int, error)
	MTU() (int, error)
	Name() (string, error)
	BatchSize() int
	Close() error
}

// newIPStack constructs the selected userspace IP stack.
func newIPStack(option IPStackOption, localAddresses []netip.Prefix, mtu uint32) (ipStack, error) {
	mode := option.Mode
	if mode == ipStackAuto {
		if features.WithGVisor {
			mode = ipStackGVisor
		} else {
			mode = ipStackMips
		}
	}
	switch mode {
	case ipStackGVisor:
		return wireguard.NewStackDevice(localAddresses, mtu)
	case ipStackMips:
		return mipstack.New(mipstack.Config{
			LocalAddresses: localAddresses,
			MTU:            mtu,
			TCP: mipstack.TCPSocketDefaults{
				CongestionControl: mipstack.CongestionControl(option.CongestionController),
				// Align with sing-wireguard: enable keepalive with 15-second
				// idle/interval timing and gVisor's default probe count.
				KeepAlive: true,
				KeepAliveConfig: mipstack.KeepAliveConfig{
					Idle: 15 * time.Second, Interval: 15 * time.Second, Count: 9,
				},
			},
		})
	default:
		return nil, errors.New("invalid IP stack mode")
	}
}

var _ ipStack = (*mipstack.Stack)(nil)
var _ ipStack = (wireguard.Device)(nil)

type ipStackNetDialer struct {
	stack ipStack
}

var _ dialer.NetDialer = (*ipStackNetDialer)(nil)

func (d ipStackNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dst, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", address, err)
	}
	switch {
	case strings.HasPrefix(network, "tcp"):
		return d.stack.DialTCP(ctx, network, netip.AddrPort{}, dst)
	case strings.HasPrefix(network, "udp"):
		return d.stack.DialUDP(ctx, network, netip.AddrPort{}, dst)
	default:
		return nil, fmt.Errorf("invalid network %q", network)
	}
}

type wireguardDevice interface {
	ipStack
	tun.Device
}

type ipStackWireguardDevice struct {
	ipStack
	events    chan tun.Event
	closeOnce sync.Once
}

func (d *ipStackWireguardDevice) File() *os.File {
	return nil
}

func (d *ipStackWireguardDevice) Events() <-chan tun.Event {
	return d.events
}

func (d *ipStackWireguardDevice) Start() error {
	d.events <- tun.EventUp
	return nil
}

func (d *ipStackWireguardDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.events)
	})
	return d.ipStack.Close()
}

func newWireguardDevice(stack ipStack) (wireguardDevice, error) {
	if wgDevice, ok := stack.(wireguardDevice); ok {
		return wgDevice, nil
	}
	// mipstack must start at here
	err := stack.Start()
	if err != nil {
		return nil, err
	}
	return &ipStackWireguardDevice{
		ipStack: stack,
		events:  make(chan tun.Event, 1),
	}, nil
}

func (o *AmneziaWGOption) hasHandshakeChanges() bool {
	return o.Version == 3 || o.S1 != 0 || o.S2 != 0 || o.S3 != 0 || o.S4 != 0 ||
		o.H1 != "" || o.H2 != "" || o.H3 != "" || o.H4 != "" ||
		o.I1 != "" || o.I2 != "" || o.I3 != "" || o.I4 != "" || o.I5 != "" ||
		o.J1 != "" || o.J2 != "" || o.J3 != "" || o.Itime != 0 ||
		o.HeaderProtectionKey != "" || o.ContentPaddingAddition != "" || o.RekeyAfterTime != "" ||
		o.RekeyTimeout != "" || o.RejectAfterTime != "" || o.KeepaliveTimeout != "" ||
		o.MaxHandshakeAttempts != "" || o.RandomTrailers || o.DisableCookies
}

type wgSingErrorHandler struct {
	name string
}

var _ E.Handler = (*wgSingErrorHandler)(nil)

func (w wgSingErrorHandler) NewError(ctx context.Context, err error) {
	if E.IsClosedOrCanceled(err) {
		log.SingLogger.Debug(fmt.Sprintf("[WG](%s) connection closed: %s", w.name, err))
		return
	}
	log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", w.name, err))
}

type wgNetDialer struct {
	tunDevice wireguard.Device
}

var _ dialer.NetDialer = (*wgNetDialer)(nil)

func (d wgNetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tunDevice.DialContext(ctx, network, M.ParseSocksaddr(address).Unwrap())
}

func (option WireGuardPeerOption) Addr() M.Socksaddr {
	return M.ParseSocksaddrHostPort(option.Server, uint16(option.Port))
}

func (option WireGuardOption) Prefixes() ([]netip.Prefix, error) {
	localPrefixes := make([]netip.Prefix, 0, 2)
	if len(option.Ip) > 0 {
		if !strings.Contains(option.Ip, "/") {
			option.Ip = option.Ip + "/32"
		}
		if prefix, err := netip.ParsePrefix(option.Ip); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ip address parse error")
		}
	}
	if len(option.Ipv6) > 0 {
		if !strings.Contains(option.Ipv6, "/") {
			option.Ipv6 = option.Ipv6 + "/128"
		}
		if prefix, err := netip.ParsePrefix(option.Ipv6); err == nil {
			localPrefixes = append(localPrefixes, prefix)
		} else {
			return nil, E.Cause(err, "ipv6 address parse error")
		}
	}
	if len(localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}
	return localPrefixes, nil
}

func NewWireGuard(option WireGuardOption) (*WireGuard, error) {
	dpiOption := option.DPIOption
	// Legacy junk-only options use the standard device so WARP handshakes and reserved bytes stay intact.
	if awg := option.AmneziaWGOption; awg != nil && !awg.hasHandshakeChanges() {
		if dpiOption == nil && (awg.JC != 0 || awg.JMin != 0 || awg.JMax != 0) {
			dpiOption = &WireGuardDPIOption{
				FakeCount:   awg.JC,
				FakeMinSize: awg.JMin,
				FakeMaxSize: awg.JMax,
				FakeTTL:     wireGuardDefaultDPIFakeTTL,
			}
		}
		option.AmneziaWGOption = nil
	}
	if dpiOption != nil {
		if !dpiOption.enabled() {
			dpiOption = nil
		} else if err := dpiOption.validate(); err != nil {
			return nil, err
		}
	}
	option.DPIOption = dpiOption
	var initiationPattern wireGuardInitiationPattern
	var err error
	if dpiOption != nil {
		initiationPattern, err = newWireGuardInitiationPattern(option.AmneziaWGOption)
		if err != nil {
			return nil, err
		}
	}
	outbound := &WireGuard{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type:         C.WireGuard,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(proxydialer.NewSlowDownDialer(outbound.dialer, slowdown.New()))
	var clientDialer N.Dialer = singDialer
	var dpiControl *wireGuardDPIWriteControl
	if dpiOption != nil {
		dpiControl = &wireGuardDPIWriteControl{}
		if option.DialerProxy == "" && option.DialerForAPI == nil {
			clientDialer = &wireGuardDPIDialer{Dialer: clientDialer, control: dpiControl}
		}
	}

	var reserved [3]uint8
	if len(option.Reserved) > 0 {
		if len(option.Reserved) != 3 {
			return nil, E.New("invalid reserved value, required 3 bytes, got ", len(option.Reserved))
		}
		copy(reserved[:], option.Reserved)
	}
	var isConnect bool
	if len(option.Peers) < 2 {
		isConnect = true
		if len(option.Peers) == 1 {
			outbound.connectAddr = option.Peers[0].Addr()
		} else {
			outbound.connectAddr = option.Addr()
		}
	}
	outbound.bind = wireguard.NewClientBind(context.Background(), wgSingErrorHandler{outbound.Name()}, clientDialer, isConnect, outbound.connectAddr.AddrPort(), reserved)

	outbound.localPrefixes, err = option.Prefixes()
	if err != nil {
		return nil, err
	}

	{
		bytes, err := base64.StdEncoding.DecodeString(option.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "decode private key")
		}
		option.PrivateKey = hex.EncodeToString(bytes)
	}

	if len(option.Peers) > 0 {
		for i := range option.Peers {
			peer := &option.Peers[i] // we need modify option here
			bytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode public key for peer ", i)
			}
			peer.PublicKey = hex.EncodeToString(bytes)

			if peer.PreSharedKey != "" {
				bytes, err := base64.StdEncoding.DecodeString(peer.PreSharedKey)
				if err != nil {
					return nil, E.Cause(err, "decode pre shared key for peer ", i)
				}
				peer.PreSharedKey = hex.EncodeToString(bytes)
			}

			if len(peer.AllowedIPs) == 0 {
				return nil, E.New("missing allowed_ips for peer ", i)
			}

			if len(peer.Reserved) > 0 {
				if len(peer.Reserved) != 3 {
					return nil, E.New("invalid reserved value for peer ", i, ", required 3 bytes, got ", len(peer.Reserved))
				}
			}
		}
	} else {
		{
			bytes, err := base64.StdEncoding.DecodeString(option.PublicKey)
			if err != nil {
				return nil, E.Cause(err, "decode peer public key")
			}
			option.PublicKey = hex.EncodeToString(bytes)
		}
		if option.PreSharedKey != "" {
			bytes, err := base64.StdEncoding.DecodeString(option.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key")
			}
			option.PreSharedKey = hex.EncodeToString(bytes)
		}
	}
	if option.AmneziaWGOption != nil && option.AmneziaWGOption.HeaderProtectionKey != "" {
		bytes, err := base64.StdEncoding.DecodeString(option.AmneziaWGOption.HeaderProtectionKey)
		if err != nil {
			return nil, E.Cause(err, "decode header protection key")
		}
		option.AmneziaWGOption.HeaderProtectionKey = hex.EncodeToString(bytes)
	}
	outbound.option = option

	mtu := option.MTU
	if mtu == 0 {
		mtu = 1408
	}
	option.IPStack.normalize()
	if err = option.IPStack.validate(); err != nil {
		return nil, err
	}
	if len(outbound.localPrefixes) == 0 {
		return nil, E.New("missing local address")
	}

	stack, err := newIPStack(option.IPStack, outbound.localPrefixes, uint32(mtu))
	if err != nil {
		return nil, E.Cause(err, "create WireGuard stack")
	}
	outbound.tunDevice, err = newWireguardDevice(stack)
	if err != nil {
		_ = stack.Close()
		return nil, E.Cause(err, "create WireGuard device")
	}

	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			log.SingLogger.Debug(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
		Errorf: func(format string, args ...interface{}) {
			log.SingLogger.Error(fmt.Sprintf("[WG](%s) %s", option.Name, fmt.Sprintf(format, args...)))
		},
	}
	deviceBind := wgconn.Bind(outbound.bind)
	if dpiOption != nil {
		deviceBind = &wireGuardDPIBind{
			Bind:      deviceBind,
			option:    *dpiOption,
			pattern:   initiationPattern,
			control:   dpiControl,
			identity:  option.Name,
			rotations: make(map[string]uint32),
		}
	}
	if option.AmneziaWGOption != nil {
		outbound.bind.SetParseReserved(false) // AmneziaWG don't need parse reserved
		if option.AmneziaWGOption.Version == 3 {
			outbound.device = amneziav3.NewDevice(outbound.tunDevice, deviceBind, logger, option.Workers)
		} else {
			outbound.device = amnezia.NewDevice(outbound.tunDevice, deviceBind, logger, option.Workers)
		}
	} else {
		outbound.device = device.NewDevice(outbound.tunDevice, deviceBind, logger, option.Workers)
	}

	var has6 bool
	for _, address := range outbound.localPrefixes {
		if !address.Addr().Unmap().Is4() {
			has6 = true
			break
		}
	}

	if option.RemoteDnsResolve && len(option.Dns) > 0 {
		nss, err := dns.ParseNameServer(option.Dns)
		if err != nil {
			return nil, err
		}
		for i := range nss {
			nss[i].ProxyAdapter = outbound
		}
		outbound.resolver = dns.NewResolver(dns.Config{
			Main: nss,
			IPv6: has6,
		})
	}

	return outbound, nil
}

func (w *WireGuard) resolve(ctx context.Context, address M.Socksaddr) (netip.AddrPort, error) {
	if address.Addr.IsValid() {
		return address.AddrPort(), nil
	}
	udpAddr, err := resolveUDPAddr(ctx, "udp", address.String(), w.prefer)
	if err != nil {
		return netip.AddrPort{}, err
	}
	// net.ResolveUDPAddr maybe return 4in6 address, so unmap at here
	addrPort := udpAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()), nil
}

func (w *WireGuard) init(ctx context.Context) error {
	err := w.init0(ctx)
	if err != nil {
		return err
	}
	w.updateServerAddr(ctx)
	return nil
}

func (w *WireGuard) init0(ctx context.Context) error {
	if w.initOk.Load() {
		return nil
	}
	w.initMutex.Lock()
	defer w.initMutex.Unlock()
	// double check like sync.Once
	if w.initOk.Load() {
		return nil
	}
	if w.initErr != nil {
		return w.initErr
	}

	w.bind.ResetReservedForEndpoint()
	w.serverAddrMap = make(map[M.Socksaddr]netip.AddrPort)
	ipcConf, err := w.genIpcConf(ctx, false)
	if err != nil {
		// !!! do not set initErr here !!!
		// let us can retry domain resolve in next time
		return err
	}

	if debug.Enabled {
		log.SingLogger.Trace(fmt.Sprintf("[WG](%s) created wireguard ipc conf: \n %s", w.option.Name, ipcConf))
	}
	err = w.device.IpcSet(ipcConf)
	if err != nil {
		w.initErr = E.Cause(err, "setup wireguard")
		return w.initErr
	}
	w.serverAddrTime.Store(time.Now())

	err = w.tunDevice.Start()
	if err != nil {
		w.initErr = err
		return w.initErr
	}

	w.initOk.Store(true)
	return nil
}

func (w *WireGuard) updateServerAddr(ctx context.Context) {
	if w.option.RefreshServerIPInterval != 0 && time.Since(w.serverAddrTime.Load()) > time.Second*time.Duration(w.option.RefreshServerIPInterval) {
		if w.serverAddrMutex.TryLock() {
			defer w.serverAddrMutex.Unlock()
			ipcConf, err := w.genIpcConf(ctx, true)
			if err != nil {
				log.Warnln("[WG](%s)UpdateServerAddr failed to generate wireguard ipc conf: %s", w.option.Name, err)
				return
			}
			err = w.device.IpcSet(ipcConf)
			if err != nil {
				log.Warnln("[WG](%s)UpdateServerAddr failed to update wireguard ipc conf: %s", w.option.Name, err)
				return
			}
			w.serverAddrTime.Store(time.Now())
		}
	}
}

func (w *WireGuard) genIpcConf(ctx context.Context, updateOnly bool) (string, error) {
	ipcConf := ""
	if !updateOnly {
		ipcConf += "private_key=" + w.option.PrivateKey + "\n"
		if w.option.AmneziaWGOption != nil {
			if w.option.AmneziaWGOption.JC != 0 {
				ipcConf += "jc=" + strconv.Itoa(w.option.AmneziaWGOption.JC) + "\n"
			}
			if w.option.AmneziaWGOption.JMin != 0 {
				ipcConf += "jmin=" + strconv.Itoa(w.option.AmneziaWGOption.JMin) + "\n"
			}
			if w.option.AmneziaWGOption.JMax != 0 {
				ipcConf += "jmax=" + strconv.Itoa(w.option.AmneziaWGOption.JMax) + "\n"
			}
			if w.option.AmneziaWGOption.S1 != 0 {
				ipcConf += "s1=" + strconv.Itoa(w.option.AmneziaWGOption.S1) + "\n"
			}
			if w.option.AmneziaWGOption.S2 != 0 {
				ipcConf += "s2=" + strconv.Itoa(w.option.AmneziaWGOption.S2) + "\n"
			}
			if w.option.AmneziaWGOption.S3 != 0 {
				ipcConf += "s3=" + strconv.Itoa(w.option.AmneziaWGOption.S3) + "\n"
			}
			if w.option.AmneziaWGOption.S4 != 0 {
				ipcConf += "s4=" + strconv.Itoa(w.option.AmneziaWGOption.S4) + "\n"
			}
			if w.option.AmneziaWGOption.H1 != "" {
				ipcConf += "h1=" + w.option.AmneziaWGOption.H1 + "\n"
			}
			if w.option.AmneziaWGOption.H2 != "" {
				ipcConf += "h2=" + w.option.AmneziaWGOption.H2 + "\n"
			}
			if w.option.AmneziaWGOption.H3 != "" {
				ipcConf += "h3=" + w.option.AmneziaWGOption.H3 + "\n"
			}
			if w.option.AmneziaWGOption.H4 != "" {
				ipcConf += "h4=" + w.option.AmneziaWGOption.H4 + "\n"
			}
			if w.option.AmneziaWGOption.I1 != "" {
				ipcConf += "i1=" + w.option.AmneziaWGOption.I1 + "\n"
			}
			if w.option.AmneziaWGOption.I2 != "" {
				ipcConf += "i2=" + w.option.AmneziaWGOption.I2 + "\n"
			}
			if w.option.AmneziaWGOption.I3 != "" {
				ipcConf += "i3=" + w.option.AmneziaWGOption.I3 + "\n"
			}
			if w.option.AmneziaWGOption.I4 != "" {
				ipcConf += "i4=" + w.option.AmneziaWGOption.I4 + "\n"
			}
			if w.option.AmneziaWGOption.I5 != "" {
				ipcConf += "i5=" + w.option.AmneziaWGOption.I5 + "\n"
			}
			if w.option.AmneziaWGOption.J1 != "" {
				ipcConf += "j1=" + w.option.AmneziaWGOption.J1 + "\n"
			}
			if w.option.AmneziaWGOption.J2 != "" {
				ipcConf += "j2=" + w.option.AmneziaWGOption.J2 + "\n"
			}
			if w.option.AmneziaWGOption.J3 != "" {
				ipcConf += "j3=" + w.option.AmneziaWGOption.J3 + "\n"
			}
			if w.option.AmneziaWGOption.Itime != 0 {
				ipcConf += "itime=" + strconv.FormatInt(int64(w.option.AmneziaWGOption.Itime), 10) + "\n"
			}
			if w.option.AmneziaWGOption.HeaderProtectionKey != "" {
				ipcConf += "header_protection_key=" + w.option.AmneziaWGOption.HeaderProtectionKey + "\n"
			}
			if w.option.AmneziaWGOption.ContentPaddingAddition != "" {
				ipcConf += "content_padding_addition=" + w.option.AmneziaWGOption.ContentPaddingAddition + "\n"
			}
			if w.option.AmneziaWGOption.RekeyAfterTime != "" {
				ipcConf += "rekey_after_time=" + w.option.AmneziaWGOption.RekeyAfterTime + "\n"
			}
			if w.option.AmneziaWGOption.RekeyTimeout != "" {
				ipcConf += "rekey_timeout=" + w.option.AmneziaWGOption.RekeyTimeout + "\n"
			}
			if w.option.AmneziaWGOption.RejectAfterTime != "" {
				ipcConf += "reject_after_time=" + w.option.AmneziaWGOption.RejectAfterTime + "\n"
			}
			if w.option.AmneziaWGOption.KeepaliveTimeout != "" {
				ipcConf += "keepalive_timeout=" + w.option.AmneziaWGOption.KeepaliveTimeout + "\n"
			}
			if w.option.AmneziaWGOption.MaxHandshakeAttempts != "" {
				ipcConf += "max_handshake_attempts=" + w.option.AmneziaWGOption.MaxHandshakeAttempts + "\n"
			}
			if w.option.AmneziaWGOption.RandomTrailers {
				ipcConf += "random_trailers=1\n"
			}
			if w.option.AmneziaWGOption.DisableCookies {
				ipcConf += "disable_cookies=1\n"
			}
		}
	}
	if len(w.option.Peers) > 0 {
		for i, peer := range w.option.Peers {
			peerAddr := peer.Addr()
			destination, err := w.resolve(ctx, peerAddr)
			if err != nil {
				return "", E.Cause(err, "resolve endpoint domain for peer ", i)
			}
			if w.serverAddrMap[peerAddr] != destination {
				w.serverAddrMap[peerAddr] = destination
			} else if updateOnly {
				continue
			}

			if len(w.option.Peers) == 1 { // must call SetConnectAddr if isConnect == true
				w.bind.SetConnectAddr(destination)
			}
			ipcConf += "public_key=" + peer.PublicKey + "\n"
			if updateOnly {
				ipcConf += "update_only=true\n"
			}
			ipcConf += "endpoint=" + destination.String() + "\n"
			if len(peer.Reserved) > 0 {
				var reserved [3]uint8
				copy(reserved[:], peer.Reserved)
				w.bind.SetReservedForEndpoint(destination, reserved)
			}
			if updateOnly {
				continue
			}
			if peer.PreSharedKey != "" {
				ipcConf += "preshared_key=" + peer.PreSharedKey + "\n"
			}
			for _, allowedIP := range peer.AllowedIPs {
				ipcConf += "allowed_ip=" + allowedIP + "\n"
			}
			if w.option.PersistentKeepalive != 0 {
				ipcConf += fmt.Sprintf("persistent_keepalive_interval=%d\n", w.option.PersistentKeepalive)
			}
		}
	} else {
		destination, err := w.resolve(ctx, w.connectAddr)
		if err != nil {
			return "", E.Cause(err, "resolve endpoint domain")
		}
		if w.serverAddrMap[w.connectAddr] != destination {
			w.serverAddrMap[w.connectAddr] = destination
		} else if updateOnly {
			return "", nil
		}
		w.bind.SetConnectAddr(destination) // must call SetConnectAddr if isConnect == true
		ipcConf += "public_key=" + w.option.PublicKey + "\n"
		if updateOnly {
			ipcConf += "update_only=true\n"
		}
		ipcConf += "endpoint=" + destination.String() + "\n"
		if updateOnly {
			return ipcConf, nil
		}
		if w.option.PreSharedKey != "" {
			ipcConf += "preshared_key=" + w.option.PreSharedKey + "\n"
		}
		var has4, has6 bool
		for _, address := range w.localPrefixes {
			if address.Addr().Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		if has4 {
			ipcConf += "allowed_ip=0.0.0.0/0\n"
		}
		if has6 {
			ipcConf += "allowed_ip=::/0\n"
		}

		if w.option.PersistentKeepalive != 0 {
			ipcConf += fmt.Sprintf("persistent_keepalive_interval=%d\n", w.option.PersistentKeepalive)
		}
	}
	return ipcConf, nil
}

// Close implements C.ProxyAdapter
func (w *WireGuard) Close() error {
	if w.device != nil {
		w.device.Close()
	}
	return nil
}

func (w *WireGuard) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	var conn net.Conn
	if err = w.init(ctx); err != nil {
		return nil, err
	}
	if !metadata.Resolved() || w.resolver != nil {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		options := w.DialOptions()
		options = append(options, dialer.WithResolver(r))
		options = append(options, dialer.WithNetDialer(ipStackNetDialer{stack: w.tunDevice}))
		conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	} else {
		conn, err = w.tunDevice.DialTCP(ctx, "tcp", netip.AddrPort{}, metadata.AddrPort())
	}
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, E.New("conn is nil")
	}
	return NewConn(conn, w), nil
}

func (w *WireGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	var pc net.PacketConn
	if err = w.init(ctx); err != nil {
		return nil, err
	}
	if err = w.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	// The ipStack contract guarantees that a generic UDP wildcard supports both address families.
	pc, err = w.tunDevice.ListenUDP(ctx, "udp", netip.AddrPort{})
	if err != nil {
		return nil, err
	}
	if pc == nil {
		return nil, E.New("packetConn is nil")
	}
	return NewPacketConn(pc, w), nil
}

func (w *WireGuard) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || w.resolver != nil) && metadata.Host != "" {
		r := resolver.DefaultResolver
		if w.resolver != nil {
			r = w.resolver
		}
		ip, err := resolveIPWithResolver(ctx, metadata.Host, w.prefer, r)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

// ProxyInfo implements C.ProxyAdapter
func (w *WireGuard) ProxyInfo() C.ProxyInfo {
	info := w.Base.ProxyInfo()
	info.DialerProxy = w.option.DialerProxy
	return info
}

// IsL3Protocol implements C.ProxyAdapter
func (w *WireGuard) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}
