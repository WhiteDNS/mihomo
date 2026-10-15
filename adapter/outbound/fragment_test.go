package outbound

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"

	"github.com/stretchr/testify/require"
)

func TestFragmentOptionDecode(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	var option VlessOption
	require.NoError(t, decoder.Decode(map[string]any{
		"name":          "test",
		"server":        "127.0.0.1",
		"port":          443,
		"uuid":          "00000000-0000-0000-0000-000000000000",
		"cipher-suites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"fragments": []any{
			map[string]any{"packets": "tlshello", "lengths": []any{0, 104, 1}, "delays": []any{0}, "maxSplit": 0},
			map[string]any{"packets": "1-1", "lengths": []any{114, 1}, "delays": []any{1}, "maxSplit": 11},
		},
	}, &option))
	require.NoError(t, option.Validate())
	require.Len(t, option.Fragments, 2)
	require.Len(t, option.CipherSuites, 13)

	config, err := option.Fragments[0].build()
	require.NoError(t, err)
	require.True(t, config.tlsHello)
	require.Equal(t, []FragmentRange{{Min: 0, Max: 0}, {Min: 104, Max: 104}, {Min: 1, Max: 1}}, config.lengths)
	require.Equal(t, []FragmentRange{{Min: 0, Max: 0}}, config.delays)
	require.Equal(t, FragmentRange{}, config.maxSplit)

	config, err = option.Fragments[1].build()
	require.NoError(t, err)
	require.Equal(t, uint64(1), config.from)
	require.Equal(t, uint64(1), config.to)
	require.Equal(t, FragmentRange{Min: 11, Max: 11}, config.maxSplit)
}

func TestFragmentOptionValidation(t *testing.T) {
	tests := []struct {
		name   string
		option FragmentOption
	}{
		{name: "missing length", option: FragmentOption{}},
		{name: "zero final length", option: FragmentOption{Lengths: []FragmentRange{{Min: 0, Max: 1}}}},
		{name: "invalid packets", option: FragmentOption{Packets: "0-1", Lengths: []FragmentRange{{Min: 1, Max: 1}}}},
		{name: "delay aliases", option: FragmentOption{Length: &FragmentRange{Min: 1, Max: 1}, Delay: &FragmentRange{}, Interval: &FragmentRange{}}},
		{name: "max split aliases", option: FragmentOption{Length: &FragmentRange{Min: 1, Max: 1}, MaxSplit: &FragmentRange{}, MaxSplitCompat: &FragmentRange{}}},
		{name: "excessive delay", option: FragmentOption{Length: &FragmentRange{Min: 1, Max: 1}, Delay: &FragmentRange{Min: 1_001, Max: 1_001}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.option.build()
			require.Error(t, err)
		})
	}
}

func TestFragmentStageLimit(t *testing.T) {
	err := (&BasicOption{Fragments: make([]FragmentOption, maxFragmentStages+1)}).Validate()
	require.EqualError(t, err, "fragments must contain at most 8 stages")
}

func TestFragmentTLSHello(t *testing.T) {
	raw := &recordingConn{}
	conn := &fragmentConn{Conn: raw, config: mustFragmentConfig(t, FragmentOption{
		Packets:  "tlshello",
		Lengths:  []FragmentRange{{Min: 1, Max: 1}, {Min: 3, Max: 3}},
		Delays:   []FragmentRange{{}},
		MaxSplit: &FragmentRange{Min: 2, Max: 2},
	})}
	input := append([]byte{22, 3, 1, 0, 4}, []byte("abcdtail")...)

	n, err := conn.Write(input)
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	require.Equal(t, [][]byte{
		{22, 3, 1, 0, 1, 'a', 22, 3, 1, 0, 3, 'b', 'c', 'd'},
		[]byte("tail"),
	}, raw.writes)
}

func TestFragmentWriteSelectionAndMaxSplit(t *testing.T) {
	raw := &recordingConn{}
	conn := &fragmentConn{Conn: raw, config: mustFragmentConfig(t, FragmentOption{
		Packets:  "2",
		Lengths:  []FragmentRange{{Min: 1, Max: 1}},
		MaxSplit: &FragmentRange{Min: 2, Max: 2},
	})}

	for i := 0; i < 3; i++ {
		n, err := conn.Write([]byte("abcd"))
		require.NoError(t, err)
		require.Equal(t, 4, n)
	}
	require.Equal(t, [][]byte{[]byte("abcd"), []byte("a"), []byte("bcd"), []byte("abcd")}, raw.writes)
}

func TestFragmentWriteHandlesShortWrites(t *testing.T) {
	raw := &recordingConn{maxWrite: 1}
	conn := &fragmentConn{Conn: raw, config: mustFragmentConfig(t, FragmentOption{
		Length: &FragmentRange{Min: 3, Max: 3},
	})}

	n, err := conn.Write([]byte("abcdef"))
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, []byte("abcdef"), bytes.Join(raw.writes, nil))
}

func TestFragmentDialerWrapsOnlyTCP(t *testing.T) {
	dialer := newFragmentDialer(&stubDialer{}, &FragmentOption{Length: &FragmentRange{Min: 1, Max: 1}})

	tcpConn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)
	require.IsType(t, &fragmentConn{}, tcpConn)

	udpConn, err := dialer.DialContext(context.Background(), "udp", "example.com:443")
	require.NoError(t, err)
	require.IsType(t, &recordingConn{}, udpConn)
}

func TestFragmentChainUsesXrayOrder(t *testing.T) {
	raw := &recordingConn{}
	dialer := newFragmentDialerChain(&stubDialer{conn: raw}, nil, []FragmentOption{
		{Packets: "tlshello", Length: &FragmentRange{Min: 1, Max: 1}},
		{Packets: "1", Length: &FragmentRange{Min: 2, Max: 2}},
	})
	conn, err := dialer.DialContext(context.Background(), "tcp", "example.com:443")
	require.NoError(t, err)

	input := append([]byte{22, 3, 1, 0, 4}, []byte("abcd")...)
	_, err = conn.Write(input)
	require.NoError(t, err)
	expected := []byte{
		22, 3, 1, 0, 1, 'a',
		22, 3, 1, 0, 1, 'b',
		22, 3, 1, 0, 1, 'c',
		22, 3, 1, 0, 1, 'd',
	}
	require.Equal(t, expected, bytes.Join(raw.writes, nil))
	require.Len(t, raw.writes, len(expected)/2)
	for _, write := range raw.writes {
		require.Len(t, write, 2)
	}
}

func TestFragmentChainSharesWriteDelayBudget(t *testing.T) {
	inner := newFragmentConn(&recordingConn{}, &fragmentConfig{})
	outer := newFragmentConn(inner, &fragmentConfig{})
	require.Same(t, inner.delayRuntime(), outer.delayRuntime())

	outerBudget := outer.delayRuntime().enterWrite()
	innerBudget := inner.delayRuntime().enterWrite()
	require.Equal(t, outerBudget, innerBudget)
	inner.delayRuntime().leaveWrite()
	outer.delayRuntime().leaveWrite()
}

func TestFragmentDelayHonorsWriteDeadline(t *testing.T) {
	conn := newFragmentConn(&recordingConn{}, mustFragmentConfig(t, FragmentOption{
		Length: &FragmentRange{Min: 1, Max: 1},
		Delay:  &FragmentRange{Min: 100, Max: 100},
	}))
	require.NoError(t, conn.SetWriteDeadline(time.Now().Add(10*time.Millisecond)))

	_, err := conn.Write([]byte("ab"))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

func TestFragmentDelayStopsWhenClosed(t *testing.T) {
	conn := newFragmentConn(&recordingConn{}, mustFragmentConfig(t, FragmentOption{
		Length: &FragmentRange{Min: 1, Max: 1},
		Delay:  &FragmentRange{Min: 100, Max: 100},
	}))
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("ab"))
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, conn.Close())
	require.ErrorIs(t, <-done, net.ErrClosed)
}

func TestFragmentDelayBudget(t *testing.T) {
	conn := newFragmentConn(&recordingConn{}, &fragmentConfig{})
	err := conn.waitDelay(time.Second, time.Now().Add(10*time.Millisecond))
	require.ErrorIs(t, err, errFragmentDelayBudget)
}

func mustFragmentConfig(t *testing.T, option FragmentOption) *fragmentConfig {
	t.Helper()
	config, err := option.build()
	require.NoError(t, err)
	return config
}

type recordingConn struct {
	writes   [][]byte
	maxWrite int
}

func (c *recordingConn) Read([]byte) (int, error) { return 0, nil }

func (c *recordingConn) Write(p []byte) (int, error) {
	n := len(p)
	if c.maxWrite > 0 && n > c.maxWrite {
		n = c.maxWrite
	}
	c.writes = append(c.writes, append([]byte(nil), p[:n]...))
	return n, nil
}

func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return testAddr("local") }
func (c *recordingConn) RemoteAddr() net.Addr             { return testAddr("remote") }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

type stubDialer struct {
	conn net.Conn
}

func (d *stubDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	return &recordingConn{}, nil
}

func (d *stubDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, C.ErrNotSupport
}
