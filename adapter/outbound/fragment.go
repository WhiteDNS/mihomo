package outbound

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const (
	maxFragmentStages     = 8
	maxFragmentDelay      = time.Second
	maxFragmentWriteDelay = 10 * time.Second
)

var errFragmentDelayBudget = errors.New("fragment delay budget exceeded")

type FragmentRange struct {
	Min int64
	Max int64
}

func (r *FragmentRange) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	parts := strings.Split(value, "-")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" {
		return fmt.Errorf("invalid range %q", value)
	}

	min, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil || min < 0 {
		return fmt.Errorf("invalid range %q", value)
	}
	max := min
	if len(parts) == 2 {
		max, err = strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil || max < 0 {
			return fmt.Errorf("invalid range %q", value)
		}
	}
	if min > max {
		min, max = max, min
	}
	r.Min, r.Max = min, max
	return nil
}

func (r FragmentRange) random() (int64, error) {
	if r.Min == r.Max {
		return r.Min, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(r.Max-r.Min+1))
	if err != nil {
		return 0, err
	}
	return r.Min + n.Int64(), nil
}

type FragmentOption struct {
	Packets        string          `proxy:"packets,omitempty"`
	Length         *FragmentRange  `proxy:"length,omitempty"`
	Delay          *FragmentRange  `proxy:"delay,omitempty"`
	Interval       *FragmentRange  `proxy:"interval,omitempty"`
	Lengths        []FragmentRange `proxy:"lengths,omitempty"`
	Delays         []FragmentRange `proxy:"delays,omitempty"`
	MaxSplit       *FragmentRange  `proxy:"max-split,omitempty"`
	MaxSplitCompat *FragmentRange  `proxy:"maxSplit,omitempty"`
}

type fragmentConfig struct {
	tlsHello bool
	from     uint64
	to       uint64
	lengths  []FragmentRange
	delays   []FragmentRange
	maxSplit FragmentRange
}

func (o *FragmentOption) build() (*fragmentConfig, error) {
	c := &fragmentConfig{}
	switch packets := strings.ToLower(strings.TrimSpace(o.Packets)); packets {
	case "":
	case "tlshello":
		c.tlsHello = true
	default:
		var packetRange FragmentRange
		if err := packetRange.UnmarshalText([]byte(packets)); err != nil || packetRange.Min == 0 {
			return nil, fmt.Errorf("packets must be tlshello or a positive range")
		}
		c.from, c.to = uint64(packetRange.Min), uint64(packetRange.Max)
	}

	if len(o.Lengths) > 0 {
		c.lengths = append([]FragmentRange(nil), o.Lengths...)
	} else if o.Length != nil {
		c.lengths = []FragmentRange{*o.Length}
	} else {
		return nil, fmt.Errorf("length or lengths is required")
	}
	if c.lengths[len(c.lengths)-1].Min == 0 {
		return nil, fmt.Errorf("last length range must start above zero")
	}

	if len(o.Delays) > 0 {
		c.delays = append([]FragmentRange(nil), o.Delays...)
	} else {
		if o.Delay != nil && o.Interval != nil {
			return nil, fmt.Errorf("delay and interval cannot both be set")
		}
		switch {
		case o.Delay != nil:
			c.delays = []FragmentRange{*o.Delay}
		case o.Interval != nil:
			c.delays = []FragmentRange{*o.Interval}
		default:
			c.delays = []FragmentRange{{}}
		}
	}
	for _, delay := range c.delays {
		if delay.Max > maxFragmentDelay.Milliseconds() {
			return nil, fmt.Errorf("delay must not exceed %d ms", maxFragmentDelay.Milliseconds())
		}
	}

	if o.MaxSplit != nil && o.MaxSplitCompat != nil {
		return nil, fmt.Errorf("max-split and maxSplit cannot both be set")
	}
	switch {
	case o.MaxSplit != nil:
		c.maxSplit = *o.MaxSplit
	case o.MaxSplitCompat != nil:
		c.maxSplit = *o.MaxSplitCompat
	}
	return c, nil
}

type fragmentDialer struct {
	C.Dialer
	config *fragmentConfig
	err    error
}

func newFragmentDialer(dialer C.Dialer, option *FragmentOption) C.Dialer {
	if option == nil {
		return dialer
	}
	config, err := option.build()
	return &fragmentDialer{Dialer: dialer, config: config, err: err}
}

func newFragmentDialerChain(dialer C.Dialer, fragment *FragmentOption, fragments []FragmentOption) C.Dialer {
	if fragment != nil {
		dialer = newFragmentDialer(dialer, fragment)
	}
	for i := len(fragments) - 1; i >= 0; i-- {
		dialer = newFragmentDialer(dialer, &fragments[i])
	}
	return dialer
}

func (d *fragmentDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.err != nil {
		return nil, d.err
	}
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil || !strings.HasPrefix(strings.ToLower(network), "tcp") {
		return conn, err
	}
	return newFragmentConn(conn, d.config), nil
}

type fragmentConn struct {
	net.Conn
	config *fragmentConfig
	count  uint64
	mu     sync.Mutex

	signalOnce      sync.Once
	closeOnce       sync.Once
	closed          chan struct{}
	deadlineChanged chan struct{}
	deadlineMu      sync.RWMutex
	writeDeadline   time.Time
	closeErr        error
	runtimeOnce     sync.Once
	runtime         *fragmentDelayRuntime
}

type fragmentDelayRuntime struct {
	mu       sync.Mutex
	depth    int
	deadline time.Time
}

func (r *fragmentDelayRuntime) enterWrite() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.depth == 0 {
		r.deadline = time.Now().Add(maxFragmentWriteDelay)
	}
	r.depth++
	return r.deadline
}

func (r *fragmentDelayRuntime) leaveWrite() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.depth--
}

func newFragmentConn(conn net.Conn, config *fragmentConfig) *fragmentConn {
	c := &fragmentConn{Conn: conn, config: config}
	c.initSignals()
	c.delayRuntime()
	return c
}

func (c *fragmentConn) delayRuntime() *fragmentDelayRuntime {
	c.runtimeOnce.Do(func() {
		if inner, ok := c.Conn.(*fragmentConn); ok {
			c.runtime = inner.delayRuntime()
		} else {
			c.runtime = &fragmentDelayRuntime{}
		}
	})
	return c.runtime
}

func (c *fragmentConn) initSignals() {
	c.signalOnce.Do(func() {
		c.closed = make(chan struct{})
		c.deadlineChanged = make(chan struct{}, 1)
	})
}

func (c *fragmentConn) Upstream() any {
	return c.Conn
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	runtime := c.delayRuntime()
	delayBudget := runtime.enterWrite()
	defer runtime.leaveWrite()
	c.count++
	if c.config.tlsHello {
		return c.writeTLSHello(p, delayBudget)
	}
	if c.config.from != 0 && (c.count < c.config.from || c.count > c.config.to) {
		return c.Conn.Write(p)
	}
	return c.writeFragments(p, delayBudget)
}

func (c *fragmentConn) writeTLSHello(p []byte, delayBudget time.Time) (int, error) {
	if c.count != 1 || len(p) <= 5 || p[0] != 22 {
		return c.Conn.Write(p)
	}
	recordLen := 5 + (int(p[3]) << 8) + int(p[4])
	if len(p) < recordLen {
		return c.Conn.Write(p)
	}

	data := p[5:recordLen]
	maxSplit, err := c.config.maxSplit.random()
	if err != nil {
		return 0, err
	}
	merge := len(c.config.delays) == 1 && c.config.delays[0].Max == 0
	var merged []byte

	for from, segment := 0, 0; ; segment++ {
		to, err := c.segmentEnd(from, len(data), segment, maxSplit)
		if err != nil {
			return 5 + from, err
		}
		record := make([]byte, 5+to-from)
		copy(record[:3], p[:3])
		record[3] = byte((to - from) >> 8)
		record[4] = byte(to - from)
		copy(record[5:], data[from:to])

		if merge {
			merged = append(merged, record...)
		} else {
			if _, err = writeFull(c.Conn, record); err != nil {
				return 5 + from, err
			}
			if err = c.delay(segment, delayBudget); err != nil {
				return 5 + to, err
			}
		}
		from = to
		if from == len(data) {
			break
		}
	}

	if merge {
		if _, err = writeFull(c.Conn, merged); err != nil {
			return 0, err
		}
	}
	if len(p) > recordLen {
		n, err := writeFull(c.Conn, p[recordLen:])
		if err != nil {
			return recordLen + n, err
		}
	}
	return len(p), nil
}

func (c *fragmentConn) writeFragments(p []byte, delayBudget time.Time) (int, error) {
	if len(p) == 0 {
		return c.Conn.Write(p)
	}
	maxSplit, err := c.config.maxSplit.random()
	if err != nil {
		return 0, err
	}
	for from, segment := 0, 0; ; segment++ {
		to, err := c.segmentEnd(from, len(p), segment, maxSplit)
		if err != nil {
			return from, err
		}
		n, err := writeFull(c.Conn, p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		if err = c.delay(segment, delayBudget); err != nil {
			return from, err
		}
		if from == len(p) {
			return from, nil
		}
	}
}

func (c *fragmentConn) segmentEnd(from, total, segment int, maxSplit int64) (int, error) {
	rangeIndex := segment
	if rangeIndex >= len(c.config.lengths) {
		rangeIndex = len(c.config.lengths) - 1
	}
	r := c.config.lengths[rangeIndex]
	length, err := r.random()
	if err != nil {
		return 0, err
	}
	if (maxSplit > 0 && int64(segment+1) >= maxSplit) || length >= int64(total-from) {
		return total, nil
	}
	return from + int(length), nil
}

func (c *fragmentConn) delay(segment int, delayBudget time.Time) error {
	if segment >= len(c.config.delays) {
		segment = len(c.config.delays) - 1
	}
	r := c.config.delays[segment]
	delay, err := r.random()
	if err != nil {
		return err
	}
	if delay > 0 {
		return c.waitDelay(time.Duration(delay)*time.Millisecond, delayBudget)
	}
	return nil
}

func (c *fragmentConn) waitDelay(delay time.Duration, delayBudget time.Time) error {
	c.initSignals()
	delayEnd := time.Now().Add(delay)
	for {
		wakeAt := delayEnd
		var wakeErr error
		if delayBudget.Before(wakeAt) {
			wakeAt = delayBudget
			wakeErr = errFragmentDelayBudget
		}
		c.deadlineMu.RLock()
		writeDeadline := c.writeDeadline
		c.deadlineMu.RUnlock()
		if !writeDeadline.IsZero() && writeDeadline.Before(wakeAt) {
			wakeAt = writeDeadline
			wakeErr = os.ErrDeadlineExceeded
		}

		remaining := time.Until(wakeAt)
		if remaining <= 0 {
			return wakeErr
		}
		timer := time.NewTimer(remaining)
		select {
		case <-timer.C:
			return wakeErr
		case <-c.closed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return net.ErrClosed
		case <-c.deadlineChanged:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}
}

func (c *fragmentConn) Close() error {
	c.initSignals()
	c.closeOnce.Do(func() {
		close(c.closed)
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *fragmentConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	c.setWriteDeadline(t)
	return nil
}

func (c *fragmentConn) SetWriteDeadline(t time.Time) error {
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.setWriteDeadline(t)
	return nil
}

func (c *fragmentConn) setWriteDeadline(t time.Time) {
	c.initSignals()
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
}

func writeFull(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return written, io.ErrShortWrite
		}
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
