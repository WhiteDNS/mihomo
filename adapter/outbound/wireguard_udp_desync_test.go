package outbound

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	wgconn "github.com/metacubex/wireguard-go/conn"
)

type recordedWireGuardSend struct {
	bufs []byte
	ttl  int
}

type recordingWireGuardBind struct {
	wgconn.Bind
	control   *wireGuardDPIWriteControl
	sends     []recordedWireGuardSend
	failFirst bool
}

func (b *recordingWireGuardBind) Send(bufs [][]byte, _ wgconn.Endpoint) error {
	for _, buf := range bufs {
		b.sends = append(b.sends, recordedWireGuardSend{
			bufs: bytes.Clone(buf),
			ttl:  b.control.ttl,
		})
	}
	if b.failFirst && len(b.sends) == 1 {
		return errors.New("fake send failed")
	}
	return nil
}

func TestWireGuardDPIStrategyEngine(t *testing.T) {
	if (&AmneziaWGOption{JC: 2, JMin: 64, JMax: 64}).hasHandshakeChanges() {
		t.Fatal("legacy junk-only options must keep standard WireGuard")
	}
	if !(&AmneziaWGOption{S1: 15}).hasHandshakeChanges() {
		t.Fatal("Amnezia handshake fields must keep the AmneziaWG device")
	}
	awgPattern, err := newWireGuardInitiationPattern(&AmneziaWGOption{S1: 10, H1: "100-200"})
	if err != nil {
		t.Fatal(err)
	}
	awgHandshake := make([]byte, wireGuardHandshakeInitiationSize+10)
	binary.LittleEndian.PutUint32(awgHandshake[10:], 150)
	if !awgPattern.matches(awgHandshake) {
		t.Fatal("Amnezia initiation range was not recognized")
	}

	option := WireGuardDPIOption{FakeCount: 4, FakeMinSize: 64, FakeMaxSize: 64, FakeTTL: 3}
	if err := option.validate(); err != nil {
		t.Fatal(err)
	}
	awgControl := &wireGuardDPIWriteControl{}
	awgRecorder := &recordingWireGuardBind{control: awgControl}
	awgBind := &wireGuardDPIBind{
		Bind:      awgRecorder,
		option:    option,
		pattern:   awgPattern,
		control:   awgControl,
		identity:  "profile-awg",
		rotations: make(map[string]uint32),
	}
	if err := awgBind.Send([][]byte{awgHandshake}, nil); err != nil {
		t.Fatal(err)
	}
	if len(awgRecorder.sends) != option.FakeCount+1 {
		t.Fatalf("Amnezia initiation sent %d packets, want %d", len(awgRecorder.sends), option.FakeCount+1)
	}
	var awgRealCount int
	for _, send := range awgRecorder.sends {
		if bytes.Equal(send.bufs, awgHandshake) {
			awgRealCount++
		}
	}
	awgReal := awgRecorder.sends[len(awgRecorder.sends)-1]
	if awgRealCount != 1 || awgReal.ttl != 0 || !bytes.Equal(awgReal.bufs, awgHandshake) {
		t.Fatal("Amnezia initiation must be the final packet and sent exactly once without fake TTL")
	}

	standardHandshake := make([]byte, wireGuardHandshakeInitiationSize)
	binary.LittleEndian.PutUint32(standardHandshake, 1)
	standardStart := len(awgRecorder.sends)
	if err := awgBind.Send([][]byte{standardHandshake}, nil); err != nil {
		t.Fatal(err)
	}
	if len(awgRecorder.sends) != standardStart+1 || !bytes.Equal(awgRecorder.sends[standardStart].bufs, standardHandshake) {
		t.Fatal("standard initiation must not be classified as an Amnezia initiation")
	}

	control := &wireGuardDPIWriteControl{}
	recorder := &recordingWireGuardBind{control: control}
	bind := &wireGuardDPIBind{
		Bind:      recorder,
		option:    option,
		pattern:   wireGuardInitiationPattern{size: wireGuardHandshakeInitiationSize, typeMin: 1, typeMax: 1},
		control:   control,
		identity:  "profile-a",
		rotations: make(map[string]uint32),
	}

	pairedPlan := bind.fakePlan(wireGuardDPIStrategyPairedDuplicates)
	if !bytes.Equal(pairedPlan[0], pairedPlan[1]) || !bytes.Equal(pairedPlan[2], pairedPlan[3]) {
		t.Fatal("paired strategy did not duplicate adjacent decoys")
	}
	interleavedPlan := bind.fakePlan(wireGuardDPIStrategyInterleavedDuplicates)
	if !bytes.Equal(interleavedPlan[0], interleavedPlan[2]) || !bytes.Equal(interleavedPlan[1], interleavedPlan[3]) {
		t.Fatal("interleaved strategy did not preserve controlled ordering")
	}
	randomPlan := bind.fakePlan(wireGuardDPIStrategyBurst)
	if bytes.Equal(randomPlan[0], randomPlan[1]) {
		t.Fatal("independent decoys were not randomized")
	}

	handshake := make([]byte, wireGuardHandshakeInitiationSize)
	binary.LittleEndian.PutUint32(handshake, 1)
	handshake[10] = 42
	seenStrategies := make(map[wireGuardDPIStrategy]bool)
	for attempt := 0; attempt < int(wireGuardDPIStrategyCount); attempt++ {
		strategy := bind.nextStrategy(nil)
		bind.rotations[""]--
		start := len(recorder.sends)
		if err := bind.Send([][]byte{handshake}, nil); err != nil {
			t.Fatal(err)
		}
		sends := recorder.sends[start:]
		if len(sends) != option.FakeCount+1 {
			t.Fatalf("strategy %d sent %d packets, want %d", strategy, len(sends), option.FakeCount+1)
		}
		for _, fake := range sends[:option.FakeCount] {
			if len(fake.bufs) != 64 || fake.bufs[0] != 0 {
				t.Fatalf("strategy %d emitted a valid or incorrectly sized decoy", strategy)
			}
			if strategy == wireGuardDPIStrategyTTL && fake.ttl != option.FakeTTL {
				t.Fatalf("TTL strategy used ttl=%d, want %d", fake.ttl, option.FakeTTL)
			}
			if strategy != wireGuardDPIStrategyTTL && fake.ttl != 0 {
				t.Fatalf("strategy %d unexpectedly used ttl=%d", strategy, fake.ttl)
			}
		}
		real := sends[len(sends)-1]
		if real.ttl != 0 || !bytes.Equal(real.bufs, handshake) {
			t.Fatal("real handshake was modified or inherited fake TTL")
		}
		seenStrategies[strategy] = true
	}
	if len(seenStrategies) != int(wireGuardDPIStrategyCount) {
		t.Fatalf("rotation covered %d strategies, want %d", len(seenStrategies), wireGuardDPIStrategyCount)
	}

	transport := make([]byte, 32)
	binary.LittleEndian.PutUint32(transport, 4)
	start := len(recorder.sends)
	if err := bind.Send([][]byte{transport}, nil); err != nil {
		t.Fatal(err)
	}
	if len(recorder.sends) != start+1 || !bytes.Equal(recorder.sends[start].bufs, transport) {
		t.Fatal("non-initiation packets must pass through unchanged")
	}

	failControl := &wireGuardDPIWriteControl{}
	failingRecorder := &recordingWireGuardBind{control: failControl, failFirst: true}
	failOpenBind := &wireGuardDPIBind{
		Bind:      failingRecorder,
		option:    option,
		pattern:   bind.pattern,
		control:   failControl,
		identity:  "profile-b",
		rotations: make(map[string]uint32),
	}
	if err := failOpenBind.Send([][]byte{handshake}, nil); err != nil {
		t.Fatal(err)
	}
	if len(failingRecorder.sends) != 2 || !bytes.Equal(failingRecorder.sends[1].bufs, handshake) {
		t.Fatal("a decoy failure must still send the real handshake")
	}
}
