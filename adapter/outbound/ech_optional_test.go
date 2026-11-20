package outbound

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/tls"
)

type noECHResolver struct {
	resolver.Resolver
	calls *atomic.Int32
	block bool
}

func (noECHResolver) Invalid() bool { return true }

func (r noECHResolver) ResolveECH(ctx context.Context, _ string) ([]byte, error) {
	if r.calls != nil {
		r.calls.Add(1)
	}
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, errors.New("no ECH config found in DNS records")
}

func useECHResolver(t *testing.T, r resolver.Resolver) {
	previous := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = r
	optionalECHMisses.Clear()
	t.Cleanup(func() {
		resolver.ProxyServerHostResolver = previous
		optionalECHMisses.Clear()
	})
}

func TestOptionalECHLookupIsBoundedAndBackedOff(t *testing.T) {
	calls := &atomic.Int32{}
	useECHResolver(t, noECHResolver{calls: calls, block: true})
	config, err := ECHOptions{Enable: true, Optional: true}.Parse()
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	for i := 0; i < 3; i++ {
		tlsConfig := &tls.Config{ServerName: "blocked.example.com"}
		if err := config.ClientHandle(context.Background(), tlsConfig); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > optionalECHLookupTimeout+time.Second {
		t.Fatalf("three dials took %v; lookups were not bounded or backed off", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("ECH lookups = %d, want 1 while backing off", got)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	optionalECHMisses.Clear()
	if err := config.ClientHandle(canceled, &tls.Config{ServerName: "blocked.example.com"}); err == nil {
		t.Fatal("a canceled dial must not fall back to plain TLS")
	}
}

func TestOptionalECHFallsBackToPlainTLS(t *testing.T) {
	useECHResolver(t, noECHResolver{})

	for _, test := range []struct {
		optional bool
		wantErr  bool
	}{{optional: false, wantErr: true}, {optional: true, wantErr: false}} {
		config, err := ECHOptions{Enable: true, Optional: test.optional}.Parse()
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig := &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12}
		err = config.ClientHandle(context.Background(), tlsConfig)
		if (err != nil) != test.wantErr {
			t.Fatalf("optional=%v: err=%v, wantErr=%v", test.optional, err, test.wantErr)
		}
		if test.optional && (tlsConfig.EncryptedClientHelloConfigList != nil || tlsConfig.MinVersion != tls.VersionTLS12) {
			t.Fatalf("optional fallback changed the plain TLS config: %+v", tlsConfig)
		}
	}
}
