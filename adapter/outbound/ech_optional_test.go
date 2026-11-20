package outbound

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/tls"
)

type noECHResolver struct{ resolver.Resolver }

func (noECHResolver) Invalid() bool { return true }

func (noECHResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, errors.New("no ECH config found in DNS records")
}

func TestOptionalECHFallsBackToPlainTLS(t *testing.T) {
	previous := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = noECHResolver{}
	t.Cleanup(func() { resolver.ProxyServerHostResolver = previous })

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
