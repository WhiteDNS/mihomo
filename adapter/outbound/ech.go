package outbound

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

type ECHOptions struct {
	Enable bool   `proxy:"enable,omitempty" obfs:"enable,omitempty"`
	Config string `proxy:"config,omitempty" obfs:"config,omitempty"`

	QueryServerName string `proxy:"query-server-name,omitempty" obfs:"query-server-name,omitempty"`

	// Optional dials without ECH when no config can be resolved, so ECH can be
	// enabled by default for servers that may or may not publish an HTTPS record.
	Optional bool `proxy:"optional,omitempty" obfs:"optional,omitempty"`
}

func (o ECHOptions) Parse() (*ech.Config, error) {
	if !o.Enable {
		return nil, nil
	}
	echConfig := &ech.Config{}
	if o.Config != "" {
		list, err := base64.StdEncoding.DecodeString(o.Config)
		if err != nil {
			return nil, fmt.Errorf("base64 decode ech config string failed: %v", err)
		}
		echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
			return list, nil
		}
	} else {
		echConfig.GetEncryptedClientHelloConfigList = func(ctx context.Context, serverName string) ([]byte, error) {
			if o.QueryServerName != "" { // overrides the domain name used for ECH HTTPS record queries
				serverName = o.QueryServerName
			}
			if o.Optional {
				return resolveOptionalECH(ctx, serverName)
			}
			return resolver.ResolveECHWithResolver(ctx, serverName, resolver.ProxyServerHostResolver)
		}
	}
	return echConfig, nil
}

const (
	// Optional ECH must not stall every dial where HTTPS DNS records are dropped.
	optionalECHLookupTimeout = 2 * time.Second
	optionalECHRetryAfter    = time.Minute
)

// optionalECHMisses maps a server name to the time its next ECH lookup is allowed.
var optionalECHMisses sync.Map

func resolveOptionalECH(ctx context.Context, serverName string) ([]byte, error) {
	if retryAt, ok := optionalECHMisses.Load(serverName); ok && time.Now().Before(retryAt.(time.Time)) {
		return nil, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, optionalECHLookupTimeout)
	defer cancel()
	list, err := resolver.ResolveECHWithResolver(lookupCtx, serverName, resolver.ProxyServerHostResolver)
	if err == nil && len(list) > 0 {
		optionalECHMisses.Delete(serverName)
		return list, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	optionalECHMisses.Store(serverName, time.Now().Add(optionalECHRetryAfter))
	log.Debugln("[ECH] %s: continuing without ECH: %v", serverName, err)
	return nil, nil
}
