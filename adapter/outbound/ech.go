package outbound

import (
	"context"
	"encoding/base64"
	"fmt"

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
			list, err := resolver.ResolveECHWithResolver(ctx, serverName, resolver.ProxyServerHostResolver)
			if err != nil && o.Optional && ctx.Err() == nil {
				log.Debugln("[ECH] %s: continuing without ECH: %v", serverName, err)
				return nil, nil
			}
			return list, err
		}
	}
	return echConfig, nil
}
