package config

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"

	"go.yaml.in/yaml/v3"
)

// Decode the final Android configuration once, before ParseRawConfig has side effects.
// Subscription data may select outbound routing, but cannot add native servers.
func unmarshalWhiteVPNConfig(buf []byte, raw *RawConfig) error {
	decoder := yaml.NewDecoder(bytes.NewReader(buf))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("WhiteVPN config must be a mapping")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("WhiteVPN config must contain exactly one YAML document")
	}
	root := document.Content[0]
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("WhiteVPN config keys must be strings; root merges are unsupported")
		}
		switch key.Value {
		case "proxies", "proxy-groups", "proxy-providers", "rules", "rule-providers", "sub-rules",
			"hosts", "sniffer", "profile", "tls", "experimental",
			"mode", "unified-delay", "log-level", "ipv6", "tcp-concurrent", "find-process-mode",
			"global-client-fingerprint", "global-ua", "etag-support", "keep-alive-idle",
			"keep-alive-interval", "disable-keep-alive", "geodata-mode", "geodata-loader", "geosite-matcher",
			"mixed-port", "allow-lan", "bind-address", "authentication", "skip-auth-prefixes",
			"lan-allowed-ips", "lan-disallowed-ips", "external-controller", "secret", "dns", "tun":
		default:
			return fmt.Errorf("unsupported WhiteVPN config key %q", key.Value)
		}
	}
	// Node.Decode enforces duplicate keys, resolves nested aliases, and produces the
	// exact typed object subsequently consumed by ParseRawConfig.
	if err := root.Decode(raw); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(raw.ExternalController)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || host != "127.0.0.1" || portErr != nil || portNumber < 1 || portNumber > 65535 || raw.Secret == "" {
		return fmt.Errorf("WhiteVPN controller must use authenticated IPv4 loopback")
	}
	if raw.MixedPort != 2080 || raw.DNS.Listen != "127.0.0.1:1053" || raw.Tun.Enable {
		return fmt.Errorf("WhiteVPN requires its app-managed proxy, DNS and VPN sockets")
	}
	if raw.TLS.Certificate != "" || raw.TLS.PrivateKey != "" || raw.TLS.ClientAuthType != "" || raw.TLS.ClientAuthCert != "" || raw.TLS.EchKey != "" {
		return fmt.Errorf("WhiteVPN does not support TLS server configuration")
	}
	return nil
}
