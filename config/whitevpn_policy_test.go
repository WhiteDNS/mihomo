package config

import (
	"strings"
	"testing"
)

const whitevpnControl = `mixed-port: 2080
external-controller: 127.0.0.1:19090
secret: test-only
allow-lan: false
dns: {enable: true, listen: '127.0.0.1:1053'}
tun: {enable: false}
proxies:
  - &proxy {name: first, type: socks5, server: 127.0.0.1, port: 1080}
  - {<<: *proxy, name: second}
proxy-groups: [{name: select, type: select, proxies: [first, second]}]
rules: [MATCH,select]
`

func TestWhiteVPNConfigBoundary(t *testing.T) {
	for _, input := range []string{whitevpnControl, strings.Replace(whitevpnControl, "allow-lan: false", "allow-lan: true\nbind-address: 0.0.0.0", 1)} {
		raw := DefaultRawConfig()
		if err := unmarshalWhiteVPNConfig([]byte(input), raw); err != nil {
			t.Fatal(err)
		}
		if len(raw.Proxy) != 2 || raw.Proxy[1]["server"] != "127.0.0.1" {
			t.Fatal("legitimate nested alias was not retained")
		}
	}
	for name, attack := range map[string]string{
		"listener":        "listeners: [{name: injected, type: http, listen: 0.0.0.0, port: 18080}]\n",
		"quoted listener": "'listeners': [{name: injected, type: http, listen: 0.0.0.0, port: 18080}]\n",
		"tunnel":          "tunnels: [{network: [tcp, udp], address: '0.0.0.0:18081', target: '127.0.0.1:80'}]\n",
		"root merge":      "<<: {listeners: [{name: injected, type: http, port: 18080}]}\n",
		"unknown":         "future-server: {enable: true}\n",
		"alternate port":  "socks-port: 18082\n",
		"controller unix": "external-controller-unix: /tmp/controller.sock\n",
		"controller tls":  "external-controller-tls: '0.0.0.0:8443'\n",
		"ui updater":      "external-ui-url: https://example.com/ui.zip\n",
		"ntp":             "ntp: {enable: true, write-to-system: true}\n",
		"tls server":      "tls: {certificate: certificate, private-key: key}\n",
		"duplicate":       "mixed-port: 8080\n",
		"document":        "---\nlisteners: []\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := unmarshalWhiteVPNConfig([]byte(whitevpnControl+attack), DefaultRawConfig()); err == nil {
				t.Fatal("accepted hostile configuration")
			}
		})
	}
	for _, input := range []string{
		"[]", "null", "{}",
		strings.Replace(whitevpnControl, "127.0.0.1:19090", "0.0.0.0:19090", 1),
		strings.Replace(whitevpnControl, "127.0.0.1:1053", "0.0.0.0:1053", 1),
		strings.Replace(whitevpnControl, "secret: test-only", "secret: ''", 1),
		strings.Replace(whitevpnControl, "tun: {enable: false}", "tun: {enable: true}", 1),
	} {
		if err := unmarshalWhiteVPNConfig([]byte(input), DefaultRawConfig()); err == nil {
			t.Fatal("accepted invalid runtime boundary")
		}
	}
}
