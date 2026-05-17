// Package config defines the YAML schema for chaos-tproxy-ebpf-loader.
//
// The shape mirrors chaos-tproxy-proxy's RawConfig (so we can pass
// `proxy` straight through without re-marshaling), with one extra
// loader-side field: `proxy_mark`.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Top-level config consumed by cmd/loader.
//
// The Proxy field is forwarded verbatim to chaos-tproxy-proxy over UDS
// (with proxy_mark and send_listener_fd injected by the loader before
// serialization). The Container field is informational — the loader
// expects to already be running inside the target's netns via
// `docker run --network=container:<name>`.
type Loader struct {
	Container string                 `yaml:"container"`
	ProxyMark uint32                 `yaml:"proxy_mark"`
	IfaceWAN  string                 `yaml:"iface_wan"`
	IfaceLO   string                 `yaml:"iface_lo"`
	Proxy     map[string]interface{} `yaml:",inline"`
}

func defaults(l *Loader) {
	if l.ProxyMark == 0 {
		l.ProxyMark = 0xCFC1
	}
	if l.IfaceWAN == "" {
		l.IfaceWAN = "eth0"
	}
	if l.IfaceLO == "" {
		l.IfaceLO = "lo"
	}
}

// Load reads a YAML config from path.
func Load(path string) (*Loader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var l Loader
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	defaults(&l)
	return &l, nil
}

// ProxyPorts extracts the port list from the inline `proxy_ports` YAML
// field, accepting both the legacy string form ("80,8080") and a list
// of integers.
func (l *Loader) ProxyPorts() ([]uint16, error) {
	raw, ok := l.Proxy["proxy_ports"]
	if !ok {
		return nil, nil
	}
	switch v := raw.(type) {
	case string:
		return parsePortString(v)
	case []interface{}:
		out := make([]uint16, 0, len(v))
		for _, p := range v {
			switch n := p.(type) {
			case int:
				if n < 0 || n > 0xFFFF {
					return nil, fmt.Errorf("port out of range: %d", n)
				}
				out = append(out, uint16(n))
			default:
				return nil, fmt.Errorf("unexpected port entry type %T", p)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected proxy_ports type %T", raw)
	}
}

func parsePortString(s string) ([]uint16, error) {
	if s == "" {
		return nil, nil
	}
	var out []uint16
	cur := 0
	have := false
	emit := func() error {
		if !have {
			return nil
		}
		if cur < 0 || cur > 0xFFFF {
			return fmt.Errorf("port out of range: %d", cur)
		}
		out = append(out, uint16(cur))
		cur = 0
		have = false
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' {
			if err := emit(); err != nil {
				return nil, err
			}
			continue
		}
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("invalid char %q in proxy_ports", c)
		}
		cur = cur*10 + int(c-'0')
		have = true
	}
	if err := emit(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListenPort extracts `listen_port`. Defaults to 58080.
func (l *Loader) ListenPort() uint16 {
	v, ok := l.Proxy["listen_port"]
	if !ok {
		return 58080
	}
	if n, ok := v.(int); ok && n > 0 && n <= 0xFFFF {
		return uint16(n)
	}
	return 58080
}
