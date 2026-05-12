// Package config: YAML schema for iptables-redirect chaos-tproxy.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Loader struct {
	ProxyMark uint32                 `yaml:"proxy_mark"`
	IfaceWAN  string                 `yaml:"iface_wan"`
	Proxy     map[string]interface{} `yaml:",inline"`
}

func defaults(l *Loader) {
	if l.ProxyMark == 0 {
		l.ProxyMark = 0xCFC1
	}
	if l.IfaceWAN == "" {
		l.IfaceWAN = "eth0"
	}
}

func Load(path string) (*Loader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var l Loader
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	defaults(&l)
	return &l, nil
}

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
			n, ok := p.(int)
			if !ok || n < 0 || n > 0xFFFF {
				return nil, fmt.Errorf("invalid port: %v", p)
			}
			out = append(out, uint16(n))
		}
		return out, nil
	}
	return nil, fmt.Errorf("unexpected proxy_ports type %T", raw)
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
		if c == ',' || c == ' ' {
			if err := emit(); err != nil {
				return nil, err
			}
			continue
		}
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("invalid char %q", c)
		}
		cur = cur*10 + int(c-'0')
		have = true
	}
	if err := emit(); err != nil {
		return nil, err
	}
	return out, nil
}

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
