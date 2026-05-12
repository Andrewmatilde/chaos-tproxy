module github.com/chaos-mesh/chaos-tproxy/chaos-tproxy-iptables-loader

go 1.22

require (
	github.com/coreos/go-iptables v0.7.0
	github.com/vishvananda/netlink v1.2.1-beta.2
	golang.org/x/sys v0.20.0
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/vishvananda/netns v0.0.4 // indirect
