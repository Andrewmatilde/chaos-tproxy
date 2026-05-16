package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Docker talks to the local Docker daemon via its unix socket. We use a
// hand-rolled HTTP client rather than github.com/docker/docker/client to
// keep the dependency footprint tiny — we only need /containers/{id}/json.
type Docker struct {
	SocketPath string
	client     *http.Client
}

// NewDocker returns a Docker runtime client bound to the standard socket
// (/var/run/docker.sock). Override with DOCKER_HOST=unix:///path if needed.
func NewDocker() *Docker {
	sock := "/var/run/docker.sock"
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		if u, err := url.Parse(h); err == nil && u.Scheme == "unix" {
			sock = u.Path
		}
	}
	return &Docker{
		SocketPath: sock,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", sock)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

func (d *Docker) Name() string { return "docker" }

func (d *Docker) Available(ctx context.Context) bool {
	if _, err := os.Stat(d.SocketPath); err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return false
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (d *Docker) InspectByName(ctx context.Context, name string) (*Container, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://docker/containers/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker inspect %s: %w", name, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	default:
		return nil, fmt.Errorf("docker inspect %s: HTTP %d", name, resp.StatusCode)
	}

	var info struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Pid     int  `json:"Pid"`
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode docker inspect: %w", err)
	}
	if !info.State.Running {
		return nil, fmt.Errorf("container %s is not running", name)
	}
	return &Container{
		Runtime:   "docker",
		ID:        info.ID,
		Name:      info.Name,
		PID:       info.State.Pid,
		NetnsPath: fmt.Sprintf("/proc/%d/ns/net", info.State.Pid),
	}, nil
}
