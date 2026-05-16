// Package state owns the on-disk record of active chaos injections.
//
// One injection == one file under StateDir named "<sanitized-name>.json".
// The file is written by `run` right after the proxy + BPF are ready and
// removed on clean exit. `ls` reads the directory; entries whose pid is
// gone are auto-collected.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// DefaultDir is /var/run/chaos-tproxy. On modern systems /var/run is
// a symlink to /run (tmpfs), so entries are automatically wiped at
// reboot.
const DefaultDir = "/var/run/chaos-tproxy"

// Entry is one active injection's metadata. Written as JSON.
type Entry struct {
	Container   string    `json:"container"`
	Runtime     string    `json:"runtime"`
	ContainerID string    `json:"container_id"`
	NetnsPath   string    `json:"netns_path"`
	ConfigPath  string    `json:"config_path"`
	PID         int       `json:"pid"`
	StartedAt   time.Time `json:"started_at"`
	LogPath     string    `json:"log_path,omitempty"`
	Detached    bool      `json:"detached"`
}

// ErrAlreadyInjected is returned when state already exists for a
// container and the recorded pid is still alive.
var ErrAlreadyInjected = errors.New("already injected")

// Dir returns the resolved state directory. Override with
// CHAOS_TPROXY_STATE_DIR for non-root / test scenarios.
func Dir() string {
	if d := os.Getenv("CHAOS_TPROXY_STATE_DIR"); d != "" {
		return d
	}
	return DefaultDir
}

// FileFor returns the absolute path of the state file for the given
// container name (sanitized into something safe for a filename).
func FileFor(container string) string {
	return filepath.Join(Dir(), sanitize(container)+".json")
}

func sanitize(s string) string {
	// Allow only a conservative charset; replace everything else with
	// underscore. Strip leading slash (docker names come back as "/web").
	s = strings.TrimPrefix(s, "/")
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "unnamed"
	}
	return string(b)
}

// Write atomically persists e to its state file. Creates the state
// directory on demand.
func Write(e *Entry) error {
	if err := os.MkdirAll(Dir(), 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	buf, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	path := FileFor(e.Container)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0644); err != nil {
		return fmt.Errorf("write state %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename state %s: %w", path, err)
	}
	return nil
}

// Read returns the state entry for the given container, or nil if no
// file exists. Returns an error only on I/O / parse failure.
func Read(container string) (*Entry, error) {
	path := FileFor(container)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	return &e, nil
}

// Remove deletes the state file for the given container. Missing file
// is not an error.
func Remove(container string) error {
	if err := os.Remove(FileFor(container)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// PIDAlive reports whether the given pid is a currently running process.
func PIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// signal 0 is a "does this process exist + can I signal it?" probe.
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// EnsureNotRunning returns ErrAlreadyInjected if a live injection exists
// for container; otherwise removes any stale state file and returns nil.
func EnsureNotRunning(container string) error {
	e, err := Read(container)
	if err != nil {
		return err
	}
	if e == nil {
		return nil
	}
	if PIDAlive(e.PID) {
		return fmt.Errorf("%w: %s (pid %d) — kill the pid or wait for it to exit",
			ErrAlreadyInjected, container, e.PID)
	}
	// stale — wipe it.
	_ = Remove(container)
	return nil
}

// List walks the state directory and returns every entry. Entries whose
// pid is no longer alive are removed from disk and excluded from the
// result.
func List() ([]*Entry, error) {
	d := Dir()
	ents, err := os.ReadDir(d)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Entry
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		path := filepath.Join(d, ent.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		if !PIDAlive(e.PID) {
			_ = os.Remove(path)
			continue
		}
		out = append(out, &e)
	}
	return out, nil
}
