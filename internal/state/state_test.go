package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withStateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("CHAOS_TPROXY_STATE_DIR", d)
	return d
}

func TestWriteReadRoundTrip(t *testing.T) {
	withStateDir(t)
	in := &Entry{
		Container:   "web",
		Runtime:     "docker",
		ContainerID: "abc123",
		NetnsPath:   "/proc/42/ns/net",
		ConfigPath:  "/etc/chaos.yaml",
		PID:         os.Getpid(),
		StartedAt:   time.Date(2026, 5, 14, 10, 0, 0, 0, time.UTC),
		Detached:    true,
	}
	if err := Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := Read("web")
	if err != nil || out == nil {
		t.Fatalf("Read: %v / %v", out, err)
	}
	if out.Container != in.Container || out.Runtime != in.Runtime ||
		out.PID != in.PID || !out.StartedAt.Equal(in.StartedAt) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestReadMissingReturnsNil(t *testing.T) {
	withStateDir(t)
	e, err := Read("absent")
	if err != nil || e != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", e, err)
	}
}

func TestSanitizeStripsLeadingSlash(t *testing.T) {
	withStateDir(t)
	// docker names come back as "/web"; the on-disk file should be web.json.
	in := &Entry{Container: "/web", PID: os.Getpid()}
	if err := Write(in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := filepath.Join(Dir(), "web.json")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected %s to exist: %v", want, err)
	}
}

func TestEnsureNotRunningWithLiveEntry(t *testing.T) {
	withStateDir(t)
	if err := Write(&Entry{Container: "web", PID: os.Getpid()}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	err := EnsureNotRunning("web")
	if err == nil {
		t.Fatal("expected ErrAlreadyInjected, got nil")
	}
}

func TestEnsureNotRunningSweepsStale(t *testing.T) {
	dir := withStateDir(t)
	// pid 9999999 is overwhelmingly likely to be dead in our linux test
	// box; PIDAlive returns false → EnsureNotRunning wipes the file.
	if err := Write(&Entry{Container: "web", PID: 9999999}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := EnsureNotRunning("web"); err != nil {
		t.Fatalf("EnsureNotRunning: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "web.json")); !os.IsNotExist(err) {
		t.Fatalf("expected file removed; stat err = %v", err)
	}
}

func TestListSkipsDeadAndCollects(t *testing.T) {
	dir := withStateDir(t)
	_ = Write(&Entry{Container: "alive", PID: os.Getpid(), StartedAt: time.Now()})
	_ = Write(&Entry{Container: "dead", PID: 9999999, StartedAt: time.Now()})

	entries, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Container != "alive" {
		t.Fatalf("expected only alive entry, got: %+v", entries)
	}
	// dead.json should be gone from disk
	if _, err := os.Stat(filepath.Join(dir, "dead.json")); !os.IsNotExist(err) {
		t.Fatalf("expected dead.json removed; stat err = %v", err)
	}
}

func TestPIDAlive(t *testing.T) {
	if !PIDAlive(os.Getpid()) {
		t.Fatal("own pid should be alive")
	}
	if PIDAlive(9999999) {
		t.Fatal("pid 9999999 should not be alive")
	}
	if PIDAlive(0) || PIDAlive(-1) {
		t.Fatal("non-positive pids must not be alive")
	}
}

func TestListWithEmptyDir(t *testing.T) {
	withStateDir(t)
	entries, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil slice for empty dir, got %v", entries)
	}
}
