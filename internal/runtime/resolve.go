package runtime

import (
	"context"
	"errors"
	"fmt"
)

// Resolve looks up a container by name across the supported runtimes.
//
// hint pins the search to a specific runtime ("docker" or "containerd").
// Empty hint means "auto-detect": probe both runtimes and return the
// single match. Multiple matches → ErrAmbiguous (caller passes -r).
func Resolve(ctx context.Context, name, hint string) (*Container, error) {
	candidates := pickRuntimes(ctx, hint)
	if len(candidates) == 0 {
		if hint != "" {
			return nil, fmt.Errorf("%w: %s", ErrNoRuntime, hint)
		}
		return nil, ErrNoRuntime
	}

	var matches []*Container
	var lastErr error
	for _, rt := range candidates {
		c, err := rt.InspectByName(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		matches = append(matches, c)
	}

	switch len(matches) {
	case 0:
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	case 1:
		return matches[0], nil
	default:
		rts := make([]string, len(matches))
		for i, m := range matches {
			rts[i] = m.Runtime
		}
		return nil, fmt.Errorf("%w: %q exists in %v — pass -r to choose",
			ErrAmbiguous, name, rts)
	}
}

func pickRuntimes(ctx context.Context, hint string) []Runtime {
	all := []Runtime{NewDocker(), NewContainerd()}
	var out []Runtime
	for _, rt := range all {
		if hint != "" && rt.Name() != hint {
			continue
		}
		if rt.Available(ctx) {
			out = append(out, rt)
		}
	}
	return out
}

// Available returns the names of runtimes currently usable on this host.
// Used by `version` to surface support status.
func Available(ctx context.Context) []string {
	all := []Runtime{NewDocker(), NewContainerd()}
	var out []string
	for _, rt := range all {
		if rt.Available(ctx) {
			out = append(out, rt.Name())
		}
	}
	return out
}
