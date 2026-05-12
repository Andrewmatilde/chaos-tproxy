// Package bpfload contains the bpf2go-generated bindings for the eBPF
// program in ../../bpf/redirect.bpf.c.
//
// Code generation runs at image-build time via `go generate`. The
// pre-built object is embedded into the loader binary so the runtime
// image doesn't need clang.
package bpfload

//go:generate bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu -I/usr/include" Redirect ../../bpf/redirect.bpf.c
