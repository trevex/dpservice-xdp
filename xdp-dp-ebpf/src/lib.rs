#![no_std]

// This crate's real content is the bpfel-only program binary in `src/main.rs`. This empty
// `#![no_std]` library target exists so that `xdp-dp`'s host-built `path` build-dependency on
// this crate resolves (build-dependencies compile the lib target for the host).
