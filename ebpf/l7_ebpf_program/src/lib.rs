//! eBPF program build component for L7 network session resolution
//!
//! This crate is responsible for compiling the eBPF C program into an object file
//! that can be loaded by the main application. The actual eBPF program is written
//! in C and compiled using clang during the build process.
//!
//! The build.rs script handles the compilation and makes the object file available
//! to the main application through environment variables.

// This is a build-time only crate, so it doesn't need any runtime code