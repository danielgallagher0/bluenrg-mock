# BlueNRG Mocks
This crate provides a mock implementation of
[BlueNRG](https://crates.io/crates/bluenrg) traits.  It is _not_
`no_std` since it is intended to be used within unit tests, which are
expected to run on the host, with a full standard library.

# Release Schedule

This crate is intended to be released in lockstep with BlueNRG.
