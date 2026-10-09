// Exercise the vendored pool's unit tests from this workspace, whose dependency
// patches and test utilities match the binaries. TLSN is a patched dependency,
// so Cargo cannot directly run its dev-dependencies from the root workspace.
#[allow(dead_code)]
#[path = "../../../vendor/tlsn/crates/tlsn/src/vole_pool.rs"]
mod vole_pool;
