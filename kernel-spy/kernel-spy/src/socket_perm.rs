//! after `UnixListener::bind`, chmod the path so unprivileged clients can connect when we run as
//! root (default umask often leaves the socket root-only otherwise)

use std::path::Path;

#[cfg(unix)]
pub fn chmod_0666_for_clients(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)) {
        log::warn!(
            "could not chmod 0666 {}: {e} (unprivileged clients may get permission denied)",
            path.display()
        );
    }
}

#[cfg(not(unix))]
pub fn chmod_0666_for_clients(_path: &Path) {}
