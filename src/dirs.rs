use install_dirs::dirs::InstallDirs;
use lazy_static::lazy_static;
use std::path::Path;

lazy_static! {
    pub static ref INSTALL_DIRS: InstallDirs = install_dirs::parse_env!("lc-login");
}

lazy_static! {
    pub static ref USERS: &'static Path =
        Path::new(std::option_env!("users").unwrap_or("/etc/users"));
}

lazy_static! {
    pub static ref GROUPS: &'static Path =
        Path::new(std::option_env!("groups").unwrap_or("/etc/groups"));
}
