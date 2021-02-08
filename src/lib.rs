#![deny(warnings, unsafe_code)]

#[cfg(not(unix))]
compile_error!("This is a replacement for the unix login programs, and is only available on unix");

pub mod dirs;

pub mod password;

pub mod users;
