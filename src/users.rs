use std::{ffi::OsString, io::ErrorKind, path::PathBuf};

pub fn get_user_dir(name: &str) -> PathBuf {
    let mut dir = PathBuf::from(*crate::dirs::USERS);
    dir.push(name);
    dir
}

pub fn get_user_name(uid: i32) -> std::io::Result<Option<OsString>> {
    let mut path = PathBuf::from(*crate::dirs::USERS);
    path.push(uid.to_string());
    path.push("name");
    path = std::fs::read_link(path)?;
    Ok(path.file_name().map(|v| v.to_owned()))
}

pub fn get_user_id(name: &str) -> std::io::Result<i32> {
    let mut dir = PathBuf::from(*crate::dirs::USERS);
    dir.push(name);
    dir = std::fs::read_link(dir)?;
    dir.file_name()
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "No file component in username link")
        })?
        .to_str()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "non-UTF file name"))?
        .parse()
        .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
}

pub fn get_home_dir(st: &str) -> std::io::Result<Option<PathBuf>> {
    let mut dir = PathBuf::from(*crate::dirs::USERS);
    dir.push(st);
    dir.push("home");

    match std::fs::metadata(&dir) {
        Ok(_) => Some(std::fs::read_link(dir)).transpose(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn get_root_dir(st: &str) -> std::io::Result<Option<PathBuf>> {
    let mut dir = PathBuf::from(*crate::dirs::USERS);
    dir.push(st);
    dir.push("root");

    match std::fs::metadata(&dir) {
        Ok(_) => Some(std::fs::read_link(dir)).transpose(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn get_shell(st: &str) -> std::io::Result<Option<PathBuf>> {
    let mut dir = PathBuf::from(*crate::dirs::USERS);
    dir.push(st);
    dir.push("shell");

    match std::fs::metadata(&dir) {
        Ok(_) => Some(std::fs::read_link(dir)).transpose(),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
