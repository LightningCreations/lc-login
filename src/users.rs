use std::{
    ffi::OsStr,
    io::{ErrorKind, Read, Write},
    mem::forget,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use std::os::unix::prelude::*;

use itertools::Itertools;

use crate::password::PasswordHeader;

pub struct UserHandle {
    path: PathBuf,
}

impl UserHandle {
    pub fn from_name<S: AsRef<OsStr>>(name: S) -> std::io::Result<Self> {
        let mut path = PathBuf::from(*crate::dirs::USERS);
        path.push(name.as_ref());
        match std::fs::read_link(&path) {
            Ok(p) => path = p,
            Err(e) if e.kind() == ErrorKind::InvalidInput => {}
            Err(e) => return Err(e),
        }

        Ok(Self { path })
    }

    pub fn from_uid(uid: u32) -> Self {
        let mut path = PathBuf::from(*crate::dirs::USERS);
        path.push(uid.to_string());
        Self { path }
    }

    pub fn from_name_in<S: AsRef<OsStr>, P: AsRef<Path>>(
        name: S,
        chroot: P,
    ) -> std::io::Result<Self> {
        let mut path = PathBuf::from(chroot.as_ref());

        path.push(crate::dirs::USERS.strip_prefix("/").unwrap());
        path.push(name.as_ref());
        match std::fs::read_link(&path) {
            Ok(p) => path = p,
            Err(e) if e.kind() == ErrorKind::InvalidInput => {}
            Err(e) => return Err(e),
        }

        Ok(Self { path })
    }

    pub fn from_uid_in<P: AsRef<Path>>(uid: u32, chroot: P) -> Self {
        let mut path = PathBuf::from(chroot.as_ref());

        path.push(crate::dirs::USERS.strip_prefix("/").unwrap());
        path.push(uid.to_string());

        Self { path }
    }

    pub fn user_dir(&self) -> &Path {
        &self.path
    }

    pub fn name(&self) -> std::io::Result<Option<String>> {
        let mut path = self.path.clone();
        path.push("name");
        match std::fs::read_link(path) {
            Ok(p) => Some(
                p.file_name()
                    .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "Invalid name stem"))
                    .and_then(|v| {
                        v.to_str()
                            .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "Non-UTF8"))
                    })
                    .map(<str>::to_string),
            )
            .transpose(),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_name<S: AsRef<OsStr>>(&self, st: S) -> std::io::Result<()> {
        if let Some(s) = self.name()? {
            let mut path = self.path.clone();
            path.push(s);
            let _ = std::fs::remove_file(path);
        }
        let mut path = self.path.clone();
        path.pop();
        path.push(st.as_ref());
        std::os::unix::fs::symlink(&self.path, &path)?;
        let mut path2 = self.path.clone();
        path2.push("name");
        std::os::unix::fs::symlink(path, path2)
    }

    pub fn shell(&self) -> std::io::Result<Option<PathBuf>> {
        let mut path = self.path.clone();
        path.push("shell");
        match std::fs::read_link(path) {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn home(&self) -> std::io::Result<Option<PathBuf>> {
        let mut path = self.path.clone();
        path.push("home");
        match std::fs::read_link(path) {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn root(&self) -> std::io::Result<Option<PathBuf>> {
        let mut path = self.path.clone();
        path.push("root");
        match std::fs::read_link(path) {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn set_home<P: AsRef<Path>>(&mut self, p: P) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("home");
        std::os::unix::fs::symlink(p, path)
    }

    pub fn set_shell<P: AsRef<Path>>(&mut self, p: P) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("shell");
        std::os::unix::fs::symlink(p, path)
    }

    pub fn set_root<P: AsRef<Path>>(&mut self, p: P) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("root");
        std::os::unix::fs::symlink(p, path)
    }

    pub fn has_password(&self) -> std::io::Result<bool> {
        let mut path = self.path.clone();
        path.push("password");
        match std::fs::metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn remove_password(&self) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("password");
        match std::fs::remove_file(path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn authenticate(&self, passwd: &str) -> std::io::Result<bool> {
        let mut path = self.path.clone();
        path.push("password");
        let mut file = std::fs::File::open(path)?;
        let mut header = PasswordHeader::default();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        if header.version == crate::password::INVALID_VERSION {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid Authentication File",
            ));
        }

        if header.algorithm == crate::password::algorithms::DISABLED
            || header.salt_and_repetition & crate::password::salting::MASK
                == crate::password::salting::DISABLED
        {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "Account has authentication disabled",
            ));
        }

        let mut salt = vec![0u8; header.salt_size as usize];
        file.read_exact(&mut salt)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let mut checked = Vec::new();
        crate::password::write_password(
            passwd,
            &salt,
            header.algorithm,
            header.salt_and_repetition,
            &mut checked,
        )?;
        if bytes.len() != checked.len() {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "Password is incorrect",
            ));
        }
        if openssl::memcmp::eq(&bytes, &checked) {
            Ok(header.expiry_seconds != 0
                && matches!(
                    (SystemTime::UNIX_EPOCH + Duration::from_secs(header.expiry_seconds)).elapsed(),
                    Ok(_)
                ))
        } else {
            Err(std::io::Error::new(
                ErrorKind::Other,
                "Password is incorrect",
            ))
        }
    }

    pub fn expire_password(&self, at: Option<SystemTime>) -> std::io::Result<()> {
        let at = at.unwrap_or_else(SystemTime::now);

        let mut path = self.path.clone();
        path.push("password-");
        let mut passwd_path = self.path.clone();
        passwd_path.push("password");
        let mut backup = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let defer = defer::defer(|| drop(std::fs::remove_file(&path)));
        let mut file = std::fs::File::open(&passwd_path)?;
        let mut header = PasswordHeader::default();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        if header.version == crate::password::INVALID_VERSION {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid Authentication File",
            ));
        }
        header.expiry_seconds = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?
            .as_secs();
        let mut salt = vec![0u8; header.salt_size as usize];
        file.read_exact(&mut salt)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        backup.write_all(bytemuck::bytes_of(&header))?;
        backup.write_all(&salt)?;
        backup.write_all(&bytes)?;
        std::fs::rename(&path, &passwd_path)?;
        forget(defer);
        Ok(())
    }

    pub fn unexpire_password(&self) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("password-");
        let mut passwd_path = self.path.clone();
        passwd_path.push("password");
        let mut backup = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let defer = defer::defer(|| drop(std::fs::remove_file(&path)));
        let mut file = std::fs::File::open(&passwd_path)?;
        let mut header = PasswordHeader::default();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        if header.version == crate::password::INVALID_VERSION {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid Authentication File",
            ));
        }
        header.expiry_seconds = 0;
        let mut salt = vec![0u8; header.salt_size as usize];
        file.read_exact(&mut salt)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        backup.write_all(bytemuck::bytes_of(&header))?;
        backup.write_all(&salt)?;
        backup.write_all(&bytes)?;
        std::fs::rename(&path, &passwd_path)?;
        forget(defer);
        Ok(())
    }

    pub fn disable_password(&self) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("password-");
        let mut passwd_path = self.path.clone();
        passwd_path.push("password");
        let mut backup = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let defer = defer::defer(|| drop(std::fs::remove_file(&path)));
        let mut file = std::fs::File::open(&passwd_path)?;
        let mut header = PasswordHeader::default();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        if header.version == crate::password::INVALID_VERSION {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid Authentication File",
            ));
        }
        if header.algorithm == crate::password::algorithms::DISABLED
            || header.salt_and_repetition & crate::password::salting::MASK
                == crate::password::salting::DISABLED
        {
            return Ok(()); // Already Disabled, no need to disable multiple times
        }

        let disabled_header = PasswordHeader {
            version: crate::password::CURRENT_VERSION,
            salt_size: 0,
            ..PasswordHeader::default()
        };
        let mut salt = vec![0u8; header.salt_size as usize];
        file.read_exact(&mut salt)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        backup.write_all(bytemuck::bytes_of(&disabled_header))?;
        backup.write_all(bytemuck::bytes_of(&header))?;
        backup.write_all(&salt)?;
        backup.write_all(&bytes)?;
        std::fs::rename(&path, &passwd_path)?;
        forget(defer);
        Ok(())
    }

    pub fn enable_password(&self) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("password-");
        let mut passwd_path = self.path.clone();
        passwd_path.push("password");
        let mut backup = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let defer = defer::defer(|| drop(std::fs::remove_file(&path)));
        let mut file = std::fs::File::open(&passwd_path)?;
        let mut header = PasswordHeader::default();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        if header.version == crate::password::INVALID_VERSION {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "Invalid Authentication File",
            ));
        }
        if header.algorithm != crate::password::algorithms::DISABLED
            && header.salt_and_repetition & crate::password::salting::MASK
                != crate::password::salting::DISABLED
        {
            return Ok(()); // Already Enabled
        }

        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;
        let mut salt = vec![0u8; header.salt_size as usize];
        file.read_exact(&mut salt)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;

        backup.write_all(bytemuck::bytes_of(&header))?;
        backup.write_all(&salt)?;
        backup.write_all(&bytes)?;
        std::fs::rename(&path, &passwd_path)?;
        forget(defer);
        Ok(())
    }

    pub fn set_password(&self, passwd: &str) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("password-"); // Use the password write file, so that authenticate never observes a broken write
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let defer = defer::defer(|| drop(std::fs::remove_file(&path)));
        let mut passwd_path = self.path.clone();
        passwd_path.push("password");
        let mut authtemplate = crate::dirs::INSTALL_DIRS.sysconfdir.clone();
        authtemplate.push("authtemplate");
        let mut header = PasswordHeader::default();
        match std::fs::File::open(authtemplate) {
            Ok(mut f) => f.read_exact(bytemuck::bytes_of_mut(&mut header))?,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                header = PasswordHeader {
                    version: crate::password::CURRENT_VERSION,
                    algorithm: crate::password::DEFAULT_ALGORITHM,
                    salt_and_repetition: crate::password::DEFAULT_SALT
                        | crate::password::DEFAULT_ROUNDS,
                    salt_size: 31,
                    expiry_seconds: 0,
                }
            }
            Err(e) => return Err(e),
        }
        file.write_all(bytemuck::bytes_of(&header))?;
        let mut salt = vec![0u8; header.salt_size as usize];
        openssl::rand::rand_bytes(&mut salt)
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e))?;
        file.write_all(&salt)?;
        crate::password::write_password(
            passwd,
            &salt,
            header.algorithm,
            header.salt_and_repetition,
            file,
        )?;
        std::fs::rename(&path, &passwd_path)?;
        forget(defer);
        Ok(())
    }

    pub fn uid(&self) -> std::io::Result<libc::uid_t> {
        let mut path = self.path.clone();
        path.push("uid");
        std::fs::read_link(path)
            .and_then(|e| {
                e.file_name()
                    .ok_or_else(|| {
                        std::io::Error::new(ErrorKind::InvalidData, "Invalid path in symlink")
                    })
                    .map(|s| s.to_owned())
            })
            .and_then(|s| {
                s.into_string().map_err(|_| {
                    std::io::Error::new(ErrorKind::InvalidData, "Non-UTF path in symlink")
                })
            })
            .and_then(|s| {
                s.parse()
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
            })
    }

    pub fn primary_group(&self) -> std::io::Result<libc::gid_t> {
        let mut path = self.path.clone();
        path.push("group");
        std::fs::read_link(path)
            .and_then(|e| {
                e.file_name()
                    .ok_or_else(|| {
                        std::io::Error::new(ErrorKind::InvalidData, "Invalid path in symlink")
                    })
                    .map(|s| s.to_owned())
            })
            .and_then(|s| {
                s.into_string().map_err(|_| {
                    std::io::Error::new(ErrorKind::InvalidData, "Non-UTF path in symlink")
                })
            })
            .and_then(|s| {
                s.parse()
                    .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
            })
    }

    pub fn secondary_groups(&self) -> std::io::Result<Vec<libc::gid_t>> {
        let mut path = self.path.clone();
        path.push("groups");
        let mut file = std::fs::File::open(path)?;
        let mut bytes = String::new();
        file.read_to_string(&mut bytes)?;
        bytes
            .split(',')
            .map(|v| v.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
    }

    pub fn set_primary_group(&self, group: u32) -> std::io::Result<()> {
        let mut path = self.path.clone();
        path.push("group");
        let mut group_path = PathBuf::from(&*crate::dirs::GROUPS);
        group_path.push(group.to_string());
        std::os::unix::fs::symlink(group_path, path)
    }

    pub fn add_secondary_group(&self, group: u32) -> std::io::Result<()> {
        let mut groups = self.secondary_groups()?;
        groups.push(group);
        groups.sort_unstable();
        let mut path = self.path.clone();
        path.push("groups");
        let mut file = std::fs::File::create(path)?;
        file.write_all(
            groups
                .iter()
                .dedup()
                .map(|i| i.to_string())
                .join(",")
                .as_bytes(),
        )
    }

    pub fn remove_secondary_group(&self, group: u32) -> std::io::Result<()> {
        let groups = self.secondary_groups()?;
        let mut path = self.path.clone();
        path.push("groups");
        let mut file = std::fs::File::create(path)?;
        file.write_all(
            groups
                .iter()
                .filter(|v| **v != group)
                .map(|i| i.to_string())
                .join(",")
                .as_bytes(),
        )
    }
}
