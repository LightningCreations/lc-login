use std::{collections::HashMap, ffi::CString, io::ErrorKind, path::Path, process::Command};

use lc_login::users::UserHandle;
use libc::getuid;

use std::os::unix::prelude::*;

pub enum Void {}

pub fn execute_login(
    handle: &UserHandle,
    env: HashMap<String, String>,
    preserve_env: bool,
) -> std::io::Result<Void> {
    let uid = handle.uid()?;
    let home = handle.home()?;
    let shell = handle.shell()?;
    let root = handle.root()?;
    let group = handle.primary_group()?;
    let groups = handle.secondary_groups()?;
    if let Some(root) = root {
        let rdir = CString::new(root.into_os_string().into_vec())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        //
        // SAFETY:
        // rdir.as_ptr() is from rdir, so it is valid
        // rdir is a CString, so it has a NUL terminator.
        if unsafe { libc::chroot(rdir.as_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    //
    // SAFETY:
    // groups.as_ptr() is from groups, so it is valid
    // groups.as_ptr() is valid for the length of the vector
    if unsafe { libc::setgroups(groups.len(), groups.as_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut cmd = Command::new(shell.as_deref().unwrap_or(Path::new("/bin/sh")));
    if !preserve_env {
        cmd.env_clear();
    } else {
        if let Some(dir) = &home {
            cmd.env("HOME", dir);
        }
        cmd.env("SHELL", shell.as_deref().unwrap_or(Path::new("/bin/sh")));
        cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    }
    cmd.envs(env);

    cmd.uid(uid);
    cmd.gid(group);
    cmd.current_dir(home.as_deref().unwrap_or(Path::new("/")));
    Err(cmd.exec())
}

pub fn main() {
    let mut args = std::env::args();
    let prg_name = args.next().unwrap(); // Yoink the program name.

    //
    // SAFETY:
    // geteuid does not prescribe undefined behaviour
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{}: Cannot possibly work without effective root", prg_name);
        std::process::exit(1);
    }

    let mut preserve = false;
    let mut no_auth = false;
    let mut uname = None;
    let mut env = HashMap::new();
    while let Some(v) = args.next() {
        match &*v {
            "-p" => preserve = true,
            "-r" | "-h" => {
                eprintln!("rlogin is not implemented by lc-login");
                std::process::exit(1);
            }
            "-f" => no_auth = true,
            x if x.find("=").is_some() => {
                let mut k = x.split("=");
                env.insert(k.next().unwrap().to_string(), k.next().unwrap().to_string());
            }
            x => uname = Some(x.to_string()),
        }
    }

    if no_auth {
        if unsafe { getuid() } != 0 {
            eprintln!("{}: Permission Denied", prg_name);
            std::process::exit(0)
        }
        if let Some(uname) = &uname {
            let handle = match lc_login::users::UserHandle::from_name(uname) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("{}: {}", prg_name, e);
                    std::process::exit(1)
                }
            };

            match execute_login(&handle, env, preserve) {
                Ok(v) => match v {},
                Err(e) => {
                    eprintln!("{}: {}", prg_name, e);
                    std::process::exit(1)
                }
            }
        }
    }
}