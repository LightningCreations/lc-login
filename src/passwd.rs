use std::{
    io::ErrorKind,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use lc_login::users::UserHandle;
use zeroize::Zeroizing;

pub fn main() {
    let mut login_name = None;
    let mut args = std::env::args();
    let prg_name = args.next().unwrap();
    let mut delete = false;
    let mut expire = false;
    let mut lock = false;
    let mut unlock = false;
    let mut expire_days = None;
    let mut chroot = None;

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{}: Cannot possibly work without effective root", prg_name);
    }

    while let Some(s) = args.next() {
        match &*s {
            "--help" => {
                println!("Usage: {} [options] [LOGIN]", prg_name);
                println!("Changes the password of the current user account. The superuser can change the password of any account");
                println!("Options:");
                println!("\t-d, --delete: Removes the user password");
                println!("\t-e, --expire: Expire the user's password immediately. During the next login, the user will be required to enter a new password");
                println!("\t-h, --help: Print this message and exit");
                println!("\t-l, --lock: Lock the password.");
                println!("\t-q, --quiet: Accepted for compatibility. Currently has no effect");
                println!("\t-R, --root: Make changes within the given sysroot");
                println!(
                    "\t-u, --unlock: Unlock the password and restore it to the previous value"
                );
                println!("\t-x, --maxdays <days>: Expire the password in <days> days, or -1 to remove the expiry");

                std::process::exit(0);
            }
            "--delete" => delete = true,
            "--expire" => expire = true,
            "--lock" => lock = true,
            "--quiet" => {}
            "--root" => chroot = args.next(),
            "--unlock" => unlock = true,
            "--maxdays" => {
                expire_days = match args.next().map(|s| s.parse::<i32>()).transpose() {
                    Ok(Some(s)) => Some(s),
                    Ok(None) => {
                        eprintln!("{}: Missing operand for --maxdays", prg_name);
                        std::process::exit(6)
                    }
                    Err(e) => {
                        eprintln!("{}: {}", prg_name, e);
                        std::process::exit(6)
                    }
                }
            }
            "--" => {
                login_name = args.next();
                break;
            }
            x if x.starts_with("--") => {
                eprintln!("{}: Unrecognized Option {}", prg_name, x)
            }
            x if x.starts_with("-") => {
                let mut chars = x.chars();
                while let Some(c) = chars.next() {
                    match c {
                        'd' => delete = true,
                        'e' => expire = true,
                        'h' => {
                            println!("Usage: {} [options] [LOGIN]", prg_name);
                            println!("Changes the password of the current user account. The superuser can change the password of any account");
                            println!("Options:");
                            println!("\t-d, --delete: Removes the user password");
                            println!("\t-e, --expire: Expire the user's password immediately. During the next login, the user will be required to enter a new password");
                            println!("\t-h, --help: Print this message and exit");
                            println!("\t-l, --lock: Lock the password.");
                            println!("\t-q, --quiet: Accepted for compatibility. Currently has no effect");
                            println!("\t-R, --root: Make changes within the given sysroot");
                            println!("\t-u, --unlock: Unlock the password and restore it to the previous value");
                            println!("\t-x, --maxdays <days>: Expire the password in <days> days, or -1 to remove the expiry");

                            std::process::exit(0);
                        }
                        'l' => lock = true,
                        'q' => {}
                        'R' => {
                            let str = chars.collect::<String>();
                            if str.is_empty() {
                                chroot = args.next();
                            } else {
                                chroot = Some(str);
                            }
                            break;
                        }
                        'u' => unlock = true,
                        'x' => {
                            let mut str = chars.collect::<String>();
                            if str.is_empty() {
                                str = match args.next() {
                                    Some(s) => s,
                                    None => {
                                        eprintln!("{}: Missing operand for -x ", prg_name);
                                        std::process::exit(6)
                                    }
                                }
                            }
                            expire_days = match str.parse() {
                                Ok(v) => Some(v),
                                Err(e) => {
                                    eprintln!("{}: {}", prg_name, e);
                                    std::process::exit(6)
                                }
                            };
                            break;
                        }
                        v => {
                            eprintln!("{}: Unrecognized option {}", prg_name, v);
                            std::process::exit(2)
                        }
                    }
                }
            }
            x => login_name = Some(x.to_string()),
        }
    }

    if matches!(login_name, Some(_))
        || expire
        || lock
        || unlock
        || matches!(expire_days, Some(_))
        || matches!(chroot, Some(_))
    {
        if unsafe { libc::getuid() } != 0 {
            eprintln!("{}: Permission Denied", prg_name);
            std::process::exit(1)
        }
    }

    if lock && (unlock || delete) {
        eprintln!(
            "{}: Cannot both lock and unlock an account simultaneously",
            prg_name
        );
        std::process::exit(2)
    }

    if expire && matches!(expire_days, Some(_)) {
        eprintln!(
            "{}: Cannot expire an account immediately and set the expiry time simultaneously",
            prg_name
        );
        std::process::exit(2)
    }
    let handle;
    if let Some(n) = login_name {
        if let Some(chroot) = chroot {
            match UserHandle::from_name_in(&*n, PathBuf::from(chroot)) {
                Ok(hdl) => handle = hdl,
                Err(_) => {
                    eprintln!("{}: No such user {}", prg_name, n);
                    std::process::exit(4);
                }
            }
        } else {
            match UserHandle::from_name(&*n) {
                Ok(hdl) => handle = hdl,
                Err(e) => {
                    eprintln!("{}: {}", prg_name, e);
                    std::process::exit(3);
                }
            }
        }
    } else {
        let uid = unsafe { libc::getuid() };
        if let Some(chroot) = chroot {
            handle = UserHandle::from_uid_in(uid, PathBuf::from(chroot));
        } else {
            handle = UserHandle::from_uid(uid);
        }
    }

    if unsafe { libc::getuid() } != 0 {
        let passwd = match rpassword::read_password_from_tty(Some("Current Password:")) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => {
                eprintln!("{}: Could not read password", prg_name);
                std::process::exit(1)
            }
        };

        match handle.authenticate(&passwd) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("{}: Incorrect password", prg_name);
                std::process::exit(1)
            }
        }
    }

    if expire {
        match handle.expire_password(None) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                eprintln!("{}: Password File busy, please retry", prg_name);
                std::process::exit(5)
            }
            Err(_) => {
                eprintln!("{}: Failed to expire password", prg_name);
                std::process::exit(3)
            }
        }
    } else if let Some(days) = expire_days {
        if days < 0 {
            match handle.expire_password(Some(SystemTime::UNIX_EPOCH)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    eprintln!("{}: Password File busy, please retry", prg_name);
                    std::process::exit(5)
                }
                Err(_) => {
                    eprintln!("{}: Failed to unexpire password", prg_name);
                    std::process::exit(3)
                }
            }
        } else {
            let mut time = SystemTime::now();
            time += Duration::from_secs((days as u64) * 60 * 60 * 24);
            match handle.expire_password(Some(time)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    eprintln!("{}: Password File busy, please retry", prg_name);
                    std::process::exit(5)
                }
                Err(_) => {
                    eprintln!("{}: Failed to unexpire password", prg_name);
                    std::process::exit(3)
                }
            }
        }
    }

    if delete {
        if let Err(_) = handle.remove_password() {
            eprintln!("{}: Failed to remove password", prg_name);
            std::process::exit(3)
        }
    } else if lock {
        match handle.disable_password() {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                eprintln!("{}: Password File busy, please retry", prg_name);
                std::process::exit(5)
            }
            Err(_) => {
                eprintln!("{}: Failed to lock password", prg_name);
                std::process::exit(3)
            }
        }
    } else if unlock {
        match handle.enable_password() {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                eprintln!("{}: Password File busy, please retry", prg_name);
                std::process::exit(5)
            }
            Err(_) => {
                eprintln!("{}: Failed to unlock password", prg_name);
                std::process::exit(3)
            }
        }
    } else {
        let passwd = match rpassword::read_password_from_tty(Some("New Password: ")) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => {
                eprintln!("{}: Failed to read password, {}", prg_name, e);
                std::process::exit(3)
            }
        };
        let passwd_confirm = match rpassword::read_password_from_tty(Some("Confirm Password: ")) {
            Ok(s) => Zeroizing::new(s),
            Err(e) => {
                eprintln!("{}: Failed to read password, {}", prg_name, e);
                std::process::exit(3)
            }
        };
        if passwd.len() == passwd_confirm.len()
            && openssl::memcmp::eq(passwd.as_bytes(), passwd_confirm.as_bytes())
        {
            match handle.set_password(&passwd) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    eprintln!("{}: Password File busy, please retry", prg_name);
                    std::process::exit(5)
                }
                Err(e) => {
                    eprintln!("{}: Failed to set password, {}", prg_name, e);
                    std::process::exit(3)
                }
            }
        } else {
            eprintln!("{}: Password Mismatch", prg_name);
            std::process::exit(1)
        }
    }
}
