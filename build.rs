use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use install_dirs::dirs::{CanonicalizationError, InstallDirs};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    pub dirs: Paths,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct Paths {
    #[serde(flatten)]
    pub dirs: InstallDirs,
    pub users: PathBuf,
    pub groups: PathBuf,
    pub passwd: PathBuf,
    pub shadow: PathBuf,
    pub group: PathBuf,
    pub gshadow: PathBuf,
    pub sudoers: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            dirs: InstallDirs::with_project_name("lc-login"),
            users: PathBuf::from("users"),
            groups: PathBuf::from("groups"),
            passwd: PathBuf::from("passwd"),
            shadow: PathBuf::from("shadow"),
            group: PathBuf::from("group"),
            gshadow: PathBuf::from("gshadow"),
            sudoers: PathBuf::from("sudoers"),
        }
    }
}

impl Paths {
    pub fn read_env(&mut self) {
        self.dirs.read_env();
        if let Ok(v) = std::env::var("users") {
            self.users = v.into();
        }
        if let Ok(v) = std::env::var("groups") {
            self.groups = v.into();
        }
        if let Ok(v) = std::env::var("passwd") {
            self.passwd = v.into();
        }
        if let Ok(v) = std::env::var("shadow") {
            self.shadow = v.into();
        }
        if let Ok(v) = std::env::var("group") {
            self.group = v.into();
        }
        if let Ok(v) = std::env::var("gshadow") {
            self.gshadow = v.into();
        }
        if let Ok(v) = std::env::var("sudoers") {
            self.sudoers = v.into();
        }
    }

    pub fn canonicalize(mut self) -> Result<Self, CanonicalizationError> {
        self.dirs = self.dirs.canonicalize()?;
        self.groups = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.groups);
        self.users = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.users);
        self.passwd = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.passwd);
        self.shadow = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.shadow);
        self.group = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.group);
        self.gshadow = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.gshadow);
        self.sudoers = InstallDirs::canonicalize_dir(&self.dirs.sysconfdir, self.sudoers);
        Ok(self)
    }

    pub fn as_env(&self) -> impl IntoIterator<Item = (&str, &Path)> {
        let mut map = HashMap::new();
        map.insert("users", &*self.users);
        map.insert("groups", &self.groups);
        map.insert("passwd", &self.passwd);
        map.insert("shadow", &self.shadow);
        map.insert("group", &self.group);
        map.insert("gshadow", &self.gshadow);
        map.insert("sudoers", &self.sudoers);

        self.dirs.as_env().into_iter().chain(map)
    }
}

pub fn main() {
    println!("cargo:rerun-if-change=config.toml");
    let mut config_path = File::open("config.toml").unwrap();
    let mut st = String::new();
    config_path.read_to_string(&mut st).unwrap();
    let Config { mut dirs } = toml::from_str(&st).unwrap();
    dirs.read_env();
    dirs = dirs.canonicalize().unwrap();
    for (k, v) in dirs.as_env() {
        println!("cargo:rustc-env={}={}", k, v.to_str().unwrap());
    }
}
