use std::{
    ffi::OsStr,
    io::ErrorKind,
    path::{Path, PathBuf},
};

pub struct GroupHandle {
    path: PathBuf,
}

impl GroupHandle {
    pub fn from_name<S: AsRef<OsStr>>(name: S) -> std::io::Result<Self> {
        let mut path = PathBuf::from(*crate::dirs::GROUPS);
        path.push(name.as_ref());
        path = std::fs::read_link(path)?;
        Ok(Self { path })
    }

    pub fn from_uid(uid: u32) -> Self {
        let mut path = PathBuf::from(*crate::dirs::GROUPS);
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

    pub fn set_name<S: AsRef<OsStr>>(&mut self, st: S) -> std::io::Result<()> {
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

    pub fn gid(&self) -> std::io::Result<u32> {
        let mut path = self.path.clone();
        path.push("gid");
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
}
