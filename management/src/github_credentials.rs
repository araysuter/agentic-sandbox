//! Protected host-only GitHub MCP credentials. Never serialized into VM metadata.
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

pub struct Secret(String);
impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl Clone for Secret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        // Keep the owned allocation valid UTF-8 while erasing it.
        unsafe {
            self.0.as_mut_vec().fill(0);
        }
    }
}
struct Credential {
    secret: Secret,
    path: PathBuf,
}
#[derive(Default)]
pub struct GithubCredentials(Mutex<BTreeMap<String, Credential>>);
impl GithubCredentials {
    pub fn set(&self, id: &str, token: &str, path: &Path) -> Result<(), String> {
        validate(token)?;
        if !path.is_absolute() {
            return Err("credential path must be absolute".into());
        }
        write_private(path, token.as_bytes())
            .map_err(|_| "could not save host GitHub credential")?;
        match fs::remove_file(path.with_extension("revoked")) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("could not clear host GitHub revocation".into()),
        }
        fs::File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|_| "could not durably authorize host GitHub credential")?;
        self.0.lock().unwrap().insert(
            id.into(),
            Credential {
                secret: Secret(token.into()),
                path: path.into(),
            },
        );
        Ok(())
    }
    pub fn restore(&self, id: &str, path: &Path) -> Result<bool, String> {
        let marker = path.with_extension("revoked");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err("invalid host GitHub revocation marker".into());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.nlink() != 1
                        || metadata.mode() & 0o777 != 0o600
                        || metadata.uid() != unsafe { libc::geteuid() }
                    {
                        return Err("host GitHub revocation marker is not private".into());
                    }
                }
                self.0.lock().unwrap().remove(id);
                return Ok(false);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("could not inspect host GitHub revocation".into()),
        }
        let Some(secret) = read_private(path)? else {
            return Ok(false);
        };
        self.0.lock().unwrap().insert(
            id.into(),
            Credential {
                secret,
                path: path.into(),
            },
        );
        Ok(true)
    }
    pub fn configured(&self, id: &str) -> bool {
        self.0.lock().unwrap().contains_key(id)
    }
    pub fn get(&self, id: &str) -> Option<Secret> {
        self.0.lock().unwrap().get(id).map(|c| c.secret.clone())
    }
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let credential = self.0.lock().unwrap().remove(id);
        if let Some(credential) = credential {
            // The marker survives a failed unlink and prevents restoring an old
            // credential after restart. A new explicit key clears it on set().
            let marker_result =
                write_private(&credential.path.with_extension("revoked"), b"revoked");
            match fs::remove_file(&credential.path) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(_) => return Err("could not delete protected GitHub credential".into()),
            }
            if let Some(parent) = credential.path.parent() {
                fs::File::open(parent)
                    .and_then(|d| d.sync_all())
                    .map_err(|_| "could not durably delete protected GitHub credential")?;
            }
            marker_result.map_err(|_| "could not durably record GitHub revocation")?;
        }
        Ok(())
    }
}
pub fn validate(token: &str) -> Result<(), String> {
    if !(16..=4096).contains(&token.len()) || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("GitHub token must be 16..4096 visible ASCII characters".into());
    }
    Ok(())
}
fn read_private(path: &Path) -> Result<Option<Secret>, String> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("could not read protected GitHub credential".into()),
    };
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect protected GitHub credential")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("GitHub credential file exceeds host protection policy".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("GitHub credential file is not private to the management account".into());
        }
    }
    let mut token = String::new();
    file.take(4097)
        .read_to_string(&mut token)
        .map_err(|_| "GitHub credential is not valid text")?;
    validate(&token)?;
    Ok(Some(Secret(token)))
}
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("credential path has no parent"))?;
    let directory = fs::symlink_metadata(parent)?;
    if !directory.file_type().is_dir() {
        return Err(std::io::Error::other(
            "credential parent must be a real directory",
        ));
    }
    let temporary = parent.join(format!(".github-token-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_roundtrip_restore_delete_and_no_serialization() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("github-token.key");
        let token = "ghp_fixture_only_never_real";
        let store = GithubCredentials::default();
        store.set("session", token, &path).unwrap();
        assert_eq!(store.get("session").unwrap().expose(), token);
        let recovered = GithubCredentials::default();
        assert!(recovered.restore("session", &path).unwrap());
        assert!(recovered.configured("session"));
        recovered.remove("session").unwrap();
        assert!(!path.exists());
        assert!(!recovered.configured("session"));
    }
    #[test]
    fn rejects_unsafe_credentials_and_symlink_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("github-token.key");
        let store = GithubCredentials::default();
        for token in ["short", "token-with-newline\n", "token with spaces fixture"] {
            assert!(store.set("session", token, &path).is_err());
        }
        assert!(!path.exists());
        store
            .set("session", "github_pat_fixture_token", &path)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let link = tmp.path().join("link");
            symlink(&path, &link).unwrap();
            assert!(store.restore("other", &link).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(store.restore("other", &path).is_err());
        }
    }
    #[test]
    fn revocation_marker_prevents_restoring_reappeared_old_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("github-token.key");
        let store = GithubCredentials::default();
        store
            .set("session", "ghp_fixture_only_never_real", &path)
            .unwrap();
        store.remove("session").unwrap();
        assert!(path.with_extension("revoked").exists());
        write_private(&path, b"ghp_old_file_reappeared_fixture").unwrap();
        assert!(!store.restore("session", &path).unwrap());
        assert!(!store.configured("session"));
        store
            .set("session", "ghp_explicit_replacement_fixture", &path)
            .unwrap();
        assert!(!path.with_extension("revoked").exists());
        assert_eq!(
            store.get("session").unwrap().expose(),
            "ghp_explicit_replacement_fixture"
        );
    }
}
