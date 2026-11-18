use super::{Asset, Console};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use rustix::{
    fd::AsFd,
    fs::{Dir, Mode, OFlags, open, openat},
    io::Errno,
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, io::Read, path::Path};

// Match the Rust relay's per-response boundary; cap the entire snapshot too.
const MAX_FILE: usize = 8 * 1024 * 1024;
const MAX_TOTAL: usize = 48 * 1024 * 1024;
const MAX_ASSETS: usize = 512;
const PUBLIC: &[&str] = &[
    "apple-touch-icon.png",
    "favicon.ico",
    "laneway-icon-192.png",
    "laneway-icon-512.png",
    "laneway-mark.svg",
    "site.webmanifest",
];

pub(super) fn load(path: &Path) -> Result<Console> {
    ensure!(path.is_absolute(), "console directory must be absolute");
    let dir_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root =
        open(path, dir_flags, Mode::empty()).context("open console distribution directory")?;
    let mut total = 0;
    let shell = Asset {
        body: read(
            open_file(&root, "index.html").context("open console index")?,
            &mut total,
        )?,
        content_type: "text/html; charset=utf-8",
        cache: "no-store",
        etag: None,
    };
    ensure!(!shell.body.is_empty(), "console index is empty");
    let mut assets = HashMap::new();
    for name in PUBLIC {
        let file = match open_file(&root, name) {
            Ok(file) => file,
            Err(Errno::NOENT) => continue,
            Err(err) => return Err(err).context("open public console asset"),
        };
        let content_type = media(name).expect("known public asset type");
        assets.insert(
            format!("/{name}"),
            static_asset(file, &mut total, content_type, "no-cache")?,
        );
    }
    let asset_dir = openat(&root, "assets", dir_flags, Mode::empty())
        .context("open console assets directory")?;
    for (index, entry) in Dir::read_from(&asset_dir)?.enumerate() {
        ensure!(
            index < MAX_ASSETS + 2,
            "too many entries in the console assets directory"
        );
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if !safe_name(name) {
            continue;
        }
        let Some(content_type) = media(name) else {
            continue;
        };
        ensure!(assets.len() < MAX_ASSETS, "too many console assets");
        let file = open_file(&asset_dir, name).context("open bundled console asset")?;
        assets.insert(
            format!("/assets/{name}"),
            static_asset(
                file,
                &mut total,
                content_type,
                "public, max-age=31536000, immutable",
            )?,
        );
    }
    ensure!(
        assets.keys().any(|path| path.starts_with("/assets/")),
        "console build has no bundled assets"
    );
    Ok(Console { shell, assets })
}

fn open_file(dir: impl AsFd, name: &str) -> rustix::io::Result<File> {
    // Do not follow links or block on a FIFO masquerading as a static file.
    openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map(File::from)
}

fn read(file: File, total: &mut usize) -> Result<Bytes> {
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "console asset must be a regular file");
    let limit = MAX_FILE.min(MAX_TOTAL - *total);
    ensure!(
        meta.len() <= limit as u64,
        "console build exceeds its size bound"
    );
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take((limit + 1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= limit, "console build exceeds its size bound");
    *total += data.len();
    Ok(Bytes::from(data))
}

fn static_asset(
    file: File,
    total: &mut usize,
    content_type: &'static str,
    cache: &'static str,
) -> Result<Asset> {
    let body = read(file, total)?;
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body))).parse()?;
    Ok(Asset {
        body,
        content_type,
        cache,
        etag: Some(etag),
    })
}

fn safe_name(name: &str) -> bool {
    !name.starts_with('.')
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn media(name: &str) -> Option<&'static str> {
    Some(match name.rsplit_once('.')?.1 {
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpeg" | "jpg" => "image/jpeg",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "webmanifest" => "application/manifest+json",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn startup_refuses_symlinked_and_oversized_assets() -> Result<()> {
        let root = tempfile::tempdir()?;
        let dist = root.path().join("dist");
        let assets = dist.join("assets");
        fs::create_dir_all(&assets)?;
        fs::write(dist.join("index.html"), b"<title>Laneway</title>")?;
        let private = root.path().join("private");
        fs::write(&private, b"local-only")?;
        let app = assets.join("app.js");
        symlink(&private, &app)?;
        assert!(load(&dist).is_err());
        fs::remove_file(&app)?;
        File::create(&app)?.set_len((MAX_FILE + 1) as u64)?;
        assert!(load(&dist).is_err());
        fs::write(&app, b"console.log('ready')")?;
        fs::write(assets.join("app.js.map"), b"hidden source map")?;
        let console = load(&dist)?;
        assert_eq!(console.assets.len(), 1);
        assert_eq!(
            console.assets["/assets/app.js"].body,
            "console.log('ready')"
        );
        fs::write(&app, b"new build on disk")?;
        assert_eq!(
            console.assets["/assets/app.js"].body,
            "console.log('ready')"
        );
        Ok(())
    }
}
