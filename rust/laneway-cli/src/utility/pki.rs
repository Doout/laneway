use std::{
    ffi::{OsStr, OsString},
    fs::{self, DirBuilder, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};

const DEFAULT_VALIDITY: Duration = Duration::days(10 * 365);

pub(super) fn init(args: &[OsString], mut output: impl Write) -> Result<()> {
    let mut directory = PathBuf::from(".");
    let mut name = String::from("Laneway Development CA");
    let mut validity = DEFAULT_VALIDITY;
    let mut args = args.iter();

    while let Some(arg) = args.next() {
        let flag = arg.to_str().context("invalid UTF-8 in pki init option")?;
        if flag == "-" || flag == "--" || !flag.starts_with('-') {
            break;
        }
        let flag = flag.strip_prefix("--").unwrap_or(&flag[1..]);
        let (flag, inline) = flag.split_once('=').map_or((flag, None), |(flag, value)| {
            (flag, Some(OsStr::new(value)))
        });
        if matches!(flag, "h" | "help") {
            writeln!(
                std::io::stderr().lock(),
                "Usage of pki init:\n  -name string\n    \tCA common name (default \"Laneway Development CA\")\n  -out-dir string\n    \toutput directory (default \".\")\n  -validity duration\n    \tCA validity (default 87600h0m0s)"
            )?;
            return Ok(());
        }
        ensure!(
            matches!(flag, "name" | "out-dir" | "validity"),
            "flag provided but not defined: -{flag}"
        );
        let value = inline
            .or_else(|| args.next().map(OsString::as_os_str))
            .with_context(|| format!("flag needs an argument: -{flag}"))?;
        match flag {
            "name" => {
                name = value
                    .to_str()
                    .context("invalid UTF-8 in CA common name")?
                    .into()
            }
            "out-dir" => directory = PathBuf::from(value),
            "validity" => {
                validity = parse_duration(value.to_str().context("invalid UTF-8 in CA validity")?)
                    .context("invalid -validity duration")?;
            }
            _ => unreachable!("pki init flag was validated"),
        }
    }

    ensure!(
        !name.is_empty() && validity.is_positive(),
        "CA common name and positive validity are required"
    );
    let now = OffsetDateTime::now_utc();
    let mut parameters = CertificateParams::default();
    parameters.distinguished_name.push(DnType::CommonName, name);
    parameters.not_before = now - Duration::minutes(1);
    parameters.not_after = now
        .checked_add(validity)
        .context("CA validity exceeds date range")?;
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generate CA private key")?;
    let certificate = parameters
        .self_signed(&key)
        .context("create CA certificate")?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        &directory
    };
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    builder
        .create(directory)
        .context("create CA output directory")?;
    let cert_path = directory.join("ca.crt");
    let key_path = directory.join("ca.key");
    write_exclusive(&key_path, key.serialize_pem().as_bytes(), 0o600)
        .context("write private key")?;
    if let Err(error) = write_exclusive(&cert_path, certificate.pem().as_bytes(), 0o644) {
        let _ = fs::remove_file(&key_path);
        return Err(error).context("write certificate");
    }
    let display = |path: &Path| path.strip_prefix(".").unwrap_or(path).display().to_string();
    writeln!(
        output,
        "created CA certificate {} and private key {}",
        display(&cert_path),
        display(&key_path)
    )?;
    Ok(())
}

pub(super) fn write_exclusive(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let directory = path.parent().context("missing CA output directory")?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    set_mode(file.as_file(), mode)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(file: &File, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    Ok(file.set_permissions(fs::Permissions::from_mode(mode))?)
}

#[cfg(not(unix))]
fn set_mode(_file: &File, _mode: u32) -> Result<()> {
    Ok(())
}

// Go's duration flags use decimal fractions and permit concatenated units such
// as 1h30m. Work in integer nanoseconds so any sub-nanosecond part truncates.
pub(crate) fn parse_duration(input: &str) -> Result<Duration> {
    let negative = input.starts_with('-');
    let mut text = input.strip_prefix(['+', '-']).unwrap_or(input);
    if text == "0" {
        return Ok(Duration::ZERO);
    }
    ensure!(!text.is_empty(), "empty duration");
    let mut nanos = 0_i128;
    while !text.is_empty() {
        let number_end = text
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len());
        let (number, rest) = text.split_at(number_end);
        let unit_end = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let (unit, remaining) = rest.split_at(unit_end);
        text = remaining;
        let unit_nanos = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => bail!("unknown duration unit {unit:?}"),
        };
        let (whole, fractional) = number.split_once('.').unwrap_or((number, ""));
        ensure!(
            !(whole.is_empty() && fractional.is_empty())
                && fractional.bytes().all(|digit| digit.is_ascii_digit()),
            "invalid duration number {number:?}"
        );
        let whole = if whole.is_empty() {
            0
        } else {
            i128::from(whole.parse::<u64>()?)
        };
        let fractional_nanos = fractional.bytes().rev().fold(0, |scaled, digit| {
            (i128::from(digit - b'0') * unit_nanos + scaled) / 10
        });
        nanos += whole * unit_nanos + fractional_nanos;
        ensure!(
            nanos <= i128::from(i64::MAX) + i128::from(negative),
            "duration overflow"
        );
    }
    let value = if negative { -nanos } else { nanos };
    Ok(Duration::nanoseconds(i64::try_from(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn duration_matches_go_units_and_bounds() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::minutes(90));
        assert_eq!(
            parse_duration("+.25s1.5µs").unwrap(),
            Duration::nanoseconds(250_001_500)
        );
        assert_eq!(
            parse_duration("-9223372036854775808ns").unwrap(),
            Duration::nanoseconds(i64::MIN)
        );
        for invalid in ["1", "3d", "1..0s", "9223372036854775808ns"] {
            assert!(parse_duration(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn init_is_exclusive_and_keeps_private_key_mode() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ca");
        let args = [
            OsString::from("--out-dir"),
            directory.clone().into_os_string(),
            OsString::from("-name=Utility test root"),
            OsString::from("--validity"),
            OsString::from("1h30m"),
        ];
        let mut output = Vec::new();
        init(&args, &mut output).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .starts_with("created CA certificate ")
        );
        let cert = directory.join("ca.crt");
        let key = directory.join("ca.key");
        let cert_bytes = fs::read(&cert).unwrap();
        let key_bytes = fs::read(&key).unwrap();
        assert!(cert_bytes.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_bytes.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(key.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(cert.metadata().unwrap().permissions().mode() & 0o777, 0o644);
        }
        assert!(init(&args, Vec::new()).is_err());
        assert_eq!(fs::read(&cert).unwrap(), cert_bytes);
        assert_eq!(fs::read(&key).unwrap(), key_bytes);
        fs::remove_file(&key).unwrap();
        assert!(init(&args, Vec::new()).is_err());
        assert!(!key.exists());
        assert_eq!(fs::read(cert).unwrap(), cert_bytes);
    }

    #[test]
    fn init_rejects_invalid_validity_before_writing_files() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("ca");
        let args = ["--out-dir", directory.to_str().unwrap(), "-validity=-1s"]
            .map(OsStr::new)
            .map(OsStr::to_os_string);
        assert!(init(&args, Vec::new()).is_err());
        assert!(!directory.exists());
    }
}
