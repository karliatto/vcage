//! Detecting a connected Trezor over USB (via sysfs, no extra tools needed).

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbTrezor {
    pub vendor: u16,
    pub product: u16,
    pub bootloader: bool,
}

/// (vendor, product, is_bootloader) of Trezor devices.
const IDS: &[(u16, u16, bool)] = &[
    (0x534c, 0x0001, false), // Trezor One
    (0x1209, 0x53c1, false), // Trezor Model T / Safe 3 / Safe 5
    (0x1209, 0x53c0, true),  // Trezor bootloader
];

pub fn detect_usb() -> Vec<UsbTrezor> {
    detect_in(Path::new("/sys/bus/usb/devices"))
}

fn detect_in(sysfs: &Path) -> Vec<UsbTrezor> {
    let read_hex = |p: &Path| {
        fs::read_to_string(p)
            .ok()
            .and_then(|s| u16::from_str_radix(s.trim(), 16).ok())
    };
    let Ok(entries) = fs::read_dir(sysfs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        let (Some(v), Some(pr)) = (
            read_hex(&p.join("idVendor")),
            read_hex(&p.join("idProduct")),
        ) else {
            continue;
        };
        if let Some(&(_, _, bootloader)) = IDS.iter().find(|(iv, ip, _)| *iv == v && *ip == pr) {
            out.push(UsbTrezor {
                vendor: v,
                product: pr,
                bootloader,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_from_fake_sysfs() {
        let t = tempfile::tempdir().unwrap();
        let mk = |name: &str, v: &str, p: &str| {
            let d = t.path().join(name);
            fs::create_dir(&d).unwrap();
            fs::write(d.join("idVendor"), format!("{v}\n")).unwrap();
            fs::write(d.join("idProduct"), format!("{p}\n")).unwrap();
        };
        mk("1-1", "1d6b", "0002"); // a hub
        mk("1-2", "1209", "53c1");
        fs::create_dir(t.path().join("1-0:1.0")).unwrap(); // interface, no ids
        let found = detect_in(t.path());
        assert_eq!(
            found,
            vec![UsbTrezor {
                vendor: 0x1209,
                product: 0x53c1,
                bootloader: false
            }]
        );
        assert!(detect_in(&t.path().join("missing")).is_empty());
    }
}
