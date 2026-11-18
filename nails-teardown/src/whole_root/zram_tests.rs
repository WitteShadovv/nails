// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use std::fs;

/// The page size of the fake devices.
const PAGE: usize = 4096;

/// A fake `/sys/block`, `/dev` and `/proc/swaps` below a temporary root.
struct Fake {
    root: tempfile::TempDir,
}

impl Fake {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["sys/block", "dev", "proc"] {
            fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        fs::write(
            root.path().join("proc/swaps"),
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n",
        )
        .unwrap();
        Self { root }
    }

    fn places(&self) -> Places {
        Places {
            page_size: PAGE,
            ..Places::under(self.root.path())
        }
    }

    /// A block device `name`, set up when `initstate` says so, whose node
    /// holds `first` at its start (none when `None`).
    fn device(&self, name: &str, initstate: &str, first: Option<&[u8]>) {
        let sys = self.root.path().join("sys/block").join(name);
        fs::create_dir_all(&sys).unwrap();
        fs::write(sys.join("initstate"), initstate).unwrap();
        if let Some(first) = first {
            fs::write(self.root.path().join("dev").join(name), first).unwrap();
        }
    }

    /// The node of a swap area of `pages` pages.
    fn swap_area(pages: usize) -> Vec<u8> {
        let mut area = vec![0u8; PAGE * pages];
        area[PAGE - SWAP_SIGNATURE.len()..PAGE].copy_from_slice(SWAP_SIGNATURE);
        area
    }

    fn in_use(&self, line: &str) {
        let swaps = self.root.path().join("proc/swaps");
        let mut text = fs::read_to_string(&swaps).unwrap();
        text.push_str(line);
        text.push('\n');
        fs::write(swaps, text).unwrap();
    }

    fn was_reset(&self, name: &str) -> bool {
        fs::read_to_string(self.root.path().join("sys/block").join(name).join("reset"))
            .is_ok_and(|text| text == "1")
    }
}

#[test]
fn an_idle_swap_area_on_zram_is_reset() {
    // The decoy's stop left zram0 set up with its swap area, out of use.
    let fake = Fake::new();
    fake.device("zram0", "1\n", Some(&Fake::swap_area(2)));
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [("zram0".to_string(), Reset::Done)]
    );
    assert!(fake.was_reset("zram0"));
}

#[test]
fn a_zram_swap_in_use_is_left_alone() {
    let fake = Fake::new();
    fake.device("zram0", "1\n", Some(&Fake::swap_area(2)));
    fake.in_use("/dev/zram0                              partition\t3031036\t\t0\t\t100");
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [("zram0".to_string(), Reset::InUse)]
    );
    assert!(!fake.was_reset("zram0"));
}

#[test]
fn a_zram_device_without_a_swap_area_is_left_alone() {
    // One never set up, one that holds a filesystem's first page, one whose
    // first page is cut short and one whose node is not there: none is reset.
    let fake = Fake::new();
    fake.device("zram0", "0\n", Some(&Fake::swap_area(2)));
    let mut other = vec![0u8; PAGE * 2];
    other[1080..1082].copy_from_slice(&[0x53, 0xef]);
    fake.device("zram1", "1\n", Some(&other));
    fake.device("zram2", "1\n", Some(&Fake::swap_area(1)[..PAGE - 1]));
    fake.device("zram3", "1\n", None);
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [
            ("zram0".to_string(), Reset::NotSetUp),
            ("zram1".to_string(), Reset::NoSwapArea),
            ("zram2".to_string(), Reset::NoSwapArea),
            ("zram3".to_string(), Reset::NoSwapArea),
        ]
    );
    for name in ["zram0", "zram1", "zram2", "zram3"] {
        assert!(!fake.was_reset(name), "{name}");
    }
}

#[test]
fn the_signature_is_read_at_the_end_of_the_first_page() {
    // An area written with 16 KiB pages read with 4 KiB ones has no
    // signature where it is looked for.
    let fake = Fake::new();
    let mut large = vec![0u8; 16384 * 2];
    large[16384 - SWAP_SIGNATURE.len()..16384].copy_from_slice(SWAP_SIGNATURE);
    fake.device("zram0", "1\n", Some(&large));
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [("zram0".to_string(), Reset::NoSwapArea)]
    );
    let places = Places {
        page_size: 16384,
        ..fake.places()
    };
    assert_eq!(
        reset_idle_swaps(&places),
        [("zram0".to_string(), Reset::Done)]
    );
}

#[test]
fn a_refused_reset_is_said_and_other_devices_are_not_zram() {
    // The kernel refuses the reset of an open device: here the reset file
    // cannot be written. Other block devices are never looked at.
    let fake = Fake::new();
    fake.device("zram10", "1\n", Some(&Fake::swap_area(2)));
    fs::create_dir_all(fake.root.path().join("sys/block/zram10/reset")).unwrap();
    fake.device("vda", "1\n", Some(&Fake::swap_area(2)));
    fake.device("zram", "1\n", Some(&Fake::swap_area(2)));
    fake.device("zramx", "1\n", Some(&Fake::swap_area(2)));
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [("zram10".to_string(), Reset::Refused)]
    );
}

#[test]
fn without_a_sysfs_nothing_is_done() {
    let fake = Fake::new();
    fs::remove_dir_all(fake.root.path().join("sys/block")).unwrap();
    assert!(reset_idle_swaps(&fake.places()).is_empty());
    // A swaps list that cannot be read counts no device as in use, and the
    // kernel would refuse the reset of one that is.
    let fake = Fake::new();
    fs::remove_file(fake.root.path().join("proc/swaps")).unwrap();
    fake.device("zram0", "1\n", Some(&Fake::swap_area(2)));
    assert_eq!(
        reset_idle_swaps(&fake.places()),
        [("zram0".to_string(), Reset::Done)]
    );
}
