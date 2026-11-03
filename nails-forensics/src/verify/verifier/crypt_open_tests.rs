// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The line of a mapping that is not open opened a plain volume as LUKS,
//! which fails, and left out its parameters, a detached header and a
//! VeraCrypt PIM. Each volume of the decoy's crypttab is now opened as
//! systemd-cryptsetup opens it, and what has no option here is named.

use super::crypt_open::{Opening, opening};
use nails_base::crypttab::parse_crypttab;

/// The options that open the volume of the crypttab `line` and what is left
/// out, each path the line names in `<>` as `here` gives it.
fn open(line: &str) -> (String, Vec<String>) {
    let volume = parse_crypttab(line).pop().expect("one volume");
    let Opening { options, left_out } = opening(&volume, |path| Some(format!("<{path}>")));
    (options, left_out)
}

fn options(line: &str) -> String {
    open(line).0
}

/// What a plain volume is opened with where its line gives no parameters:
/// systemd-cryptsetup's defaults.
const PLAIN: &str = "--type plain --cipher aes-cbc-essiv:sha256 --key-size 256 --hash ripemd160 ";

#[test]
fn a_plain_volume_is_opened_with_the_parameters_of_its_line_or_systemds_defaults() {
    assert_eq!(
        options(
            "pl /dev/sdb3 none plain,cipher=aes-xts-plain64,size=512,hash=sha512,offset=2048,\
             skip=8,sector-size=4096"
        ),
        "--type plain --cipher aes-xts-plain64 --key-size 512 --hash sha512 --offset 2048 --skip \
         8 --sector-size 4096 "
    );
    assert_eq!(options("pl /dev/sdb3 none plain"), PLAIN);
    // `plain` as the hash is no hashing to both, and a value the shell would
    // split is quoted.
    assert_eq!(
        options("pl /dev/sdb3 none plain,hash=plain,cipher=capi:xts(aes)-plain64"),
        "--type plain --cipher 'capi:xts(aes)-plain64' --key-size 256 --hash plain "
    );
    // Swap and a fresh /tmp are plain volumes with a key that changes at
    // every boot.
    for line in [
        "sw /dev/sdb4 /dev/urandom swap",
        "tm /dev/sdb5 /dev/urandom tmp=ext4",
    ] {
        assert_eq!(
            open(line),
            (
                PLAIN.to_string(),
                vec!["the key file /dev/urandom".to_string()]
            )
        );
    }
}

#[test]
fn the_last_option_that_names_a_kind_of_volume_wins_as_in_systemd() {
    assert_eq!(options("v /dev/sdb none tcrypt,plain"), PLAIN);
    assert_eq!(options("v /dev/sdb none luks,tmp"), PLAIN);
    assert_eq!(options("v /dev/sdb none plain,luks,discard"), "");
    assert_eq!(options("v /dev/sdb none plain,key-slot=1"), "");
    assert_eq!(options("v /dev/sdb none plain,keyslot=1"), "");
    assert_eq!(options("v /dev/sdb none luks,bitlk"), "--type bitlk ");
    assert_eq!(options("v /dev/sdb none luks,tcrypt"), "--type tcrypt ");
    assert_eq!(
        options("v /dev/sdb none luks,tcrypt-keyfile=/k"),
        "--type tcrypt --key-file </k> "
    );
    // A line that names no kind is LUKS, cryptsetup's default too.
    assert_eq!(open("v /dev/sdb"), (String::new(), Vec::new()));
    // A detached header makes the volume LUKS, unless TrueCrypt comes first.
    assert_eq!(options("v /dev/sdb none plain,header=/h"), "--header </h> ");
    assert_eq!(
        options("v /dev/sdb none tcrypt,header=/h"),
        "--type tcrypt --header </h> "
    );
    assert_eq!(
        open("v /dev/sdb none header=/h,plain"),
        (PLAIN.to_string(), vec!["header=/h".to_string()])
    );
}

#[test]
fn a_truecrypt_or_veracrypt_volume_is_opened_with_its_pim_key_files_and_header() {
    assert_eq!(
        open(
            "vc /home/alice/vault.hc none tcrypt-veracrypt,tcrypt-hidden,veracrypt-pim=485,\
             tcrypt-keyfile=/etc/keys/a,tcrypt-keyfile=keys/b,tcrypt-keyfile=/etc/keys/c,\
             header=/etc/vault.hdr"
        ),
        (
            "--type tcrypt --tcrypt-hidden --veracrypt-pim 485 --key-file </etc/keys/a> \
             --key-file </etc/keys/c> --header </etc/vault.hdr> "
                .to_string(),
            Vec::new()
        )
    );
    assert_eq!(
        options("sy /dev/sda none tcrypt-system"),
        "--type tcrypt --tcrypt-system "
    );
}

#[test]
fn a_header_is_read_from_its_path_and_one_on_a_device_systemd_mounts_is_left_out() {
    assert_eq!(
        options("v UUID=ab none header=/etc/v.hdr"),
        "--header </etc/v.hdr> "
    );
    // A colon that no device follows is part of the path.
    assert_eq!(
        options("v UUID=ab none header=/dev/disk/by-path/pci-0000:00:17.0-ata-1"),
        "--header </dev/disk/by-path/pci-0000:00:17.0-ata-1> "
    );
    // A header in a filesystem systemd mounts for it, and a relative one,
    // which systemd refuses, need parameters of their own.
    for header in [
        "header=/v.hdr:UUID=cd",
        "header=/v.hdr:/dev/sdc1",
        "header=v.hdr",
    ] {
        assert_eq!(
            open(&format!("v UUID=ab none {header}")),
            (String::new(), vec![header.to_string()])
        );
    }
    // A BitLocker drive keeps its header on the drive. (A header after
    // `bitlk` makes the volume LUKS, as above.)
    assert_eq!(
        open("b PARTUUID=cd none header=/b.hdr,bitlk"),
        (
            "--type bitlk ".to_string(),
            vec!["header=/b.hdr".to_string()]
        )
    );
}

#[test]
fn what_opens_a_volume_with_no_option_here_is_named_instead() {
    // A key file and where the key lies in it, and the tokens; what only
    // measures, discards or waits at boot changes nothing here.
    assert_eq!(
        open(
            "v UUID=ab /etc/keys/v.key luks,keyfile-offset=1024,keyfile-size=64,tpm2-device=auto,\
             tpm2-pcrs=7,tpm2-measure-pcr=yes,fido2-device=auto,pkcs11-uri=auto,discard,nofail,\
             x-systemd.device-timeout=10"
        ),
        (
            String::new(),
            [
                "the key file /etc/keys/v.key",
                "keyfile-offset=1024",
                "keyfile-size=64",
                "tpm2-device=auto",
                "tpm2-pcrs=7",
                "fido2-device=auto",
                "pkcs11-uri=auto",
            ]
            .map(String::from)
            .to_vec()
        )
    );
}
