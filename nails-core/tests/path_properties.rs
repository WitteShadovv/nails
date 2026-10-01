//! Property tests for configured-path containment and mount table parsing
//!
//! Two promises are checked over generated inputs rather than a handful of
//! examples:
//!
//! - Containment: a configuration either keeps everything nails writes for
//!   the hidden environment (state file and its lock, logs, overlay upper and
//!   work directories, notifications) inside the hidden volume root, or it is
//!   rejected. Roots and paths are built from `.`, `..` and symlinks that
//!   stay inside, escape, or loop, all created in a tempdir.
//! - Round trip: any path, once escaped the way the kernel writes it into
//!   `/proc/self/mountinfo` (`\040 \011 \012 \134`) or the way nails writes it
//!   into overlay mount options, parses back to itself.
//!
//! Case counts are bounded so the suites run in the normal `cargo test` gate.

use nails_core::config::{ConfigBuilder, OverlayConfig, OverlayMode};
use nails_core::filesystem::{
    NailsMounts, escape_overlay_path, parse_mountinfo, parse_overlay_opts,
};
use nails_core::notification::notifications_dir;
use nails_core::{NailsError, StateLock};
use proptest::prelude::*;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Cases per property: enough to mix every component kind, small enough
/// that each suite finishes in well under a second.
const CASES: u32 = 64;

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

/// Components a generated path is made of. `a`, `b` are real directories and
/// `new` does not exist; the others are traversal segments or symlinks that
/// the fixture creates in every directory: `in` points at its own directory,
/// `up` at its parent, `out` at a directory outside the volume and `loop` at
/// itself.
const COMPONENTS: &[&str] = &["a", "b", "new", ".", "..", "in", "up", "out", "loop"];

/// Components that can never leave the directory they start from.
const PLAIN: &[&str] = &["a", "b", "new"];

struct Fixture {
    _dir: TempDir,
    base: PathBuf,
    outside: PathBuf,
}

/// `base/vol/a/b` with the symlinks of [`COMPONENTS`] in each directory and
/// `base/outside` next to the volume.
fn fixture() -> Fixture {
    let dir = TempDir::new().unwrap();
    // Resolve the tempdir itself so only links created here are symlinks.
    let base = dir.path().canonicalize().unwrap();
    let outside = base.join("outside");
    let vol = base.join("vol");
    std::fs::create_dir_all(vol.join("a/b")).unwrap();
    std::fs::create_dir(&outside).unwrap();
    for parent in [vol.clone(), vol.join("a"), vol.join("a/b")] {
        symlink(".", parent.join("in")).unwrap();
        symlink("..", parent.join("up")).unwrap();
        symlink(&outside, parent.join("out")).unwrap();
        symlink("loop", parent.join("loop")).unwrap();
    }
    Fixture {
        _dir: dir,
        base,
        outside,
    }
}

/// `start` followed by `components` and `leaf`, joined as text so `.` and
/// `..` survive exactly as written.
fn join(start: &str, components: &[&str], leaf: &str) -> String {
    let mut path = start.to_string();
    for component in components.iter().chain(std::iter::once(&leaf)) {
        if !component.is_empty() {
            path.push('/');
            path.push_str(component);
        }
    }
    path
}

/// Where `path` really points: the longest existing ancestor with every
/// symlink resolved, followed by the part that does not exist yet.
fn resolve(path: &Path) -> PathBuf {
    for ancestor in path.ancestors() {
        if let Ok(real) = ancestor.canonicalize() {
            let rest = path.strip_prefix(ancestor).unwrap();
            return real.join(rest);
        }
    }
    path.to_path_buf()
}

fn components(max: usize) -> impl Strategy<Value = Vec<&'static str>> {
    prop::collection::vec(prop::sample::select(COMPONENTS), 0..=max)
}

fn is_plain(components: &[&str]) -> bool {
    components.iter().all(|c| PLAIN.contains(c))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn derived_paths_stay_inside_the_hidden_root_or_are_rejected(
        relative_root in any::<bool>(),
        root_parts in components(3),
        state_parts in prop::option::of(components(3)),
        log_parts in prop::option::of(components(3)),
        upper_parts in components(3),
        work_parts in components(3),
        upper_outside in any::<bool>(),
    ) {
        let fx = fixture();
        let root = if relative_root {
            join("vol", &root_parts, "")
        } else {
            join(&fx.base.join("vol").to_string_lossy(), &root_parts, "")
        };
        let upper = if upper_outside {
            fx.outside.join("upper").to_string_lossy().into_owned()
        } else {
            join(&root, &upper_parts, "upper")
        };

        let mut builder = ConfigBuilder::new()
            .hidden_volume_root(PathBuf::from(&root))
            .overlay_mode(OverlayMode::Explicit)
            .overlays(vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: PathBuf::from(upper),
                work: PathBuf::from(join(&root, &work_parts, "work")),
                target: PathBuf::from("/home"),
            }]);
        if let Some(parts) = &state_parts {
            builder = builder.state_file_path(PathBuf::from(join(&root, parts, "state.json")));
        }
        if let Some(parts) = &log_parts {
            builder = builder.log_path(PathBuf::from(join(&root, parts, "logs")));
        }

        let config = match builder.build() {
            Ok(config) => config,
            Err(NailsError::UnsafeConfigPath { .. }) => {
                // Rejection is only allowed when something could escape.
                let clean = !relative_root
                    && !upper_outside
                    && [&root_parts, &upper_parts, &work_parts].into_iter().all(|p| is_plain(p))
                    && state_parts.as_deref().is_none_or(is_plain)
                    && log_parts.as_deref().is_none_or(is_plain);
                prop_assert!(!clean, "a plain configuration was rejected: root {root}");
                return Ok(());
            }
            Err(other) => return Err(TestCaseError::fail(format!("unexpected error: {other}"))),
        };

        let root = &config.hidden_volume_root;
        let real_root = resolve(root);
        prop_assert!(root.is_absolute());
        prop_assert_eq!(&real_root, root, "the accepted root must not involve a symlink");

        let state_dir = config.state_file_path.parent().unwrap();
        let derived = [
            config.state_file_path.clone(),
            StateLock::lock_path(state_dir),
            config.log_path.clone(),
            config.overlays[0].upper.clone(),
            config.overlays[0].work.clone(),
            notifications_dir(root),
        ];
        for path in &derived {
            prop_assert!(
                path.starts_with(root) && path != root,
                "{} is not inside {}", path.display(), root.display()
            );
            prop_assert!(
                resolve(path).starts_with(&real_root),
                "{} resolves to {} outside {}",
                path.display(), resolve(path).display(), real_root.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Mount table round trip
// ---------------------------------------------------------------------------

/// Characters a generated path is made of: plain letters, digits that could
/// be misread as an octal escape after a backslash, every character the
/// kernel or the overlay option syntax escapes, and a multibyte character.
const PATH_CHARS: &[char] = &[
    'a', 'z', '0', '4', '7', ' ', '\t', '\n', '\\', ',', ':', '=', '.', '-', 'é',
];

fn path_from(chars: &'static [char]) -> impl Strategy<Value = String> {
    let segment = prop::collection::vec(prop::sample::select(chars), 1..6)
        .prop_map(|chars| chars.into_iter().collect::<String>());
    prop::collection::vec(segment, 1..4).prop_map(|segments| format!("/{}", segments.join("/")))
}

fn any_path() -> impl Strategy<Value = String> {
    path_from(PATH_CHARS)
}

/// Every [`PATH_CHARS`] entry except the newline, which cannot be carried in
/// an overlay mount option at all.
fn mountable_path() -> impl Strategy<Value = String> {
    const MOUNTABLE: &[char] = &[
        'a', 'z', '0', '4', '7', ' ', '\t', '\\', ',', ':', '=', '.', '-', 'é',
    ];
    path_from(MOUNTABLE)
}

/// Escape `path` as the kernel writes it into mountinfo: space, tab, newline
/// and backslash (plus `extra`) become a backslash and three octal digits.
fn kernel_escape(path: &str, extra: &[char]) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, ' ' | '\t' | '\n' | '\\') || extra.contains(&c) {
            out.push_str(&format!("\\{:03o}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Overlay super options as the kernel shows them: `,` and `:` inside a
/// path are escaped as well, since they separate options and lower layers.
fn kernel_overlay_opts(lowers: &[String], upper: &str, work: &str) -> String {
    let esc = |p: &str| kernel_escape(p, &[',', ':']);
    let lowers: Vec<String> = lowers.iter().map(|l| esc(l)).collect();
    format!(
        "rw,lowerdir={},upperdir={},workdir={}",
        lowers.join(":"),
        esc(upper),
        esc(work)
    )
}

fn overlay_line(id: usize, mount_point: &str, super_opts: &str) -> String {
    format!(
        "{id} 1 0:{id} / {} rw,relatime shared:{id} - overlay overlay {super_opts}",
        kernel_escape(mount_point, &[])
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn mountinfo_path_fields_round_trip(
        entries in prop::collection::vec((any_path(), any_path(), any_path()), 1..4),
        optional_fields in 0usize..3,
    ) {
        let optional: String = (0..optional_fields).map(|i| format!(" shared:{i}")).collect();
        let content: Vec<String> = entries
            .iter()
            .enumerate()
            .map(|(i, (root, mount_point, source))| {
                format!(
                    "{} 1 8:{i} {} {} rw,relatime{optional} - ext4 {} rw",
                    i + 20,
                    kernel_escape(root, &[]),
                    kernel_escape(mount_point, &[]),
                    kernel_escape(source, &[]),
                )
            })
            .collect();

        let parsed = parse_mountinfo(&content.join("\n"));

        prop_assert_eq!(parsed.len(), entries.len());
        for (entry, (root, mount_point, source)) in parsed.iter().zip(&entries) {
            prop_assert_eq!(&entry.root, Path::new(root));
            prop_assert_eq!(&entry.mount_point, Path::new(mount_point));
            prop_assert_eq!(&entry.source, Path::new(source));
            prop_assert_eq!(entry.fstype.as_str(), "ext4");
        }
    }

    #[test]
    fn overlay_options_in_mountinfo_round_trip(
        mount_point in any_path(),
        lowers in prop::collection::vec(any_path(), 1..4),
        upper in any_path(),
        work in any_path(),
    ) {
        let line = overlay_line(30, &mount_point, &kernel_overlay_opts(&lowers, &upper, &work));

        let entries = parse_mountinfo(&line);
        prop_assert_eq!(entries.len(), 1);
        let opts = parse_overlay_opts(&entries[0].super_opts);

        let expected: Vec<PathBuf> = lowers.iter().map(PathBuf::from).collect();
        prop_assert_eq!(&entries[0].mount_point, Path::new(&mount_point));
        prop_assert_eq!(opts.lowerdir, expected);
        prop_assert_eq!(opts.upperdir, Some(PathBuf::from(&upper)));
        prop_assert_eq!(opts.workdir, Some(PathBuf::from(&work)));
    }

    #[test]
    fn overlay_mounted_from_any_hidden_root_is_recognised_as_owned(
        hidden_root in any_path(),
        mount_point in any_path(),
    ) {
        // A hidden root with a space once read as "not mounted", so teardown
        // skipped its overlays. Ownership must hold for any root.
        let upper = format!("{hidden_root}/upper");
        let work = format!("{hidden_root}/.work/upper");
        let line = overlay_line(40, &mount_point, &kernel_overlay_opts(
            std::slice::from_ref(&mount_point), &upper, &work,
        ));

        let mounts = NailsMounts::from_entries(&parse_mountinfo(&line), Some(Path::new(&hidden_root)));

        prop_assert!(mounts.is_owned(Path::new(&mount_point)));
    }

    #[test]
    fn escaped_overlay_options_round_trip(
        lowers in prop::collection::vec(mountable_path(), 1..4),
        upper in mountable_path(),
        work in mountable_path(),
    ) {
        let esc = |p: &str| escape_overlay_path(Path::new(p)).unwrap();
        let lower: Vec<String> = lowers.iter().map(|l| esc(l)).collect();
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.join(":"),
            esc(&upper),
            esc(&work)
        );

        let opts = parse_overlay_opts(&options);

        let expected: Vec<PathBuf> = lowers.iter().map(PathBuf::from).collect();
        prop_assert_eq!(opts.lowerdir, expected);
        prop_assert_eq!(opts.upperdir, Some(PathBuf::from(&upper)));
        prop_assert_eq!(opts.workdir, Some(PathBuf::from(&work)));
    }

    #[test]
    fn newline_is_never_escaped_into_an_overlay_option(path in any_path()) {
        let escaped = escape_overlay_path(Path::new(&path));

        prop_assert_eq!(escaped.is_err(), path.contains('\n'));
    }
}

// ---------------------------------------------------------------------------
// Examples: a space, `,` or `:` in a path
// ---------------------------------------------------------------------------

#[test]
fn hidden_root_with_a_space_parses_from_mountinfo() {
    let line = r"36 35 98:0 / /media/user/My\040Volume rw,nosuid - ext4 /dev/sdb1 rw";

    let entries = parse_mountinfo(line);

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].mount_point,
        PathBuf::from("/media/user/My Volume")
    );
}

#[test]
fn overlay_with_a_space_comma_and_colon_round_trips() {
    let lower = "/srv/a,b:c d".to_string();
    let upper = "/media/user/My Volume/srv";
    let work = "/media/user/My Volume/.work/srv";
    let line = overlay_line(
        50,
        "/srv",
        &kernel_overlay_opts(std::slice::from_ref(&lower), upper, work),
    );

    let entries = parse_mountinfo(&line);
    let opts = parse_overlay_opts(&entries[0].super_opts);

    assert_eq!(opts.lowerdir, vec![PathBuf::from(&lower)]);
    assert_eq!(opts.upperdir, Some(PathBuf::from(upper)));
    assert_eq!(opts.workdir, Some(PathBuf::from(work)));
    let mounts = NailsMounts::from_entries(&entries, Some(Path::new("/media/user/My Volume")));
    assert!(mounts.is_owned(Path::new("/srv")));
}

#[test]
fn escaped_lower_with_a_comma_and_colon_stays_one_layer() {
    let escaped = escape_overlay_path(Path::new("/srv/a,b:c d")).unwrap();

    let opts = parse_overlay_opts(&format!("lowerdir={escaped},upperdir=/u,workdir=/w"));

    assert_eq!(opts.lowerdir, vec![PathBuf::from("/srv/a,b:c d")]);
}
