# Changelog

All notable changes to NAILS (NixOS Anti-forensics Isolation & Layering System) are documented in
this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and the project
uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for commit history.

Each release is one annotated `v*` tag: a single workflow builds, rebuilds, tests and attests it
and drafts the GitHub release, which a maintainer then publishes (see `RELEASING.md`). The section
of this changelog for that version becomes the release notes word for word, and
`docs/verify-release.md` explains how to verify the assets.

## [Unreleased]

### Upgrade notes

- A `nails.toml` that still sets `accept_persistent_decoy` is refused by the new binary, and the
  decoy is no place to edit it. Before you move `<hidden-root>/nails.new` over `<hidden-root>/nails`,
  run `<hidden-root>/nails.new config validate` inside a hidden session (it checks the
  `config/nails.toml` next to it), delete the key if it is reported, and pass
  `--allow-persistent-decoy` on the activations that need the override.

### Added

- `nails config set <key> <value>...` and `nails config unset <key>...` change settings in
  `nails.toml` in place, so no editor touches it. Only the keys named change: the file's comments,
  its order and every other key stay as they were, a value already set as asked is not rewritten
  (and then nothing is written), a new key goes after the keys of its table, or into a new table
  below the comments that end the file, such as the template `init` writes, and a removed key's
  comments stay. The result is checked as `config validate` checks a file before it replaces the
  old one at once: a new file in the same directory with the old one's owner and mode (root's
  alone for a new file), flushed and renamed over it, under a lock on the directory, so two changes
  at the same time both land. A setting is written only on the volume the running binary lies on:
  the directory `nails` runs from must pass the attach gate and hold the NAILS layout, and the
  kernel refuses a link or another filesystem on the way as it opens the file, so a `--config` file
  on any other volume, the decoy's included, a link at the file, a file with a second name and a
  mount inside the volume are refused (exit 4) and nothing is read or written. While a hidden
  session runs, an activation is entering one or an interrupted entry is left behind, the hidden
  volume root and the state file point only where the session recorded them, since the way back
  and `recover` read its state there; a change that points them back there is written. A key or
  value the file does not take is a usage error (exit 2), a file that would not be valid is the
  error `config` (exit 3), and Ctrl+C or a SIGTERM before the rename stops the change and removes
  the new file (exit 130). Both take `--json`, and `docs/schemas/config.schema.json` describes
  their data, the file named by its absolute path. `init`'s next steps name `config set`
  inside a hidden session instead of a `.new` file moved into place, and so does the README. A new
  fuzz target, `config_edit`, checks that an edit keeps every comment and every key it does not
  name.
- A root helper for the coming window, `nails helper --stdio`, built only with the `gui` cargo
  feature, so the released binary has no such command (a flake check runs the shipped binary to
  prove it refuses it). The window runs as the operator and drives the engine through the helper's
  stdin and stdout, one JSON line per request. The helper speaks first and answers nothing until the
  window's hello names the same release and protocol version; then it runs one request at a time
  and answers each with the envelope and exit code the CLI gives for the same command under
  `--json`, with the progress of `check` streamed as events. It serves `status`, `check`, `config
  path`, `config show` and `config validate` (of its own configuration only, never a path the
  window names: started by pkexec it takes no argument but `--stdio` and reads the configuration
  beside the engine, started by `nails gui` it reads the launcher's), `discard`, `activate`, `deactivate` (both endings), `emergency`, `recover`,
  `verify`, each step of `rehearse`, and `init`. What the CLI confirms, and `init`, runs as a plan
  and an apply: the plan says what the apply would do (a discard and an activation also take the
  state lock) and hands out a single-use token, and only the next request, an apply carrying that
  token, does it. An activation's plan carries the advisories the CLI writes before it asks to log
  out, such as hidden sessions' package database no longer following the decoy's, each with its
  fix, and a deactivation's plan says in a field of its own why a return powers the machine off
  instead (what the way back cannot undo, and whether that holds whatever happens before it runs).
  An activation streams its steps and says when it passes its point of no return; a window that
  closes its pipe before that point cancels the activation, and after it the helper finishes the
  switch. The helper keeps its stdout and stdin off the pipe, so nothing a command or
  a child prints can reach the window. The decoder refuses a line over 16 KiB, an unknown or
  duplicate field, another protocol version and an argument of the wrong shape (a relative path, or
  two options the CLI refuses together), and ends the session; a libFuzzer target
  (`helper_request`) covers it.
- The window's helper changes settings too, as `config set` and `config unset` do: a
  `config_edit_plan` request names the keys to set, each with its value as JSON (a boolean, a whole
  number, a string or a list of strings), and the keys to unset; the helper reads its own
  configuration, makes and checks the change as the CLI does and writes nothing, and answers with
  each key's value before and after and a single-use token. Only a `config_edit_apply` with that
  token, as the next request, writes the file, and only while the file is still what the plan
  read: a file changed in between refuses the apply as `plan_stale`. A plan holds no lock, a
  change the file already holds answers as the CLI does with no token, and a refusal or a failure
  is the CLI's envelope for it, the refusal included of a change that moves the hidden volume root
  or the state file away from where a hidden session recorded them while one runs, is entering or
  was left behind. A cancel of the helper stops an apply before the new file replaces the old one,
  as it stops `config set`. The decoder refuses a change that names no key or more than 32, a key
  twice, a key that is not shaped as one of `nails.toml`, and a value over 4 KiB, with a control
  character or of no kind a key takes; the `helper_request` fuzz target covers it. An empty list
  of names is refused as `config set` refuses no value, and `config_edit_plan` with `unset` is the
  way back to the default.
- The launcher for the coming window, `nails gui`, built only with the `gui` cargo feature like the
  helper (the flake check proves the released binary refuses it too). Run as
  `sudo <hidden-root>/nails gui`, it starts the helper as root and the window's program
  (`<hidden-root>/gui/bin/session`) as the operator on the two ends of one socket pair, and returns.
  On the decoy it first refuses, before any window starts, on a decoy that keeps a persistent record
  (the findings of the activation's decoy persistence check) and on every desktop whose disk,
  journal and D-Bus trace test has not passed, which today is every desktop; the refusal names the
  desktop and each reason and points to `activate`. In a hidden session it always opens. The window
  gets no supplementary groups, `no_new_privs`, no inherited descriptor beyond its pipe and
  `/dev/null`, and an environment from an allowlist: the display, the session bus and the locale, a
  home and XDG directories of its own in the operator's runtime directory (refused unless it is
  private and in RAM), and settings that turn off shader caches, on-disk settings and the portals of
  GTK. The session bus stays, since the screen reader support needs it: at every start AccessKit
  asks the accessibility bus (`org.a11y.Bus`) whether a screen reader listens, which starts at-spi's
  bus launcher through D-Bus activation where it does not run, and the window reads the desktop's
  appearance from the settings portal with `NO_AUTO_START`, so xdg-desktop-portal is read where it
  runs and never started. The desktop trace test that admits a decoy desktop has to clear that. The
  helper and the window each lead a session of their own, so closing the terminal, or the shell
  being killed, signals neither.
- The way into the coming window from a hidden session's menu. A build with the `gui` cargo feature
  whose window program lies at `<hidden-root>/gui/bin/session` writes, at every activation, a menu
  entry "Session" that starts the window as whoever clicks it, and a polkit action for the helper
  the window then asks pkexec for, `<hidden-root>/nails helper --stdio`: its password dialog reads
  "Session needs your password each time it opens." instead of naming the binary, and it asks for an
  administrator's password every time. The action matches the engine and its first argument only, so
  the helper, started by pkexec, refuses any argument but `--stdio` (`--help` included) and exits 2:
  the dialog never covers a command line it does not show. Both go into the hidden root's upper and
  never onto the decoy: on Debian, Ubuntu, Fedora and Arch into `/usr/share/applications` and
  `/usr/share/polkit-1/actions`, on NixOS, which reads neither, into the operator's
  `~/.local/share/applications` and `/etc/polkit-1/actions` (read by polkit 126 and later). Every
  path is resolved inside the hidden root, so a decoy directory that is an absolute link cannot take
  the write onto the decoy disk, and one that leads into the Nix store is refused, each directory
  checked right before anything is made in it. A file that cannot be written is named on one line
  and the activation goes on.
- The window itself, `gui/nails-gui`, a Cargo workspace of its own on the Slint toolkit (its
  software renderer: no GL, no shader cache). It is not part of the release yet. It opens on the
  socket `nails gui` hands it, and from a hidden session's menu entry, which starts it with
  `--engine <hidden-root>/nails`, it asks pkexec for that engine's helper itself; only where `/` is
  the overlay of a hidden session on that engine's volume, so pkexec never runs on the decoy. There
  it first gives itself the launcher's environment, which a desktop's start does not: before its
  toolkit starts it starts itself again, as the same process, on the launcher's allowlist, with its
  home and XDG directories in a directory of its own in the operator's runtime directory (refused
  unless it is private and in RAM), in `/`, with `/dev/null` as its output, and as
  `session --engine -`, which takes the engine's path on standard input instead of its command line.
  However it starts, it turns off its core dumps (a limit of 0), makes itself not dumpable and sets
  `no_new_privs` before it opens. From a menu entry it starts pkexec before that, since pkexec
  cannot become root under `no_new_privs`, and by its set-user-ID path (`/run/wrappers/bin/pkexec`
  on NixOS, else `/usr/bin/pkexec`), never through `PATH`. Started any other way it opens nothing
  and prints the line that opens it. It refuses a helper of another release or protocol with a page
  that says so before it sends anything, and reads each frame strictly and with a size limit. Its
  pages: the decoy's check, which runs when the window opens and shows each check as it finishes,
  then the verdict with each problem and its fix; a hidden session's status; a page for a status the
  engine could not build, such as settings it cannot read, which names no place; and a page for each
  way a session can end (another release, a refused request, a lost connection, an answer it cannot
  read, a password pkexec could not get). A dismissed password dialog closes it. An operation the
  engine confirms first runs as a plan and its apply, and its question sends the plan's token back
  or withdraws the plan at once, and keeps the keyboard until it is answered, Escape cancelling it.
  A question taller than the window scrolls its sentence between its heading and its answers, which
  stay in view, with the wheel, a drag or, from its buttons, the arrow and page keys.
  A ready decoy activates from the window: Activate… asks first, with what the activation's plan
  says (the advisories the CLI writes before it asks to log out, such as hidden sessions' package
  database no longer following the decoy's, each with its fix, then the logout, each risk allowed,
  the warning for a root accepted on this computer's storage, the decoy home, a hidden system to
  build, a missing settings file); the steps then show as they
  stream; Cancel or Escape stops the activation before its point of no return by hanging up on the
  helper, which unwinds it and gives its answer last; and past that point the page reads "Logging
  Out" and takes no input, not even its Close, until the engine says the logout will not come (the
  soft-reboot could not be enqueued), when the page shows that at once with the engine's words, or
  until a minute passed without the logout, when its Close works again and it says how to see where
  things stand. A refused check that names the flag the CLI accepts it with for one run (a decoy
  that keeps a persistent record, `--allow-persistent-decoy`, a hidden volume on this computer's own
  storage, `--allow-decoy-storage`, and discards over the hidden volume, `--allow-discards`) offers
  "Allow for This Activation…", whose button acts only once the word "allow" is typed (the launcher
  refuses a decoy that keeps a persistent record before the window opens); the window then checks
  again with the flag, names the risk on the page and in the question, and gives the flag to that
  one activation, storing nothing: once its apply is answered, its plan withdrawn or refused, or a
  recovery ran, the window forgets the risk and checks again without it. Activation Options, a tool
  of the decoy's page, takes this computer's own system (`--overlay-only`), or else a NixOS flake
  (`--nixos-flake`), to the checks and the activation while the window is open, and the page names
  them. The page of an interrupted
  activation offers Clean Up, and that of a record that cannot be read on the decoy Reset Record,
  both `nails recover`; the window then says what the recovery did, without naming a device, and
  checks again. A hidden session's page deactivates: Deactivate… asks with what the return to the
  decoy would not put back, in the engine's words, and offers both endings, Power Off, the suggested
  one, and Return to Decoy; Power Off asks the engine for the plan of a power-off and applies it
  without asking again. Where the plan says the way back turns the return into a power-off, the
  question says first, in the CLI's words, that the session ends with the machine powering off
  instead of returning, and where that holds whatever happens before the way back runs it offers no
  Return to Decoy. After Return to Decoy on a plan whose return may power off, the page says so in
  the CLI's words. The page then reads "Ending the Hidden Session", takes no input but the Emergency
  control and, where the hidden volume could not be marked to close, says so without naming its
  device; a session still there a minute later gets its Close back, and the page names the Emergency
  control and the power button. A hidden session's window has the Emergency control at the start of
  its header bar, on every page until it fires: also before the helper answered, once it is gone, on
  that page and above an open question, whose dimming keeps everything else out of reach. Held, its
  bar fills in about a second, the window's own countdown, and letting go once it is full ends the
  session; letting go earlier or moving off cancels, a press made beside it and let go on it does
  nothing, and a press too short says to hold it. From the keyboard (it is a Tab stop, never where
  the focus starts) Return or Space ends it on the second press, with no time limit (a key held down
  is one press), and Escape or Tab cancels; a screen reader's activate action takes the same two
  steps, and each change of its label is announced at once. It decides on the input event itself,
  and the emergency then goes its own way on a thread of its own: it writes the engine's emergency,
  ending the session as `window.emergency` chose in advance (below), onto the helper's pipe beside
  whatever request the window waits on (a helper busy with another request reads it once that one is
  done), and where there is no helper, the request cannot be written within 3 seconds, or the window
  still runs 3 seconds after it (the engine's emergency ends the window with the session's other
  programs, so the window still runs then only where the helper did not act on the request in time),
  it asks logind for the power-off itself with `systemctl poweroff`, which needs neither root nor
  the helper, whatever the setting chose. The page names the power button for a computer that still
  does not turn off. The worker's updates reach the window's thread through one task on its event
  loop at a time, at most 64 per turn, so no flood of the helper's events can queue ahead of the
  person's input. A settled page of the session has rows that open the window's tools, each a page
  with Back (Escape goes back too), which asks for the session's status again. Verify runs `nails
  verify`, standard or with Deep Scan; its page puts the verdict first and never more than the
  engine found (no known trace is no proof of none), then each finding with the engine's fix, then
  every area the run did not check, as the engine lists it. Scan an Image, from Verify's page, scans
  a decoy's disk or image mounted read-only instead of this computer (`verify --offline --root`),
  with the examiner's view of its setup traces, grouped by what they suggest, when its switch is on
  (`--examiner`), and the raw disk behind it when one is named (`--disk`); the scan waits for full
  paths. A folder the engine refuses as holding nothing to scan says why and, in the engine's words,
  how to mount the image so that nothing writes to it, then to scan again. Rehearsal shows the
  rehearsal's three steps, where it stands and the action of the next one: Plant Test Words in a
  hidden session, for the account its field names (`rehearse plant --user`) or else the window's
  own, and Scan for Test Words once they are planted. In the session that planted them, which the
  engine refuses to scan and the window remembers for as long as it is open, Scan in This Session…
  asks first, since such a scan proves little, and its button acts only once the word "allow" is
  typed (`--allow-same-boot`), and whose result never reads as a pass. Scan Other Disks, beside the
  scan, scans the disk named instead of this computer's mounted ones (`rehearse scan --device`), or
  with its switch an image (`--offline --image`, with `--token-file` when one is named), and stops
  each read after the megabytes given (`--max-bytes`); it waits for full paths and a whole number,
  and Scan Again repeats it. Removing the test words (Remove Test Words, `rehearse
  reset`) is the decoy's, where no
  window opens yet, so a hidden session's page gives that command instead. A scan's result lists
  first what the scan did not check, a disk whose storage can hide the test words among it, and
  reads Not a Clean Result, never Passed, for such a disk, and Scan Incomplete for one it could not
  read in full; a scan that could not run says so, and never shows the verdict of the scan before
  it. On the decoy, where no desktop is admitted yet, the tools also discard the hidden changes of a
  folder, typed as its full path and sent as the engine reads it (`//home` and `/./home` are
  `/home`), and set up the hidden volume (`nails init`), with or without the hidden NixOS layout
  (its switch first, off for `--no-hardware-config`) and seeded from the hardware configuration its
  field names (`--hardware-config`), its question saying when the engine leaves the layout out,
  each as a plan, its token and its apply:
  the question says what goes (every path the discard deletes from the hidden volume) or what is
  written, and a discard of a folder that holds a home, or of `/nix`, acts only once the folder is
  typed. Either one refused for a hidden volume on this computer's own storage offers Allow for This
  Set Up… or Allow for This Discard…, whose button acts only once the word "allow" is typed, and
  plans again with `--allow-decoy-storage` for that one plan. Both are offered only where the
  window's own reading of the mount table agrees with the
  engine's status that this is the decoy. In a hidden session the tools also show the settings
  (`nails config show`): each key a value can be set for, its value and where it comes from. A
  key's page offers its states or options, the default among the options marked, or a field for a
  number, a path, a flake or a list of names, and Use the Default… where the settings file sets it.
  A change goes through the plan of `config set` or `config unset`, its token and its apply: the
  question names each key with its value before and after, a file that changed before Save writes
  nothing and is read again, and an answer the window does not expect changes nothing more. The
  hidden volume and the record cannot move during a hidden session, so their pages say why and offer
  no change. Every control and row is a Tab stop with an accessible name. The window's own names are
  neutral: its title is "Session", and its app id, its program (`<hidden-root>/gui/bin/session`),
  its process name and the application name a screen reader reads are all `session`. Its command
  line is its name alone, `session` (`session --engine -` once a menu entry's start ran again), so a
  log that quotes it, such as dbus-daemon's line for a service the window's bus traffic starts,
  names no place. Its toolkit starts no program, on X11 or on Wayland: its winit backend is a
  patched copy of Slint's (`gui/patches/i-slint-backend-winit`) that builds winit without
  sctk-adwaita. winit still builds its Wayland client-side frame and hides it, since the window has
  no frame, but that frame is now smithay's fallback frame, which starts no program, where
  sctk-adwaita's ran `dbus-send`, `gsettings` and `fc-match`. The copy also reads the settings
  portal without starting it, and `just vet gui` holds it to the published crate plus its patch,
  byte for byte. A process list still shows `nails` while the window is open: the helper runs as
  `<hidden-root>/nails helper --stdio`. Its tests run without a display, on Slint's testing
  platform.
- `window.emergency` in `nails.toml` chooses in advance how the window's Emergency control ends a
  hidden session, since its gesture asks nothing at that moment: `return`, the default, goes back to
  the decoy's login screen as a plain `nails emergency` does, and so powers off instead where the
  way back cannot undo what the session changed in the network, `poweroff` and `reboot` end it as
  `--poweroff` and `--reboot` do. `config set`, `config unset` and the window's Settings page change
  it as any other key. Only the window reads it: the hot path of `nails emergency` still acts before
  any configuration is read, and its flags choose how each run ends. The window reads the setting
  once the first status of a hidden session came in and again with every read of its Settings page,
  so a change saved there holds from the read after the save. The hidden session's page names what
  the control does, and so does the control's description. The control powers off instead where the
  window cannot be sure the session ends so, and the page then says why: once the window cannot
  reach NAILS (on the page of a deactivation whose switch took NAILS with the session, only once the
  session is still there a minute later); while Verify or Rehearsal waits for NAILS (a step, or the
  read of where the rehearsal stands), since NAILS reads the emergency only after that and the
  window does not wait that long; until the window has read the setting, and where the settings
  cannot be read or hold a value the window does not know; for a return or a restart while a
  deactivation powers off, and for a restart while one returns to the decoy; and for a return in a
  session without a way back, or while the question of a deactivation says the return powers off
  instead whatever happens before it runs. While a deactivation returns to the decoy, the window
  also asks logind for a power-off of the control right after the request, since NAILS takes the
  emergency only after it has started that return, whose switch can end the window and NAILS first.
  A return logind already holds may still come first. Once it fired, the page says how the session
  ends and that the computer powers off where it does not end so.
- `nails check` and activation refuse an updatedb that would list the hidden volume in the
  decoy's locate database (the `locate-database` check). updatedb (plocate, mlocate, NixOS's
  `services.locate`) writes the name of every file it finds into a database on the decoy disk,
  and a run while the volume is mounted on the decoy writes every name on the volume there. The
  check refuses while one runs now (a service the system manager shows active, or a process, one
  started by hand included) or is scheduled, and does not skip the volume; no flag lifts the
  refusal. Scheduled are a service that runs updatedb and that a timer or path unit starts that is
  enabled, that the system manager runs (`systemctl list-units`, a timer started by hand
  included) or that is transient (`systemd-run --on-calendar`), or that is enabled itself (as
  `systemctl add-wants` makes it, which also runs it at the soft-reboot back to the decoy), for
  the system manager and for users' managers, read from every directory systemd loads units from,
  and a cron job: `/etc/crontab`, `/etc/cron.d`, root's and the users' crontabs (cronie's
  unlogged `-` jobs and the input cron feeds a job after `%` included), `/etc/anacrontab` and the
  `/etc/cron.{hourly,daily,weekly,monthly}` scripts, each command read as the shell splits it. It
  reads `/etc/updatedb.conf`, or the file `--config-file` names, as plocate and mlocate read it,
  with the options of each run's command line on top as updatedb reads them (`--prunepaths`
  replaces the file's list, `--add-prunepaths` adds to it, `--database-root` starts the scan
  elsewhere, a relative path resolved where updatedb runs), a service's commands from its unit file
  and drop-ins as systemd reads them. It judges the hidden root where its links lead and every
  other mount of its filesystem: updatedb skips it for a `PRUNEPATHS` entry that is exactly a
  directory on the way to it, a `PRUNENAMES` entry that names one, or a `PRUNEFS` entry that is the
  type of a filesystem mounted on the way. The check passes naming the rule that skips the volume,
  and warns where it cannot tell (an `/etc/updatedb.conf` it cannot read or that updatedb refuses,
  a command or option it does not follow, findutils' updatedb, a unit directory, crontab, cron
  script, `/etc/passwd` or process it cannot read, a timer it cannot ask the system manager about)
  and where only a person starts an updatedb that does not skip it. What it does not read, such as
  a script a cron job runs by its name or an `at` job, docs/decoy-requirements.md lists. The fix it
  prints names the directory the volume is mounted in, never a mount point of the volume: on NixOS
  `services.locate.prunePaths = lib.mkOptionDefault [ "/mnt" ];`, or adding it to the list the
  configuration sets, which the check of the decoy's `/etc/nixos` does not refuse, and elsewhere
  `PRUNEPATHS`, or masking and stopping the timer or service, stopping a transient timer, or
  removing the cron job it found. Fedora installs and enables plocate by default, and the default
  `PRUNEPATHS` of Debian 13, Ubuntu 26.04, Fedora 44 and NixOS do not skip `/mnt`.
- `nails check` and activation warn when a decoy that is not NixOS holds what a Nix install
  leaves behind (the `decoy-nix-trace` check). There Nix belongs inside the hidden session, where
  everything it writes lands on the hidden volume, while a Nix installed on the decoy writes what it
  installs or builds there to the decoy disk, under the name of each package. The check looks for
  `/nix`, whatever it is; `nix-daemon.service` and `nix-daemon.socket` in the unit directories on
  the disk, a link that enables one in a dependency directory of `/etc/systemd/system` and a
  drop-in directory for one there, and `/etc/tmpfiles.d/nix-daemon.conf`; `/etc/nix` and a `nix`
  command in `/usr/bin` or `/usr/local/bin`; the `nixbld` group and the build users in
  `/etc/group`, `/etc/gshadow`, `/etc/passwd` and `/etc/shadow` and in the copies shadow-utils
  keeps of them (`/etc/passwd-` and the others), which still name the group and a build user after
  Nix's uninstall steps; the shell hooks (`/etc/profile.d/nix.sh` and `nix-daemon.sh`,
  `conf.d/nix.fish` in each Fish prefix the installer writes to, the hook lines in `/etc/bashrc`,
  `/etc/bash.bashrc`, `/etc/profile`, `/etc/zshrc` and `/etc/zsh/zshrc`, and the installer's
  `.backup-before-nix` copies); and what Nix keeps in `/root` and in each home `/etc/passwd` names,
  the single-user installer's hook lines in its shell startup files among it, except a home on the
  hidden volume. A lookup that would pass an automount point that nothing is mounted on yet, on
  the way to a home or a file and through a link or not, is not made, since it would mount it: the
  check names that path instead, and where it cannot read the mount table it looks up nothing. It
  names each one it finds, and what it cannot look up or read, and never refuses. It passes on
  NixOS and is skipped inside a hidden session, whose `/` shows the session's own files.
- `nails check` and activation warn when hidden sessions cannot load the running kernel's modules
  (the `kernel-modules` check). A kernel package update in a hidden session (on Arch Linux, a
  `pacman -Syu` that brings a new `linux`) deletes `/usr/lib/modules/<release>` in the overlay
  upper, and every later hidden session starts without modules for the kernel it runs on. The check
  reads the upper and warns when a hidden session deleted or replaced that tree, a directory above
  it or its index (`modules.dep`, or `modules.dep.bin`, the form `modprobe` reads), made one of
  those directories anew so the decoy's copy no longer shows through, or wrote its own index before
  the decoy last rebuilt its own, and when the decoy itself lacks the tree. The fix it prints is
  the `discard` of the path that holds the change, with `--allow-decoy-storage` when the run was
  given it. It offers an update of the decoy's kernel to a new release only when that path is
  `/usr/lib/modules/<release>` itself: a change above that tree hides the decoy's modules for every
  kernel, so there a kernel update does not bring them back. Only root can see whether a directory
  was made anew, so an unprivileged `nails check` that needs to know says it cannot tell instead of
  passing. A decoy without `/usr/lib/modules`, such as NixOS, passes.
- `nails check` and activation warn when hidden sessions' package database no longer follows the
  decoy's (the `package-drift` check). A package change in a hidden session lands in the overlay
  upper, and a later update of the decoy does not reach the record hidden sessions keep of their
  own: dpkg's `status` file and rpm's database are copied whole at a hidden session's first change,
  and pacman lists a package twice when a hidden session and the decoy both changed it. For dpkg the
  check names each package the decoy installed, updated or removed since hidden sessions made their
  copy, with its version on each side, and leaves out the packages a hidden session changed itself
  (their files under `/var/lib/dpkg/info` in the upper show which); for pacman each package listed
  twice, or listed without the files a hidden session deleted. For rpm it reads both SQLite
  databases with a reader of its own (no SQLite library, no `rpm`, nothing written), the committed
  transactions of each write-ahead log included, row by row and keeping of their packages, with the
  links they record, no more than 256 MiB, names each package the decoy changed since as for dpkg,
  and counts a package as a hidden session's own when the upper holds or deleted one of the files
  the package installs, where rpm installed it through the directory links rpm's own records give
  (Fedora records a kernel's modules below its link `/lib`, so a kernel update in a hidden session
  counts as its own). The fix names the package manager's commands to run in a hidden session, and a
  hidden session that deleted or replaced the database itself draws the `discard` that brings the
  decoy's back. Activation shows the warning before it asks to log you out (unless `-y` skips the
  question), lists it again among the warnings of its result (exit 9), and reports it to a window's
  event stream as an `advisory` event. It never refuses. The decoy's database is read as root, with
  `O_NOATIME`, or without root only from a filesystem mounted `noatime`, so an unprivileged `nails
  check` that would need to read it elsewhere says it cannot tell. It also tells where it can
  without the mount table, from the kernel's own word (`statx`) on which directories are mount
  points, asked only of directories below no link or automount point and taking one the decoy lacks
  for none, and passes a dpkg record whose copy holds the same bytes, whatever its format. It still
  says it cannot tell only where no answer is possible without a trace: a symbolic link on the way
  to the decoy's database, a database or upper that cannot be read (an rpm database or log over 4
  GiB, one that records a path of 4096 bytes or more, or one whose packages need more than those 256
  MiB, counts as one), links in rpm's records that make a loop or lead to such a path, an rpm
  transaction or a dpkg run stopped half way (for dpkg's journal in `/var/lib/dpkg/updates` it names
  the `sudo dpkg --configure -a` that finishes the run), or, without the mount table, a kernel
  before 5.8 or a directory the kernel cannot be asked about. The Argon2id advice reads the
  installed cryptsetup through the same dpkg and pacman readers, which now take dpkg's field names
  in any case, as dpkg does.
- `check` notes when the installed cryptsetup cannot open a VeraCrypt volume whose header key is
  derived with Argon2id (the "Argon2" entry added in VeraCrypt 1.26.29), keyed on the installed
  cryptsetup version. No released cryptsetup opens such a volume, and nothing outside the encrypted
  header reveals the algorithm, so it advises making both the outer and the hidden VeraCrypt volume
  with PBKDF2. The version is read from the package database (dpkg or pacman) or the NixOS store
  path, never by running cryptsetup, which would stamp the decoy binary's access time at every
  check and activation; a `check` that is not running as root, or a host whose cryptsetup none of
  these name (Fedora's rpm database among them), skips the note.
- `check` and activation warn when a DMA-capable device could read RAM over the bus: the kernel does
  not remap DMA through an IOMMU, some devices' IOMMU groups are identity-mapped, or a Thunderbolt or
  USB4 controller reports no DMA protection. Each group counts on its own, so a kernel that leaves
  the IOMMU off by default (no `intel_iommu=on`, as on NixOS) and has it turned on only by the
  firmware's Kernel DMA Protection, which remaps the Thunderbolt and USB4 devices and leaves every
  internal device and slot identity-mapped, warns even while a docked device's group is remapped.
  The warning names the devices in the identity-mapped groups, so you can tell a built-in device the
  kernel identity-maps on purpose (AMD's kernel does so for an APU's integrated GPU while memory
  encryption is off) from a card in a slot or a docked device. NAILS cannot change the firmware
  setting; the warning says how, and to power off before the machine leaves your control.
- `nails activate` and `nails check` refuse a decoy with a pending offline system update staged
  (a `/system-update` or `/etc/system-update` marker, on the decoy or in the overlay upper), which
  would otherwise be applied inside the hidden session and reboot the machine out from under it.
  A marker a session deleted (a whiteout in the upper) does not count. For a marker in the upper,
  which neither the decoy's updater nor an `rm` on the decoy reaches, the refusal names the
  `discard` command that deletes it, with `--allow-decoy-storage` when the run was given it.
- `check` and activation warn (`decoy-persistence`) while sssd is in use on the decoy. NAILS is not
  tested on a decoy joined to a domain (Active Directory, FreeIPA), whose domain controller records
  the hidden session's logins and account lookups out of NAILS's reach; the threat model now lists
  such decoys as out of scope. The warning names what shows sssd: an active unit or a running
  daemon, its Kerberos ticket cache listening on its socket (`sssd-kcm.socket`, which Fedora 44
  Cloud enables by default, so a decoy made from it warns), or one of nine files sssd writes under
  `/var/lib/sss` when it runs. The socket counts while either of two reads of PID 1's socket table
  lists something listening on it, or the table cannot be read, as an unprivileged `check` cannot
  read it where `/proc` hides other users' processes; the warning then says that `check` with sudo
  can tell. It does not count on a decoy that is not NixOS where no `sssd-kcm.socket` unit file can
  be in any of the thirteen unit directories docs/decoy-requirements.md lists, none of them reached
  through a link, and a process whose `comm` is `kcm` runs as root in PID 1's mount namespace, as
  Heimdal's KCM daemon, which serves the same socket, does. So on a merged `/usr`, where `/lib` is a
  link, and on NixOS, a socket something listens on always counts. On the decoy disk the probes read
  only file metadata, so no access time there changes. Following its advice clears it where the
  check can read the socket table and nothing else listens on the socket: the advice turns sssd off
  (`systemctl disable --now`, or the `services.sssd` options on NixOS) and names the `rm` of each of
  those nine files it finds, which would keep the warning, and never deletes the socket. The check
  looks for the nine by name and lists no directory, so the rest of sssd's state under
  `/var/lib/sss`, such as the cache of each domain, neither keeps the warning nor goes with that
  `rm`. docs/decoy-requirements.md says why deleting the nine is safe.
- The residue catalog in docs/decoy-requirements.md lists a pending offline update, with what
  systemd's offline-update mechanism does across a soft-reboot and the way back, and sssd on a decoy
  joined to a domain, which docs/threat-model.md also lists among its residual channels. `verify`
  lists both among its areas not checked, each with the reason it does not report them: a scan of
  the decoy disk sees part of each, a link staged on the decoy and the caches and logs of the
  decoy's own sssd, but that is the decoy's own state, while a link a session staged sits in the
  upper on the hidden volume and the domain controller keeps its records out of reach of any scan
  of this computer.
- `nails discard` takes `--allow-decoy-storage`, as `init`, `activate` and `check` do, for a hidden
  root that this computer's own storage seems to hold. Without it, discard refused such a root even
  when activation had accepted it, so nothing could be discarded there.
- A refused check in `check --json` names the flag that would accept it for one run as its
  `allowable`: `persistent_decoy` for `--allow-persistent-decoy`, `decoy_storage` for
  `--allow-decoy-storage` and `discards` for `--allow-discards`. A refusal no flag covers, such as a
  hidden root that is a folder, names none, so a front end can offer an override only where it
  works.
- An error that a flag of its command accepts for one run names that flag as its `allowable`, as
  a refused check does: `activate`, `check`, `init` and `discard` name `decoy_storage` when they
  refuse a hidden root on this computer's own storage, which their `--allow-decoy-storage` accepts.
  No other refusal names one, and `rehearse` and `config` refuse the same root naming none. This
  changes the JSON contract: the schemas of those four commands now allow `allowable`, as
  `decoy_storage` only, in their error object, which is still strict otherwise, and a reader that
  ignores it reads errors as before.
- `status` reports why the last session switch was refused. When a soft-reboot cannot switch root,
  the reason is kept on the hidden volume and shown the next time, instead of a refused switch going
  unexplained; a later successful switch clears it.
- `status` reports why and when the last session switch was refused, instead of a refused switch
  going unexplained. When the soft-reboot into the hidden session cannot switch root, the reason is
  kept on the hidden volume, written through the volume's mount in the prepared root and never on
  the decoy disk (so a hidden root accepted on the decoy's storage with `--allow-decoy-storage`
  keeps none), and shown once you open the volume again. When the way back is refused, the reason
  is kept in RAM with the session's runtime files and shown in the hidden session. `status --json`
  reports it as the `switch_refused` attention, with the refusal's own reason as `reason` and a
  `switch_refusal` object (`reason` and `at`). The next `activate` or `deactivate` clears it when it
  arms its own switch.
- `check` and `rehearse` document and probe more of the cross-distro residue surface a session can
  leave on a persistent decoy: chrony's drift and real-time-clock files, NetworkManager connection
  records, the Plymouth boot log, snapper timeline snapshots, copy-on-write and compressed storage
  history, and the GRUB boot-success counter on Fedora. Each is listed in the decoy requirements and
  threat model with where it lives, how it is checked and how to avoid it. The chrony, Plymouth and
  snapper probes run on every decoy, NixOS included, and report their files wherever the decoy runs
  the daemon. Fedora installs chrony by default, and so does Ubuntu on new systems since 25.10.
- `nails activate` and `nails check` take a per-run `--allow-discards` expert flag that turns the
  discards-over-the-hidden-volume refusal into a warning for one activation. It is buried in the
  long help: `--help` lists it, `-h` does not. It changes nothing about the encryption mapping and
  is never stored in `nails.toml`. It is distinct from cryptsetup's open-time `--allow-discards`
  (the option that turns discards on in the first place); the safe fix is still to re-open the
  volume with discards off. See docs/backends.md.
- `check` and activation warn (`backend-encryption`) when the hidden root's storage has no
  encryption of its own. The check walks the devices under every device of the hidden root's
  filesystem (each one of a btrfs or bcachefs filesystem of several): into the device behind a
  loop over a block device, from a partition into its disk where that disk keeps its data
  elsewhere (a loop, device-mapper or md device), and from a loop over a file into the devices of
  the filesystem the loop driver recorded for the file, or, where only root could read that
  record, the one the file's path leads to. Every way down to a disk has to pass a cryptsetup
  mapping of type TCRYPT, LUKS1, LUKS2, PLAIN, LOOPAES, BITLK, FVAULT2 or SUBDEV, or a mapping
  named as the VeraCrypt application names its own, that is not the decoy's: not its storage as
  the attach gate counts it, with every device below a partition of it on a disk that keeps its
  data elsewhere (the devices of the md array the decoy's root is on, which its boot opens), nor a
  volume its crypttab opens from a device or an image file, under whatever name it was opened. A
  crypttab line for the hidden drive itself, one that opens it or a device it is stored on, is no
  claim: `backend-entries` refuses that line. It knows a mapping by its device-mapper uuid and name
  and reads no mapping's table. It warns, naming the device, where nothing encrypts the hidden
  root; where only the decoy's own encryption does, as for a plain image file on the decoy's
  encrypted `/home`, which whoever unlocks the decoy can read; where it cannot tell (a
  device-mapper device of a kind it does not know, a loop device whose file it cannot follow to a
  disk or whose path disagrees with the loop driver's record, a ZFS volume, an nbd, ublk or zram
  device, a filesystem that shows no block device, such as ZFS); and for a tmpfs or ramfs root,
  whose contents a power-off ends. dm-integrity and dm-verity encrypt nothing. It never fails a
  run. See docs/backends.md.
- docs/backends.md weighs VeraCrypt's rule that on Linux a hidden volume be mounted only from a
  live system writing to a RAM disk: a NAILS setup does not meet it, since you unlock and mount the
  hidden volume with cryptsetup on the running decoy before every session. It also passes on
  VeraCrypt's warning for hidden volumes made in file containers with VeraCrypt 1.26.6 through
  1.26.28, which upgrading VeraCrypt does not repair: if you rely on deniability, recreate the
  container and its hidden volume with 1.26.29 or later, away from the decoy, then securely erase
  the old container.
- Development: the `gui/` workspace, where the graphical interface will be built, gets its
  guardrails before any toolkit dependency lands. Its graph is checked against a cargo-deny policy
  of its own, `gui/deny.toml`, wherever `deny.toml` is checked, and cargo-vet is part of the CI gate
  for it: a third-party crate that no audit or recorded exemption covers fails the pull request that
  brings it in. Its tests are held to a line-coverage floor of 85%, the file size and orphan module
  checks now cover it and the `setup/` workspace, and `nix build .#nails-gui` builds its binary,
  still a placeholder that draws no window.
- `check` and the `inherited-autostart` warning list the autologin of Plasma Login Manager, KDE's
  display manager: `User=` under `[Autologin]`, or under the first seat's `[Autologin][seat0]`, in
  `/etc/plasmalogin.conf` and the drop-ins of `/etc/plasmalogin.conf.d` and
  `/usr/lib/plasmalogin/plasmalogin.conf.d`, read as releases up to 6.6 parse them and as KConfig
  parses them since 6.7, in each language a translated `User=` is for. KDE Frameworks 6.26 to 6.28,
  which Plasma Login Manager 6.7 also runs on, keep the settings of drop-ins differently from 6.29
  and later, and the files are read both ways. An account any of these readings names is listed,
  whatever `Relogin` says; on systemd 256 and later, Plasma Login Manager 6.7 and later log in after
  a soft-reboot only with `Relogin=true` (docs/operator-guide.md).
- The forensic oracle scans btrfs images, the default root of Fedora and Arch decoys. plaso cannot
  read btrfs, so on btrfs images no timeline runs, and the verdict says `partial` (exit 3), never
  `clean`, and names `timeline: not run, plaso cannot read btrfs`. The restore carve and
  bulk_extractor stay required on every image, and the journal files plaso would compare are
  compared as files instead. The positive controls of a real btrfs image go into device space
  no btrfs chunk uses, with no mount. A nightly job scans synthetic btrfs images and passes only on
  that partial verdict (ci/oracle/README.md). Of a whole-disk image the restore channel now compares
  every byte outside the root filesystem as well: an EFI system partition's files, carved through a
  read-only mount, and its boot sector and allocation tables by their bytes, a small partition with
  no filesystem whole by its bytes, and the partition table and every gap no partition covers by
  their bytes. A partition holding any other filesystem, a table mmls cannot read or that does not
  list the root, an image with a filesystem at byte 0 beside a partition table, and an ext4 journal
  or btrfs log tree the carve would not replay each stop the run. Before, only plaso's limit to one
  partition stopped a disk of several, and only where a timeline runs.
- The oracle real-image nightly also images a real btrfs decoy: a stock Fedora 44 Cloud disk, kept
  whole before, after a plain reboot, after a second plain reboot and after a hidden session and the
  way back, then scanned without the timeline, once with the session and once with the second plain
  reboot in its place, which must leave nothing. Fedora is not admitted yet, so these images come
  from a test-only build that admits its row and is never released (ci/oracle/README.md).
- Two kinds of line bulk_extractor writes no longer stop an oracle scan before its verdict, on ext4
  as on btrfs: a zip member's description is passed over beside its saved file, whose hash keys the
  member, a member found in decompressed data included, and a login record it names `<CACHED>` is
  read from the record it saved with the same hash.
- On every oracle scan, ext4 included, a carved login record new in after is now also subtracted by
  a record of exactly the same key in the control image's login files, which the scan keeps whole
  and reads. bulk_extractor carves a record only where its bytes lie plain and in one piece, which
  btrfs compression and the place of each block decide, so the control could miss records it holds.
  On btrfs, bulk_extractor sees no compressed extent at all, and a btrfs scan's verdict now names
  `compressed_extents` among the classes it cannot see (ci/oracle/README.md).

### Changed

- The checks that need the hidden volume, which are skipped once the `hidden-volume` check fails,
  now give the reason `requires the hidden-volume check to pass` instead of
  `requires mounted hidden volume`: that check also refuses a volume that is mounted, one mounted a
  second time among them.
- `config show --json` now names in `data.sources` the source of each key of a table too, written
  `table.key` (`persona.mode`, `sleep_policy.mode`), beside the source of the table itself, which
  only says that the file holds the table. A table the file holds, even as the empty header an
  `unset` leaves, no longer makes each of its keys look set by the file. A consumer that walks
  `sources` and looks each key up in `data.config` now meets these dotted keys: their values lie
  in their table (`data.config.persona.mode`). The schema version stays 2.
- `recover` on the plain decoy now also resets a record on the hidden volume that cannot be read or
  trusted (malformed, failing its integrity check, from a newer release, or unreadable), which left
  activation refusing with no command to clear it. No hidden session is active there, which the
  live mounts show, so the record is replaced with an inactive one; `--json` reports the outcome
  `record_reset`. In the hidden session, and while an activation enters, `recover` still refuses,
  and a record this process may not read at all is left alone.
- `check` and activation warn (`hidden-volume`) about any label on the hidden volume's filesystem,
  not only one with a telling word in it. Even a neutral label such as `data`, the one the examples
  and test volumes used to carry, shows in `/dev/disk/by-label`, in systemd's device units, in file
  managers and in `lsblk`, and everyone who copied it shares it. The warning says to remove the
  label where setup happens, not on the decoy (on ext4, `e2label <device> ''`). A root on a
  filesystem the decoy uses, accepted with `--allow-decoy-storage`, carries the decoy's own label
  and does not warn. The label is read from udev's record of the device in `/run/udev/data`,
  which names the label of exactly that device, and only without a record from
  `/dev/disk/by-label`, which links one of several filesystems with the same label. A new fuzz
  target, `udev_label`, checks that a label written as udev writes it reads back unchanged.
- The operator is now resolved from `PKEXEC_UID` before `SUDO_UID`. pkexec of polkit 127 and later
  sets both, and `PKEXEC_UID` names the account that asked it.
- `rehearse` reports a decoy on a copy-on-write or compressed filesystem (btrfs, bcachefs, zfs or an
  f2fs mount with compression) as "not checked" rather than "clean" for leaked-then-deleted traces:
  such a filesystem keeps old copies in unreferenced extents and stores file contents compressed, so a
  raw plaintext scan can neither reach those old copies nor read a compressed extent, and a clean scan
  there cannot prove a trace is gone. A live decoy is classified from its mount table, and an offline
  image or an unmounted `--device` from its on-disk superblock and, for a whole disk, partition by
  partition, so a decoy read that way is reported "not checked" too. An f2fs counts only when it can
  compress: a mounted one whose options show compression, which the kernel always lists for an f2fs
  made with the compression feature, and an image or unmounted device whose superblock carries that
  feature. A plain f2fs stores every file verbatim and gets a clean result.
- Discards (TRIM) reaching the hidden volume now refuse activation instead of only warning:
  forwarding TRIM to the physical device leaves a readable map of used and free blocks, where a
  deniable volume should look like uniform random data, and writing an outer volume with discards
  on can destroy a hidden volume inside it. A LUKS2 mapping with runtime or stored discards is
  included, and a stack that rests on RAM-only zram devices alone is excepted: a zram device
  elsewhere in a stack that also rests on a disk (the cache of a cached logical volume, say)
  excepts nothing, and neither does a stack the check could not read to its end. Every activation
  runs the refusal, like the decoy-entry and decoy-flake refusals, and it names no device-mapper
  node.
- A derivative of a supported distribution — one whose os-release `ID_LIKE` names `debian` or
  `ubuntu`, such as Linux Mint — now runs with a warning that NAILS has not tested it, instead of
  being accepted silently. Fedora, Arch and their known derivatives, Enterprise Linux rebuilds
  (RHEL, CentOS, AlmaLinux, Rocky, Oracle) and SteamOS are each refused with a reason that names
  them and says NAILS has not yet validated them. A host whose `ID_LIKE` names `debian` or `ubuntu`
  and also `fedora`, `rhel`, `centos` or `arch` is refused, naming that family, wherever each
  stands in the list; 0.3.0-rc.3 accepted it as a Debian derivative.
- The platform table now holds the gate Fedora and its derivatives will take once Fedora is
  admitted. Fedora will be gated on its edition (os-release `VARIANT_ID`) as well as its release:
  Cloud will be the tested edition, and Workstation, KDE Plasma Desktop, any other edition and a
  Fedora host that names none will run with a warning that NAILS has not been tested on that
  edition, in `init`, `check` and `activate`; the `platform` row of `check` will name a tested
  edition (`Fedora 44 Cloud`). Nobara and Ultramarine will be refused below release 44 or without
  a release, and from 44 run with the untested-derivative warning. Fedora, Nobara and Ultramarine
  are still refused until Fedora's support has been verified, so no host's verdict changes yet.
- `check` and activation now warn on Ubuntu 26.04 instead of treating it as a clean tested release.
  A known upstream issue affects it: after the switch into the hidden session, AppArmor blocks chrony
  and CUPS from reaching systemd and the journal, so the clock does not sync and printing times out,
  and after the way back the decoy lists chrony as failed until its next full reboot, which hints a
  soft-reboot happened. 26.04 remains a tested release; reboot the decoy fully after a session to
  clear it. The fault is upstream, not in NAILS.
- Ubuntu 26.04 joins the automated distribution tests, beside Debian 13 and Ubuntu 24.04. They
  expect chrony's known upstream failure in the hidden session and after the way back, so they show
  when Ubuntu fixes it. Printing (CUPS), which their image does not install, is still checked by
  hand.
- A host that boots from a sealed composefs image is now refused even when it does not set
  `/run/ostree-booted`, recognised by its kernel command line or the composefs runtime directory.
  NAILS cannot overlay an immutable system.
- The hidden session's state file can now record which Linux family the host belongs to, without
  changing its on-disk format. A state file written by a 0.3.0 pre-release loads unchanged after the
  upgrade with its integrity digest intact, so an existing install is never read as corrupt.
- The host-tools pre-flight check requires only the tools NAILS actually spawns — `systemctl`,
  `loginctl` and `ip` on every host, `dmsetup` when the hidden volume is on device-mapper, and `nix`
  on NixOS — and names a missing one with an install hint for the host's package manager (`apt`,
  `dnf` or `pacman`). It no longer requires `systemd-run`, `cp`, `chown`, `sync`, `swapoff` or
  `kill`, which NAILS does through system calls or systemd units rather than by spawning a binary.
- When systemd is too old for a soft-reboot, `check` and activation now say how to upgrade this
  host, the way its distribution documents it: Debian 13 by its release notes, Ubuntu 24.04 or 26.04
  with `do-release-upgrade`, Fedora 44 with `dnf system-upgrade`, a full `pacman -Syu` on Arch,
  EndeavourOS, CachyOS and Manjaro, and on NixOS a current release for the decoy's nixpkgs, rebuilt
  and booted. Nobara, Ultramarine and a Debian derivative NAILS runs on are pointed at a release
  built on a tested one, upgraded as each documents, and any other host at the platforms NAILS runs
  on. The hint used to name the Debian, Ubuntu and NixOS releases whatever the host.
- `check` shows the "NixOS profile" section only on NixOS, or where an explicit NixOS build target is
  configured; a Debian, Ubuntu, Fedora or Arch decoy no longer prints a NixOS-profile line that does
  not apply to it.
- The machine-readable `--json` output moves to contract version 2 (`schema_version` is now `2`), a
  breaking change for scripts. Every command but `completions` prints exactly one envelope on stdout
  — the root privilege gate, a usage error (`config` without its subcommand among them), a Ctrl+C
  and an internal error included — and `activate` no longer streams progress lines before its result
  (`config show` likewise prints one document rather than a multi-line one). The envelope's `ok` is
  `true` only when the exit code is `0` or `9`, so a `verify` warning, a degraded `emergency` or
  `recover`, and a refused `check` now read as `ok: false`. A `rehearse scan` that could not check
  every device exits `9` and still reads `ok: true`: its exit code, not `ok`, says it is not a clean
  result. `status` reports where the machine is as `place` (`decoy`, `hidden` or `activating`, or
  `unknown` when reading the record was refused, so no report could be built) and the one thing that
  needs the operator as `attention` (`record_unreadable` in any place when the record cannot be read
  or trusted; only a hidden root without a way back and an interrupted activation come first),
  replacing the version-1 `posture`, `session`, `state` and `state_source` fields. An error now
  carries a stable `code`, the human `message`, and a typed `next` step — the command to run next,
  or `null` — in place of the free-form `hint`. A cancel
  reports one shape: an error with the code `cancelled`, no data, and exit `130`. That is a "no" at
  any prompt; Ctrl+C at a prompt, during `emergency --countdown` or in an activation before its
  point of no return; and, under `--json`, Ctrl+C or SIGTERM during `status`, `verify`, `check`,
  `config`, `init` or `rehearse`. A teardown that has begun (`deactivate` past its prompt,
  `emergency` once it acts, `recover`, `discard` once it deletes) runs to its end and reports its
  result. An internal error is the error `internal_error`, with exit `1`; one that comes after the
  result was printed leaves that envelope as it is, `ok` included, and still exits `1`.

  Exit codes that changed in this release:

  | Code | Before | Now |
  |---|---|---|
  | 1 | failed; also a "no" at the `activate` or `deactivate` question | failed, or not possible here. A "no" at any prompt now exits 130 instead |
  | 130 | Ctrl+C | Ctrl+C, and a "no" at any prompt |

  Codes 2, 3, 4, 5, 6, 7, 8 and 9 keep their meaning. Scripts that read the removed JSON field names,
  that treated a declined prompt as exit 1, or that parsed `activate --json` as a stream of lines must
  be updated. A JSON schema per command ships under `docs/schemas/`.
- The `--no-preflight` flag is removed. Activation always runs the full pre-flight registry, so the
  decoy-entry (`backend-entries`), decoy-flake (`nixos-build-target`) and discard (`backend-detect`)
  refusals the flag used to leave in place now run as part of every activation. Drop `--no-preflight`
  from any script.
- The persistent-decoy risk override is a per-run flag only. `--accept-persistent-decoy` is renamed
  `--allow-persistent-decoy` (on `activate` and `check`), matching `--allow-decoy-storage`, and the
  storable `accept_persistent_decoy` key is removed from `nails.toml`, so a fail-closed check can no
  longer be turned off for good. A config file that still sets the key is refused with a note that it
  is now the per-run `--allow-persistent-decoy` flag.
- `reset-upper` is renamed `discard` and hidden from the command list. It still takes a path, lists
  what it would delete and confirms first; its `--json` envelope now reports the command and its
  error code as `discard`.
- The `doctor` alias for `check` is removed. Run `check`.
- Activation gives the root of each overlay's upper, which becomes the hidden `/` or the root of an
  overlaid decoy filesystem such as a separate `/home`, and each directory the upper holds below it
  on the way to the operator's home the SELinux label of the decoy directory it stands for. Without
  them a host that runs SELinux sees the hidden `/` as `unlabeled_t`, which confined services may
  not even look up. The labels are read from the decoy without changing anything there, not even an
  access time, and each is written onto the hidden volume before the overlay over that upper is
  mounted. No other directory NAILS makes on the hidden volume takes a label from the decoy, so on
  such a host each shows as `unlabeled_t` unless the volume was relabelled, among them `root`,
  `root/mounts/<unit>` and the work directories, which the hidden session sees through the hidden
  volume's bind, and the hidden `/etc/nixos`, with `/etc` where `init` made it, that
  `init --hardware-config` makes in the root upper. Where the mount table in `/proc/self/mounts`
  lists a selinuxfs, or cannot be read while `/sys/fs/selinux` exists or `/etc/selinux/config` sets
  `SELINUX=` or `SELINUXTYPE=`, or the host cannot be detected, a label that cannot be copied
  refuses the activation and undoes it: a hidden volume whose filesystem
  stores no labels, a decoy directory without one, a policy that denies the relabel, or an operator
  without a home on the decoy, in the fresh-home persona and, once the upper holds a home for them,
  in the shared-home persona. Elsewhere a label is copied only where the decoy has one, so a decoy
  without labels gets the hidden root it got before. That includes a host that keeps an
  `/etc/selinux/config` from SELinux packages installed once, or an empty `/sys/fs/selinux`, while
  no selinuxfs is mounted: SELinux does not run there, and the activation says so in one line. `nails check` does not test this yet; see
  docs/decoy-requirements.md.
- `--nixos-flake` and `nixos_flake` refuse the decoy's own `/etc/nixos`, and now every directory
  below it, in more spellings, and compare directories by what they are, their device and inode, so
  a link and a bind mount of `/etc/nixos` (impermanence's `/persist/etc/nixos`) count. The new
  spellings: `hg+file:` and every other URL whose transport is a local file, with no authority or
  an empty one, percent-encoded (`path:/etc/%6Eixos`, a `dir` parameter `dir=%6Eixos`), with a
  `dir` parameter that starts with a `/` (`path:/etc?dir=/nixos`, which Nix appends to the path),
  through the repository's `.git` directory (`git+file:///etc/nixos/.git`,
  `git+file:///etc/.git?dir=nixos`, which Nix fetches from the repository the directory belongs
  to), with `.` or `..` components, both as the kernel resolves them after the links before them
  (`/var/run/../etc/nixos`, as Nix reads a path and `git+file:`) and by the text even where a
  directory on the way does not exist (`/etc/nixos/x/..`, as Nix reads `path:`), and the path
  relative to the working directory that Nix reads a reference it cannot parse as a URL and an
  input as (`git+file://../../etc/nixos`, `github:/../../etc/nixos`). The `nixos-build-target`
  check now passes only what NAILS can tell how Nix reads: a path or a `path:` reference, a URL
  whose transport is a local file with no authority, and a plain remote reference
  (`github:owner/repo`, `git+https://example.org/repo`). Anything else fails it whatever it names:
  a local URL with an authority, a reference such as `a_b:x` or `github:/srv/cfg`, a remote URL
  with a trailing slash, a percent-escape, an IPv6 host or a `user:token@`, and a registry alias
  such as `flake:nixos-config`, as the name alone already did. `<hidden-root>/nixos` counts as the
  decoy's flake the same way, as a link to `/etc/nixos` or a directory below it or as a bind mount
  of it, where only a link to `/etc/nixos` itself counted. An error looking at
  `/etc/nixos/flake.nix` or `<hidden-root>/nixos/flake.nix`, other than its absence, refuses too,
  in discovery as for a named reference, where it passed as "no flake". A git directory of its own
  that holds the decoy's flake (`git+file:///var/lib/cfg.git`) and `git+ssh://localhost/etc/nixos`,
  through an SSH login to the machine itself, are not recognised. Name the flake by its absolute
  path or a plain URL.
- A cancelled activation says what it left. Its notice read "Activation cancelled; nothing was
  changed.", but what the activation wrote to the hidden volume stays there, such as its log, the
  residue baseline and the parts of the hidden NixOS system a build had finished. On a hidden
  volume of its own it now reads "Activation cancelled. It wrote nothing to this computer's
  disk.", and once the entry of an activation that builds a hidden NixOS system has begun, a
  second line follows: "Anything already built stays on the hidden volume for the next
  activation." Where the attach gate warned about the hidden root, as for an encrypted container
  file on a decoy filesystem, it reads "Activation cancelled. What it wrote to the hidden volume
  stays there.", and for a root allowed with `--allow-decoy-storage` "Activation cancelled. What
  it wrote to the storage you allowed stays there." The `--json` cancel envelope and the window
  carry the same words. A Ctrl+C after the question, or under `-y`, starts the notice on a line
  of its own on a terminal, where it began right after the `^C` the terminal echoed.
- `rehearse plant` sends its notification canary with normal urgency, as an ordinary message has,
  where it used low urgency. A desktop may show a notification of low urgency without a banner, so
  the channel could be reported as planted while the desktop showed no banner for it. The operator
  guide says when `plant` counts the channel as planted.

### Fixed

- The attach gate refuses a partition of a loop device whose image file lies on the decoy's disk,
  as it refuses the loop device itself. A partition the kernel made on a loop device (`losetup -P`,
  or a disk image opened in a file manager) shows no device below it, so the image file behind it
  went unjudged and a root on it attached, and every write of a session landed in that file on the
  decoy's disk. A partition of a loop or device-mapper device now lies where that device keeps its
  data, so an image file, an encrypted container file or a device the decoy uses below it is
  judged as for the whole device. A partition whose disk is not found is refused
  (`storage_unjudged`), since nothing shows where it keeps its data.
- The attach gate refuses a partition of an md array whose devices lie on the decoy's storage, as
  it refuses the array itself. A partition of an array shows no device below it, so a root on
  `md0p1` attached where one on `md0` was refused, as for an array of image files on the decoy's
  `/home` or of a spare logical volume in its encrypted group. A root on a partition of an md array
  is now judged as one on the array, and `backend-entries` names the decoy's fstab and crypttab
  lines for the array's devices as it does for the array. Two partitions of one array still share
  nothing, as two partitions of one disk share nothing.
- The attach gate refuses a hidden root on a network block device (`nbd`) or a userspace block
  device (`ublk`) unless `--allow-decoy-storage` is given, and one on a ZFS volume (`zvol`)
  outright. sysfs shows nothing below such a disk, so a root that `qemu-nbd` or a ublk server served
  from an image file on the decoy's disk, or a ZFS volume in the decoy's own pool, attached, and
  every write of a session landed on the decoy's disk. The gate now tells these disks by the driver
  `/proc/devices` lists for their device number, and a `ublk` disk, whose number comes from the
  range the kernel shares between drivers, by the name its driver gives it. It refuses a root whose
  data reaches one anywhere on the way down: the disk itself, a partition of it, an encrypted
  mapping, a logical volume or an md array on it, an image file on a filesystem on it, or a device
  the root's filesystem keeps data on besides the one it is mounted from. That is an XFS log or
  realtime device, which the mount options name, an ext3 or ext4 journal on a device of its own,
  which jbd2 lists and the filesystem's journal thread names, and the other devices of a bcachefs
  filesystem, which its source names. The gate weighs those devices for a filesystem that holds an
  image file on the root's way and for the decoy's mounted filesystems too, and refuses a root as
  storage that cannot be judged (`storage_unjudged`) when one of them cannot be read or found. An
  `nbd` or `ublk` device is refused as not storage of its own (`not_separate_volume`), and
  `--allow-decoy-storage` turns that into a warning for a device you know is served from storage the
  decoy does not use, so the window offers "Allow for This Activation…" for it. An image file on a
  decoy filesystem that lies on such a device is refused as an image file on that filesystem, and an
  encrypted container there, which would only warn on another disk, as on the device. A ZFS volume
  is refused as storage whose disks cannot be told (`storage_unjudged`), as a ZFS dataset is, and no
  flag lifts that, not even for a root on a filesystem of the decoy's on the volume or one the
  decoy's fstab mounts from it. A disk whose driver the kernel does not name is refused the same
  way, as is a disk on the range of numbers the kernel shares between drivers that sits below no
  other device and is no `ublk` disk (a zoned loop device, which keeps its zones in files), and so
  is a root on any disk where `/proc/devices` cannot be read, on a loop device that shows no file
  (its path is longer than the kernel shows), or on top of a device whose devices sysfs cannot list.
  A loop device over the node of a device outside `/dev` is judged as that device, by the loop
  driver's record, and a `zram` device with the device it writes pages back to. A root that shares a
  device only with entries the decoy never mounts at boot, which only warns, no longer hides such a
  refusal, nor that of an image file whose filesystem cannot be told. Ordinary disks, iSCSI disks
  and `zram` devices that write nothing back are judged as before.
- The attach gate judges an image file that holds the filesystem the root's image file is on as it
  judges the root's own image file, as deep as such files go. On a decoy filesystem it is refused,
  or only warns where it is an encrypted container, as the root's own would. Where no filesystem
  mounted here holds it, its loop device's record cannot be read or its filesystem shows no device,
  the root's storage cannot be judged (`storage_unjudged`). Before, such a root attached. The gate
  also follows a stack of any width: a device the root shares with the decoy counts however many
  devices an array or volume group spans (the walk stopped after 32 before), and a device that sysfs
  does not list below another refuses the root as storage that cannot be judged.
- `backend-entries` no longer says to remove a line the decoy's own boot needs. Where a flagged
  fstab line mounts the decoy's root, another of its filesystems or its swap, or a flagged crypttab
  line opens a device below one of them (the LUKS devices of the md array the decoy's root is on,
  say), the hidden root lies on the decoy's own storage and removing the line would break the
  decoy, so the check now says to put the hidden root on storage of its own instead. Where it also
  flags lines only the hidden volume needs, it still says to remove those, since once the hidden
  root moves they are flagged no more and would stay behind naming it.
- `backend-entries` no longer refuses a root that `--allow-decoy-storage` accepted as a folder or a
  btrfs subvolume of a filesystem the decoy uses for the decoy's own fstab lines that the boot
  mounted at `/` or at a system folder for another part of that filesystem (`/usr`, `/var`, `/home`,
  `/srv`, `/boot`, `/efi`, `/boot/efi`, `/nix` and `/opt`, unless the hidden root is that folder or
  lies above it): its top, or a subvolume above or beside the root's, such as the line for `/` below
  a bind of a folder of `/`, or the line for the `/home` subvolume beside a btrfs subvolume at the
  root. Such a line names the root's device, so the check took it for a line that mounts the volume
  itself and said to remove it, while it mounts the decoy's own filesystem, which removing it would
  break. The line's mount has to be there: the mount at its folder is of that filesystem and shows
  what the line names. The check reads what that mount shows, so a mount made there by hand that
  shows the same counts as the line's own, and it reads a btrfs line with neither `subvol=` nor
  `subvolid=` as one for the filesystem's top. A line that mounts the volume itself still fails the
  check, with the flag too: one for the root's own subvolume or a subvolume inside it, by `subvol=`
  or by the `subvolid=` the mount table shows for it, and any line for a root that is the whole
  filesystem, such as a separate drive that the fstab mounts at `/srv`. So do a line whose mount is
  not there, such as the line for `/srv` of a separate drive that is mounted only at a folder bound
  at the root, a btrfs line whose subvolume cannot be told (one that gives `subvol=` or `subvolid=`
  twice, of which btrfs takes the last, or a `subvol=` path with `..`), and a line the boot mounts
  for that filesystem at any other folder, which may name the hidden drive's disk; for a folder or a
  subvolume root the check now says that it mounts the filesystem the volume is part of and that the
  decoy's own boot needs it, and to put the hidden root on storage of its own instead. A `noauto`
  line for that filesystem is still one to remove. A line the boot mounts (no `noauto`) for `/` or a
  system folder that names the root's filesystem is one the decoy's own boot needs whatever it
  mounts of it, so the check never says to remove it.
- `backend-entries` now refuses an fstab bind line whose source lies in the hidden volume, at the
  root's folder or inside it as the mount that holds the source shows it, whatever type the line
  gives and with `_netdev` too: such a line mounts the volume, or a folder of it, since `mount`
  binds whatever the type says. It let such a line pass, and with `--allow-decoy-storage` the check
  passed a root bound from a folder of `/` that the decoy's own fstab binds at the root at every
  boot. It says to remove such a line, unless the boot mounts it at a system folder, where it says
  to keep it and to put the hidden root on storage of its own instead. So it does for a swap or
  image line whose file lies there, which the boot swaps on or mounts. NAILS does not follow
  symbolic links in the path of a bind line's source, a swap file or an image file: it looks at each
  part of the path on its own, as `lstat` does, so it reads no link and changes no access time. A
  line whose path cannot be told this way fails `backend-entries`, with `--allow-decoy-storage` or
  without it, as one that may mount the volume, and the check says why, naming the link, the device
  node or the folder where there is one, and says to write the line with its real path: a path with
  a link in any part, which `mount` and `swapon` would follow at boot, a device node, outside `/dev`
  too, one that crosses the folder of an fstab line, a `noauto` one too, while that line's mount is
  not there now, one with a part that cannot be looked up, and one that crosses an automount point
  nothing is mounted on yet. systemd mounts a `noauto` line once a bind line's source, a swap file
  or an image file below its folder needs it, so a bind from a `noauto` disk needs that disk mounted
  for `check` and activation. So a swap or image line whose path is a link to the hidden volume's
  device node fails as well, where it passed before. A path with no link in it, below mounts that
  are there, is judged as it is written, and a bind line whose source as written lies in the volume
  fails whatever lies there. For the second-mount rule, a bind line whose path cannot be told makes
  no mount of the decoy's own.
- `backend-entries` reads only plain fstab lines, which NAILS reads as `libmount` and systemd do,
  and fails every other line, with `--allow-decoy-storage` or without it, as one that may mount the
  volume: a line that holds a control character other than a tab, or white space other than a space
  or a tab, a backslash in its first field or mount point that begins none of the escapes `\040`,
  `\011`, `\012` and `\134`, a backslash in its type or options, a list of types, or a first field
  that is neither an absolute path nor a `UUID=`, `LABEL=`, `PARTUUID=`, `PARTLABEL=` or `ID=` tag,
  unless it is the line of a RAM, kernel, host-share, network, overlay, ZFS or FUSE filesystem and
  no bind line. The check names what it could not read and says to write the line plainly. NAILS's
  parser left the type and options undecoded and read a relative first field only for some types, so
  `bin\144`, which `libmount` reads as `bind`, and `dev/mapper/data` with the type `ntfs-3g` or
  `ext4,xfs`, which `mount` looks up from `/`, passed the check. Such a line claims what NAILS reads
  in it, and for the second-mount rule it makes no mount of the decoy's own.
- `backend-entries` and the attach gate no longer let a device or swap line for the hidden volume's
  device go when it carries `_netdev`, which only has systemd mount it after the network: such a
  line fails `backend-entries` as it does without the option, and the gate counts what it mounts as
  the decoy's own storage. Only the line of a RAM, kernel, host-share, network or overlay filesystem
  that is no bind line names no storage of this computer's.
- `backend-entries` no longer says to remove the decoy's crypttab line for the volume that one of
  its own filesystems lies on when the hidden root is on that filesystem too: a bind of a folder of
  `/` on an encrypted decoy, say, or a subvolume of its encrypted btrfs. Such a line opens the hidden
  root's own storage, so the check took it for a line only the hidden volume needs, while the
  decoy's boot needs it to mount that filesystem at `/`, at a system folder or by an fstab line it
  needs. The check now says to keep it and to put the hidden root on storage of its own instead, as
  it does for the fstab line. With `--allow-decoy-storage` the check lets such a line be for a root
  that is a folder or a subvolume of that filesystem, as it lets the fstab lines for `/` and the
  system folders be, when the boot opens it (no `noauto`) and the decoy mounts another part of the
  filesystem at `/`, by its mount there, or by such an fstab line. So on an encrypted decoy, such
  as Debian's or Ubuntu's LUKS root, with LVM or without, or Fedora's btrfs on LUKS, a bind of a
  folder of `/` or a subvolume beside `/home` passes the check with the flag, as on an unencrypted
  one. A `noauto` crypttab line, one with `tcrypt-hidden`, one for any other device, every line for
  a root that is the whole filesystem and one for a filesystem the decoy mounts only at another
  folder, or by a line whose mount is not there, still fail it. The check says to keep a line with
  `tcrypt-hidden` too where one of the decoy's own filesystems lies on what it opens.
- `backend-entries` now refuses an fstab or crypttab line that names another device of the hidden
  root's btrfs filesystem than the one its mounts show, by its path or by a link such as `UUID=`
  that leads to it, as it refuses one for the device the mounts show: the volume lies on each of its
  devices. It let such a line pass.
- The attach gate no longer says `per /etc/fstab` of a root whose filesystem is mounted at `/` or at
  one of the system folders it counts as the decoy's (`/srv`, `/home`, `/opt` and the like) when no
  fstab line mounts it there, a separate drive mounted at `/srv` by hand, say. It says the computer
  has mounted it there, and for a system folder it says, in place of the advice to remove a line
  that does not exist, to run `sudo umount` for that folder if the volume was mounted there by
  hand. It never says to remove the line for `/`, and no longer says to remove a line of the fstab
  that mounts the filesystem at a system folder either, unless the hidden root is that folder or
  lies above it: such a line is the decoy's own.
- `verify --offline` refuses a `--root` that does not exist, is not a folder or holds no `etc`
  folder before anything is scanned: the error `nothing_to_scan`, exit 1, and its message says how
  to mount the decoy first. Every offline check looks for a path of the decoy system below the
  root, so such a root found nothing and was reported as a secure image with exit 0, and
  `--examiner` reported no setup trace either. An empty folder is what the mount point looks like
  when the image was never mounted on it, and a plain mount of a Fedora, Ubuntu or archinstall
  root on btrfs mounts the whole filesystem, whose top level holds the system in a subvolume: the
  refusal names the subvolumes it finds there. The root is looked up with `lstat` and `stat`, and
  only one without `etc` is listed, with `O_NOATIME`, as the rest of the scan reads the image. So
  the check writes nothing and, run as root, changes no access time of the folder the root names
  or of what it holds. A link on the way to that folder is followed, as by any lookup, and the
  link's own access time changes. A folder that holds `etc` is scanned as it is, whether a
  filesystem is mounted there or not, since a copy of the decoy's files and the folder of a
  subvolume are no mount points either.
- `verify --offline` lists as not checked each mount point of the decoy's `/etc/fstab` that is
  missing or empty under the root, and each home of a login account of its `/etc/passwd` that is,
  and so does the examiner's view. A btrfs decoy scanned by its system subvolume alone read as
  complete: its `@home`, and on archinstall its `@log`, lie beside that subvolume, so a history
  that names the tool or a sudo log there was not read, and nothing said so. The line of a mount
  point says how to mount it without writing to the decoy's disk, with the command: again and
  read-only when its device is mounted on the machine already, read-only and without a journal
  replay when it is not. A file the decoy mounts, such as a disk image in a home, is attached to a
  read-only loop device first, and a `/dev/mapper` device that is not open is opened read-only
  first, as systemd-cryptsetup opens the line of the decoy's `/etc/crypttab` that names it: from
  its source, as its kind of volume, a plain one with its cipher, key size, hash, offset, skip and
  sector size (systemd's defaults where the line gives none), and with its detached header,
  VeraCrypt PIM and TrueCrypt key files. A key file, where the key lies in it and a token, which
  no option there carries over, are named as needing parameters of their own. Only mounts from a
  disk count, not `/` itself, swap, filesystems in RAM, host shares, network filesystems or binds,
  whose source lies in the image and was scanned. The
  decoy's files are read inside the root with `openat2` and `RESOLVE_IN_ROOT`, so NixOS's
  `/etc/fstab`, a link into the store, is read from the image's store, and one that cannot be read
  there is listed as not read. The examiner's view says when the decoy's `/nix/store` is missing
  or empty under the root, where its tool check had nothing to read.
- An offline scan and its examiner's view look up the decoy's files and folders inside the root,
  as the decoy sees them, with `openat2` and `RESOLVE_IN_ROOT`. They followed a link in the image
  on the machine running verify: a `/home` that is an absolute link out of the image made `--deep`
  read that machine's own `/home/alice/.bash_history` and report it as a trace on the decoy, and
  made `--examiner` report from it that encrypted volumes were opened from that account. In a
  hidden session a decoy link such as `/home` to `/data/home` led to the session's own folders. On
  NixOS the examiner's view never read `/etc/fstab` or `/etc/crypttab`, links into the store it
  refused to follow, and said nothing: they are now read from the image's store, and a file that
  is there but does not resolve inside the root is listed as not checked, with where it leads,
  except for a link to `/dev/null`, which holds nothing. A path that does not resolve inside the
  root at all, through a loop of links or where the kernel refuses the lookup, is read nowhere and
  listed as not checked: looked up on the machine running verify, it would follow the image's
  links out of it. The probe for the known NAILS paths, mostly under `/run` and `/etc/nixos`,
  still follows a link on the way on the machine running verify.
- The operator guide, the `--root` help and the message of a refused root mount the decoy so that
  nothing writes to its disk. They said `mount -o ro`, but on a filesystem that was not cleanly
  unmounted ext4 replays its journal and cleans up orphaned files on a read-only mount, btrfs
  replays its tree log, and XFS and f2fs recover their logs, all onto the disk. A device that
  `findmnt` shows mounted already, as the decoy root is in a hidden session, has that behind it:
  it is mounted again and that mount made read-only, since a read-only mount of it would make its
  filesystem read-only, which ext4, XFS and f2fs refuse as busy. Any other device, in a session
  or not, a `noauto` entry the session left alone among them, is first made read-only with
  `blockdev --setro` and then mounted with `ro,noload` (ext4), `ro,rescue=nologreplay` (btrfs) or
  `ro,norecovery` (XFS, f2fs), and an image goes through a read-only loop device. A filesystem
  that was not cleanly unmounted then shows what it held before its journal, so what the decoy
  wrote last may be missing from the scan. On btrfs the guide mounts the subvolume of the system
  with `subvol=`, then each subvolume the decoy's fstab mounts on its folder below it, such as
  `@home` on `home`.
- Activation and `emergency` kill the interactive shells the newest first. A login shell that
  leads a console's session, as util-linux's `login` (Fedora's and Arch's) starts it, hangs up the
  console as it dies, and a desktop started from it in the foreground (`sway` or `startx` typed at
  the console's prompt) ends with it: its terminal windows close, and each shell in them gets
  SIGHUP, on which bash writes its history. A root shell that `sudo -i` opened at the prompt gets
  the SIGHUP from `sudo`, and a shell started at another shell's prompt (`bash`, `su`,
  `nix-shell`) as that prompt's foreground job. Both killed the other shells in the order of their
  process IDs and the ones they were started from last, so such a shell, the one the command was
  typed into among them, could write its history to the decoy disk before its own SIGKILL came,
  the activation or emergency command included. Every interactive shell is now found first and
  then killed before each one older than it, back to back: what the kernel sends as a shell dies
  reaches only shells started after it, and those have their SIGKILL by then. A terminal
  multiplexer that ends a session when its last client goes (tmux's `destroy-unattached` or
  `exit-unattached`, screen's `autodetach off`, zellij's `on_force_close "quit"`) can still hang
  up an older shell in it itself, and there the order only narrows the race: keep those options
  off on the decoy. The emergency kills the shells of the hidden session the same way, though a
  history written there lands on the hidden volume, and still spares only its own command chain.
  An emergency that leaves the decoy running kills no shell, as before.
- Activation and `emergency` count a shell as interactive when it reads its commands from a
  terminal: its standard input is a terminal and its command line runs no command string and names
  no script, or it forces interactive mode with `-i`. They followed bash's rule, which wants
  standard error on a terminal too, so a zsh or fish started with its errors sent elsewhere (`zsh
  2>/dev/null`), interactive by its own rule, lived on: when the shell it was started from died,
  its terminal hung up, and zsh wrote its history on the SIGHUP. fish's command line is now read as
  fish reads it, so a fish started with an init command (`fish -C ...` or `--init-command`) counts
  too, where its value was taken for a script. A shell that reads a terminal without being
  interactive by its own rule, as `bash 2>/dev/null` does, is killed as well: it keeps no history,
  and the switch would end it anyway.
- Activation and `emergency` kill mksh, rbash and nu too, and the other common shells the list of
  shell names missed: ash, ksh93, rksh, lksh, oksh, loksh, pdksh, yash, csh, elvish and xonsh. Such
  a shell lived on through the kill, and one that saves its history when it ends, as rbash (bash
  under another name) does, could write the activation command to the decoy disk when the switch
  ended it. Each one's command line is read with its own syntax, so `nu -e`, `elvish -norc` and the
  interpreter in front of xonsh's own options are taken for neither a command nor a script, and a
  shell that a NixOS wrapper starts (`.xonsh-wrapped`) counts under its own name. A shell of any
  other name is still not killed: the operator guide and `docs/bash-history-forensics.md` list the
  names.
- The `incremental-history-flush` check reads the settings of the shell the command was typed into,
  and names the shell and the setting. It finds that shell by the process tree: the one `sudo` and
  its monitor run under, or, when `sudo` gets no terminal of its own or `su -c` or a typed script
  runs the command, the nearest interactive shell on the command's terminal, if the command runs in
  that terminal's foreground. That one is only likely the shell it was typed into, so it is read as
  any shell the operator may use, beside every other shell the check knows. When it finds none, as
  for a window or `run0`, it reads every shell it knows: the operator's login shell, bash and zsh,
  and fish when the home has its configuration. A root shell is read with the operator's home too,
  which `sudo -s` can leave it. It read six startup files in the operator's home, whatever shell was
  in use and none in `/etc`, so it missed the `SHARE_HISTORY` that NixOS's `programs.zsh` sets for
  every zsh in `/etc/zshrc` by default, and the one Oh My Zsh sets, and it knew neither fish, which
  writes each command line to its history file as it starts the command unless it runs in private
  mode, nor `history -w`. It now reads that shell's startup files in `/etc` and in the home of the
  account the shell runs as (root's for a shell that `sudo -i` opened): the files the shell reads
  when it starts, and no history file. As root these reads change no file's access time, though a
  link on the way to one, such as NixOS's `/etc/zshrc`, can still have its own access time changed.
  zsh's files are read as zsh reads them and fail closed: in zsh's order, once for each home the
  shell can run with, `zprofile` and `zlogin` only for a login shell, only `/etc/zshenv` for a zsh
  started with `-f`, `--no-rcs` or `-o norcs`, and no other file in `/etc` for one started with
  `-d`, unless what it reads names `RCS` or `GLOBAL_RCS` (`setopt rcs`, `set +f`, an `emulate`),
  which may turn them on again, a sourced file read where it is sourced when its path resolves (so
  Home Manager's `dotDir`, whose sourced `.zshenv` sets `ZDOTDIR`, is followed), an `eval` of words
  the check can read as code, the file of each function they autoload, by its path or by its name in
  each directory they add to `fpath` (one that no directory they put in front of `fpath` holds is a
  doubt, as zsh then finds it in a directory it was built with or in one that an `FPATH` from its
  environment names, so nearly every `.zshrc`, which autoloads `compinit`, makes the check warn that
  it cannot tell), a here-document's body as text, and `INC_APPEND_HISTORY_TIME` named as writing a
  line once its command ends. An `fc` that writes the history file (`fc -A`, `fc -W`, `fc -P`, with
  other flags too, as in `fc -AI`) counts as such a write wherever it stands, as a hook (`precmd`,
  `preexec`, `zshaddhistory`, `TRAPDEBUG`) runs it after each command the way bash's `history -a`
  runs from `PROMPT_COMMAND`, and one with an expansion among its words is a doubt. An option counts
  as on wherever a file zsh reads names it, outside a line that is a comment, an `unsetopt` as much
  as a `setopt`: zsh can still end with the option on after a turn-off, through a redefined
  `unsetopt`, a trap or a hook that sets it again, a plugin loaded after the first prompt or an
  error that stops the file before the line, and no reading of the files can show that a turn-off
  holds. So zsh passes only when no file it reads names the three options and nothing is left the
  check cannot tell, which is zsh's default. An operator who turns the options off in `.zshrc` now
  gets a warning, whose fix the check can see: typing the decoy commands in a zsh started as
  `zsh -f`, which reads no startup file but `/etc/zshenv`, and for a zsh started so, taking what the
  check names out of `/etc/zshenv`. That is the fix on NixOS too, whose generated `/etc/zshrc` sets
  `SHARE_HISTORY` by default and, with it taken out of `programs.zsh.setOptions`, still runs an
  `eval` of what `dircolors` prints and autoloads `compinit` from directories added to `fpath` that
  the check cannot resolve, and with Home Manager, which names the options whether it turns them on
  or off. The options the command line of the shell turns on count too: one of the three
  (`zsh -o sharehistory`, `zsh --share-history`, `zsh -fo share_history`) is on, and a zsh that runs
  as sh or ksh, by the name it was started under or `--emulate sh`, which reads their startup files,
  is a doubt. A redirection to the history file, `$HISTFILE` or a path whose last part holds `hist`
  (`preexec() { print -r -- "$1" >> ~/.zsh_history }`), counts as a write wherever it stands, and so
  does a word in a hook that names that file (`tee -a ~/.zsh_history`), a hook being a function by
  its name, a `TRAP...` function, or one that `add-zsh-hook`, a `*_functions` array or `zle -N`
  makes one. A redirection in a hook whose target an expansion makes is a doubt. An `emulate -R ksh`
  turns `SHARE_HISTORY` on, as its reset to ksh's defaults does, and an `emulate` whose mode an
  expansion makes is a doubt. A zsh started with `-f` whose `/etc/zshenv` runs an `exec`, which may
  start another zsh, or a `set`, `setopt` or `unsetopt` with an expansion among its words
  (`set +$x`) is read on as any zsh. An alias's value, a trap's code, a `sched`'s command and a
  `zstyle -e`'s strings are read as an `eval`'s words are, and a doubt where an expansion is in
  them, and so are an alias that hands the words it is used with to a command that reads them as
  options, code, names or paths (`alias so=setopt`), a prompt that holds code (`$(...)`, `${...}`)
  where a file or the command line may turn `PROMPT_SUBST` on, an expansion that reads a parameter's
  value again (`${(e)x}`, `${(%%)x}`, `${~x}`), and a file that names `GLOB_SUBST`. An option counts
  as on in a word as brace expansion may make it too (`setopt {share,inc_append}_history`, a `{y}`
  group as `BRACE_CCL` reads it), and after an `o` among flags (`set -oshare_history`). The check
  warns that it cannot tell at a `setopt` with an expansion it cannot list, an option whose name an
  expansion makes (`options[$o]=on`, `emulate zsh -o $o`, `read -A options`, a `typeset` or
  `print -v` of a parameter whose name an expansion makes), a glob qualifier that runs code as zsh
  expands a word (`*(e:'...':)`, `*(+func)`), a sourced file or a `ZDOTDIR` it cannot follow (a
  process substitution, `: ${ZDOTDIR:=...}`), a path zsh expands into others (a glob, `{a,b}`), a
  function the files autoload that may be in an `fpath` directory it cannot follow (NixOS's
  profiles, `$p/share/zsh/site-functions`), compiled code that zsh may run in place of a file (a
  `.zwc` beside it or for an `fpath` directory), a `source` without a file, a quote, an expansion or
  a here-document that runs to the end of the file, an expansion that holds what it cannot read as
  zsh does (a `case` in a `$(...)`, a `${ command }`), a command whose name an expansion makes
  (`$cmd`), a startup file that is there but cannot be read, which it passed over before, and a
  shell other than bash, zsh, fish and dash. The lexer reads zsh's code as zsh does where that
  matters for what it can hide: a `<<` in `(( ... ))` is a shift and a quote there a character, a
  `)` or `}` in quotes closes nothing, a `\'` does not end a `$'...'`, `$$` is a parameter, glob
  flags such as `(#i)` start a word, a command in an arm of a `case` starts after the pattern's `)`,
  the number of a descriptor before a redirection is no command, and zsh's short forms
  (`repeat 3 cmd`, `for x (a) cmd`, `if [[ ... ]] cmd`) take their body. zsh's files are counted
  line by line too, without reading the code and wherever the words stand, for the three options,
  `source`, a `.` with a word after it, `eval`, an alias that stands for `.`, `autoload` and the
  `ZDOTDIR` and `fpath` settings, a line that is a comment left out: what a line names beyond what
  was read as code the check follows counts as on, for an option, adds a directory the check cannot
  follow, for `fpath`, or makes the check warn that it cannot tell, so a `source` or `eval` in an
  `echo`, a string, an alias or a here-document, or an `eval` of what a command prints, warns too.
  bash's files are read for `history -a` or `history -w` beside `PROMPT_COMMAND`, a line ending in a
  backslash going on in the next. It still only warns: such a shell has written the decoy commands
  before activation starts, so a refusal would take none of them back, and for a shell that writes a
  line once its command ends, a refused activation would add its own.
- Activation and `deactivate` soft-reboot through logind, as `systemctl soft-reboot` does, so
  the programs that wait for logind's shutdown signal end on it before the switch, as at an
  ordinary shutdown. They enqueued `soft-reboot.target` with PID 1 directly, and the decoy's
  unattended-upgrades shutdown helper was stopped without that signal: on Debian 13 it wrote
  "SIGTERM or SIGHUP received" to `/var/log/unattended-upgrades/unattended-upgrades-shutdown.log`
  on the decoy disk at every activation, a line an ordinary shutdown does not write, and on
  Ubuntu 24.04 and 26.04 it failed (`exit-code`) when the bus stopped under it. Both wait until
  PID 1 holds the soft-reboot's job, so meanwhile `status` shows the activation in progress and
  `recover` leaves it alone, and activation keeps killing every interactive shell opened on the
  decoy until then. A program that holds a shutdown block inhibitor, or a logind that does not
  answer whether one does, makes them refuse before anything of the switch happens, and a
  soft-reboot that logind refuses or drops (`shutdown -c`) fails the command with nothing left
  queued. One that logind still holds past its delay is dropped and fails the command, or, on
  systemd 256 and older, where logind cannot drop it, is enqueued with PID 1 directly. `recover`
  refuses while an interrupted activation's soft-reboot may still come, and `emergency` on the
  decoy drops it, or powers off at once where it may still come. `emergency` in the hidden session
  still enqueues its soft-reboot directly, without waiting for anything.
- `emergency` spares only the emergency command itself until the switch: the `nails` process and,
  when `nails emergency` was typed into a terminal's shell, the rest of its job, or when `sudo nails
  emergency` was typed there with `use_pty`, that `sudo`, its monitor and the rest of their job.
  It used to spare every ancestor up to PID 1, every
  process group one of them led except a shell's, and every process in its own session and
  process group. A desktop shell that starts menu entries as its own children in its session and
  process group, as GNOME Shell and niri do, could then survive the kill with the display server
  and every app it started, when the emergency ran from a program it had started: they stayed on
  screen and in RAM until the shutdown stopped them, an app that hung until its stop timeout. The
  command is now read before the shells are killed. Its ancestors count only when `nails` has a
  terminal and leads its own process group, and the walk up reaches the shell it was typed into
  through processes that run in its cgroup, have a terminal and lead their own process groups. A
  wrapper that keeps `nails` in its own process group is killed with the rest: `timeout -k` passes
  the shell kill's SIGHUP on and kills the emergency when its grace runs out. The shell kill hangs
  up the terminal's foreground job, so a reader the report was piped to, such as `less` or `tee`,
  ends then, unless it ignores SIGHUP or its job runs in the background. Two ancestors are still
  kept with the command: a terminal emulator started from a shell to run it, as in
  `xterm -e sudo nails emergency &`, which dies with the display server moments later, and a
  window manager started from a login shell that starts the command in a process group but not a
  session of its own.
- A console log line that stderr no longer takes is dropped. The log's own report of the failed
  write went to the same stderr and panicked there, so an emergency run with `--verbose` whose
  kill took the terminal or the pipe reader its stderr led to exited 1 at its first log line,
  without recording the session as ended. A notice about the log file itself is dropped there too.
- `nails rehearse plant --user <name>` plants the canary for that account or for none. Run under
  pkexec, the account pkexec named stood in for the one given, so the canary went into another
  home and the scan that followed proved nothing about the home asked for. A name no account has is
  now refused before anything is looked at (exit 2, `no_such_user`) instead of falling back to the
  operator.
- The session decides the decoy's mount, swap and automount units outside the fstab as it decides
  fstab lines. A disk the decoy mounts through a unit of its own (NixOS's `systemd.mounts`, a
  `.mount` unit enabled for `local-fs.target` or `multi-user.target`, a mount the kernel command
  line names with `systemd.mount-extra=`) was mounted read-write by the hidden systemd, a swap unit
  of its own swapped onto its disk, and the ESP the GPT auto-generator mounts at `/efi` (Arch Linux)
  was missing from the hidden session. Activation now reads every `.mount`, `.swap` and `.automount`
  unit linked in a target's `.wants`, `.requires` or `.upholds` directory (also those for every
  target and for a prefix of its name) of the hidden root and of `/run`, with its drop-ins (those
  for a prefix of its name and for its type included), except those the fstab generator made from a
  line whose decision keeps them off or puts their mount point in place (a copy of such a unit in
  `/etc/systemd/system`, as `systemctl edit --full` makes, is decided as a unit of its own, and so
  is the unit of a line the policy leaves as it is): a filesystem the decoy has mounted now is bound
  read-only or overlaid, one not mounted now is skipped or masked, and the automount of a filesystem
  put in place is kept off. RAM and kernel filesystems are left to the hidden systemd, and so is a
  zram swap whose zram device has no backing device. One with a backing device is kept off like disk
  swap. A unit whose files cannot be read, or that names its source by a specifier, is masked, and a
  directory of unit links that cannot be listed refuses the activation. A mount unit that only
  another unit pulls in is not decided. `nails check` lists the decisions with the fstab's. A mask
  now also goes into `/run/systemd/system.control`: in `/run/systemd/system` alone it lost to a unit
  in `/etc/systemd/system`, where NixOS installs every unit, so the hidden systemd started such a
  unit masked there all the same.
- A hidden session reaches `local-fs.target`, `remote-fs.target` and `swap.target` when the session
  keeps a decoy filesystem or swap off that the target requires. The session masked such a unit (an
  fstab entry without `nofail` that is not mounted now, a network filesystem, a swap line, the
  automount of a filesystem it binds or overlays), and systemd silently drops the start of a target
  that requires a masked unit, and with it every unit only that target pulls in: on Debian 13, a
  session entered with the ESP unmounted ran without `local-fs.target`. Such a unit is now skipped
  instead: a runtime drop-in gives it a start condition that never holds, so the hidden systemd
  starts it, finds the condition unmet and reaches the target, and the decoy disk stays unmounted.
  The fsck, makefs and mkswap units its fstab line or unit files pull in would start on the decoy
  disk before that condition is tested, so they are skipped with it, and so are its growfs, pcrfs,
  validatefs and quota units, for caution; every other unit it pulls in still starts, and a unit
  whose pulls NAILS cannot tell is masked instead, and so is one whose skip a drop-in of the decoy's
  would undo (one of the skip's name that systemd reads in its place, or one that sorts after it and
  resets the start conditions with an empty `Condition…=`), and so is one whose skip would pull in a
  mount the session neither keeps off nor puts in place, which the hidden systemd would mount from
  the decoy's disk first. NAILS follows what the skipped unit pulls in, and what that pulls in in
  turn, as PID 1 starts it: dependencies and their links, the mounts for a parent directory (also a
  `noauto` line's), for a bind or loop mount's source, for the paths a unit names in
  `RequiresMountsFor=` or `WantsMountsFor=`, for the directories it runs in (also one that may be
  missing, its user's home aside), its private `/tmp` and the directories it keeps its state in, and
  for the paths it listens on or watches, devices and the network a network mount waits for, slices,
  sockets, the unit a socket, path unit, timer or automount starts, the names a unit shares through
  alias links, and what an fstab line names with `x-systemd.requires=`, `x-systemd.wants=`,
  `x-systemd.requires-mounts-for=` or `x-systemd.wants-mounts-for=`, up to the targets the boot
  starts anyway. Where it cannot follow a unit on the way (a file or link it cannot read, a unit
  that does not load, a specifier it does not resolve, a chain more than 8 units deep or past 256
  units), the skip is masked as well. A skipped unit that requires a masked one, such as an
  unmounted `nofail` parent, does not start, which `nails check` and `nails activate` warn of. A
  skipped mount still waits for its device, so an entry whose device is not there at activation (its
  node, with its device unit active) is masked as before, and `nails check` and `nails activate`
  warn that the hidden session will not reach its target (attach the device, or give the entry
  `nofail`, or install a unit file of its own with `WantedBy=` rather than `RequiredBy=`, or give
  the line a generator made a unit from `nofail`, or reload systemd if that line is gone); a device
  gone by the switch has its units masked then. Entries with `nofail` stay masked. `verify` reports
  a skip drop-in left on the decoy. `nails status` lists each such unit, skipped or masked, with why
  (`required_units` in `status --json`): its device was not there, NAILS could not tell what it is
  or pulls in, or the fstab lines or unit files for it disagree, which `nails check` and
  `nails activate` now warn of too.
- An `/etc/fstab` entry that gives both `noauto` and `auto` is read as systemd's fstab generator
  reads it, by the last of the two. An entry such as `noauto,auto` is mounted at boot; the session
  left it to the hidden systemd as never mounted, and the hidden systemd mounted it read-write, and
  the attach gate did not count its device among the storage the decoy uses. The same held for a
  `noauto` entry that names a unit to pull it in with `x-systemd.wanted-by=` or
  `x-systemd.required-by=`, which the generator links there whatever `noauto` says. The older
  automount spelling `comment=systemd.automount` counts as an automount, as it does for systemd.
- Units that fail in the hidden root and have no job there are masked there, as the boot-loader
  units already were.
  On Debian 13, `systemd-remount-fs.service` failed in every hidden session, because the root
  overlay refuses the decoy root's fstab options, and so did `systemd-growfs-root.service`, which
  cannot grow it. On Ubuntu 26.04, GRUB's boot-record unit is `grub2-common.service`, which failed
  in every hidden session entered with `/boot` mounted (`grub-editenv` cannot write the read-only
  `grubenv`); it is now masked like `grub-common.service` on Debian and Ubuntu 24.04. The masks
  hold in the hidden session only, and the decoy runs the units as before.
- The way back removes the session's runtime masks by name, as it removes its drop-ins. When the
  snapshot of `/run` the entry takes was gone by the way back, the scrub kept them, and the decoy
  started again with its swap, its unmounted disks and its boot-loader units masked until its next
  boot.
- `nails rehearse scan` reports more storage it cannot vouch for as "not checked" (exit 9) where it
  used to report a clean pass (exit 0). An offline image or an unmounted `--device` that is an
  encrypted container (LUKS or BitLocker) is reported "not checked" with the advice to scan its
  unlocked mapping instead, where its ciphertext used to count as a clean scan; so are an LVM physical
  volume and storage on which the scan identifies no filesystem. A whole-disk image is classified
  partition by partition and names each partition it could not check, a btrfs, f2fs or bcachefs
  superblock is found even beside a stale signature of another format (an ISO9660 descriptor
  mkfs.f2fs left in place), and a zfs dataset of the live decoy is listed as not checked instead of
  being skipped. An image cut short, as a copy that stopped early leaves it, is not checked either: an
  ext4, xfs or f2fs image that ends before its filesystem does, and a whole-disk image that ends
  before a partition its table lists or before the disk its GPT was written for. An empty image or
  device (a copy that failed, a loop device with no file behind it) is reported as not scanned with
  exit 9 instead of a clean pass with exit 0, and a scan that left a device unread no longer prints
  the green "not found" headline.
- `nails rehearse scan` reports a bare vfat, exFAT or swap image cut short as "not checked" (exit 9)
  where it reported a clean pass (exit 0). It reads the size the boot sector or swap header
  records, as it does for ext4, xfs and f2fs, so an image that ends before its filesystem or swap
  area does is known to be incomplete. A boot sector or swap header that records what no such
  filesystem has (a sector size the kernel does not take, no sector at all, a swap header of
  another version) counts as storage the scan does not identify. An ext4 or f2fs image cut inside
  its superblock, before its feature flags, is reported as cut short too.
- `nails rehearse scan` reports file-level encryption and NTFS as "not checked" (exit 9) where it
  reported a clean pass (exit 0): a raw plaintext scan cannot read what a filesystem stores
  encrypted or compressed file by file. That covers NTFS, which can compress the files of a folder
  marked compressed, whether an `ntfs` or `ntfs3` mount, any `fuseblk` mount (the type ntfs-3g
  mounts NTFS as) or an NTFS image; an ext4 or f2fs with the encrypt feature (fscrypt), which the
  scan reads from the superblock of a mounted device too; and a device that holds the folder of an
  eCryptfs mount (an encrypted home or Private folder): the filesystem the folder lies on, or each
  one it may lie on where the mount table does not show which, and for a `--device` also a whole
  disk with that filesystem in a partition or a device below or above it (a loop device or a mapping
  built on the partition), which the scan reads from sysfs. A `--device` the scan cannot place
  against such a folder is not checked either. The scan sees an eCryptfs folder only while it is
  mounted, and never in an `--offline` scan, which reads no mount table.
- The whole-root session overlay pins its feature options (`index=off`, `metacopy=off`,
  `redirect_dir=nofollow`) on every host, matching the pre-flight capability probe. On a kernel
  that turns these on by default (such as Arch's), the hidden overlay could keep an index, copy up
  only a file's metadata, or follow a redirect, so data could stay in the lower layer after a
  rollback and the overlay no longer behaved as NAILS's forensic guarantees assume.
- The `decoy-persistence` check judges journald's journal by the running systemd's built-in default
  when no configuration sets `Storage=`: below systemd 259 the default is still `auto`, but from 259
  (Ubuntu 26.04) it is `persistent`, so a decoy that keeps no explicit setting now counts as
  persistent and is refused, where it was read as volatile before. When no configuration file sets
  `Storage=`, the `journal.storage` credential counts as journald reads it: from systemd 256 only,
  as journald received it in `/run/credentials/systemd-journald.service/`, and only when its bytes
  are exactly the value, so `volatile` followed by a newline, as `echo` writes it, does not count.
  Only root can read that copy, so for an unprivileged `check` or `status` the built-in default
  decides, and a journal that only the credential makes volatile can count as persistent; run them
  with `sudo`. A systemd whose version cannot be read is treated as persistent.
- An empty `Storage=` in the journald configuration keeps the value set before it, as journald keeps
  it, where NAILS reset it to the default.
- The journald, logind and systemd-coredump configuration is read line by line for UTF-8, as systemd
  reads it, where a file holding a byte that is not valid UTF-8 was skipped whole and the files
  after it were still read. A comment that is not valid UTF-8 (a Latin-1 comment, say) is skipped,
  so a `Storage=persistent` beside it is still seen instead of the decoy reading as amnesic. Any
  other line that is not valid UTF-8 stops the reading there, as a malformed section header does:
  the assignments before it count and the files after it are not read, so a `Storage=volatile` in a
  later drop-in, which journald never reads, no longer lets a persistent journal pass. Like systemd,
  NAILS counts the Unicode noncharacters (U+FFFF and the like) as not valid UTF-8.
- A journald, logind or systemd-coredump configuration with a main file or drop-in that is not a
  regular file is no longer read as if that entry were not there. systemd lists a drop-in by its
  name alone, so a directory with a drop-in's name shadows the drop-in of that name below it, and
  NAILS read the one below instead. The releases then read such an entry differently: up to 259 a
  directory stops the reading where it comes and a link to `/dev/null` reads as empty, while 260
  and later read none of the configuration, the main file included, when a drop-in or the main
  file is a directory, a device (`/dev/null` too), a FIFO or a socket. NAILS counts such a
  configuration as unread whatever release runs, as the daemons read their files when they start
  and an update can bring another release before they next do, at the latest when the decoy starts
  again after the way back. So does a configuration with a file or drop-in directory NAILS cannot
  read where systemd, running as root, can (an unprivileged `check` used to skip such a file):
  `decoy-persistence` refuses an unread journald configuration and warns about an unread coredump
  one, `sleep-policy` warns that the lid or an idle session may suspend the host and that a closed
  lid may leave the session unlocked, and the sleep guard's `block` mode takes the lid switch. Mask
  a vendor drop-in with an empty file, which every release reads alike. A link to a path that does
  not exist still shadows the file below it and adds nothing, as in every release.
- On systemd 255 and older, NAILS reads the main journald, logind and systemd-coredump
  configuration file from `/etc` alone, as those releases do. It took the first of `/etc`, `/run`,
  `/usr/local/lib` and `/usr/lib` that has one, as 256 and later look for it, so on Ubuntu 24.04,
  which runs 255, a `/run/systemd/journald.conf` that sets `Storage=volatile`, with
  `/etc/systemd/journald.conf` gone, let a decoy pass whose journald keeps its `auto` default and
  persists to an on-disk `/var/log/journal`. When NAILS cannot read the running release, a main
  file outside `/etc` that changes what is read leaves the configuration unread.
- `check` no longer hangs when `/usr/lib/systemd/journald.conf`, whose commented `#Storage=` NAILS
  takes for the vendor's default, is a FIFO, and no longer reads without end when it is a device
  such as `/dev/zero`. A vendor file that is no regular file, or one over 1 MiB, gives no such hint,
  so the default stays the fail-closed one.
- A btrfs decoy root is accepted only when the mounted root is a real subvolume (its mount root
  equals its `subvol=`). A bind mount of a plain folder on a btrfs filesystem is now refused before
  activation, naming the folder, instead of passing the pre-flight check and then failing the
  way-back mount. A subvolume whose path holds a space, a tab or a backslash, which the mount table
  writes escaped, is a subvolume all the same; one whose path holds a comma is refused, because the
  way back could not name it to mount it again.
- A decoy mount point that is a symlink (for example `/home` linking to `var/home`, as on
  ostree-based systems) is resolved to its real path inside the decoy root. NAILS now decides, mounts
  and masks the filesystem where the decoy really keeps it (`var-home.mount`, not `home.mount`), and
  fresh-home mode creates the home at that real path instead of a directory where the decoy has a
  symlink. A link whose target does not exist yet is followed too, as systemd follows it. The
  automount of such an entry is masked under its real path too (`var-home.automount`), so the
  hidden session no longer starts in emergency mode when the filesystem behind it is overlaid, and
  `nails check` reports the decision at the real path. An entry that the hidden session's own files
  resolve to another path than the decoy's (a symlink on the way that a session replaced) is also
  decided at that path, so the hidden systemd cannot mount the decoy's filesystem there. A path that
  such a link leads into the hidden volume is masked, where the hidden volume's own entries are left
  to its bind.
- Decoy-persistence pre-flight now catches a syslog or audit daemon (rsyslog, syslog-ng, the
  `syslogd` of sysklogd, inetutils or busybox, metalog, socklog, auditd) whether it runs as a service
  unit, a systemd template instance (such as `syslog-ng@default`), the unit `syslog.service` names on
  Debian and Ubuntu, or a bare process, so a logging daemon on the decoy can no longer slip past
  activation. It also reads the systemd 262 kernel coredump socket pattern correctly instead of
  mis-reporting it as a raw core-dump path, catches Ubuntu's default-enabled kdump (refused, see
  Security), and no longer warns about `sudo` logfile or
  I/O-logging settings on systems where sudo-rs (Ubuntu's default sudo since 25.10) ignores them.
- The `memory-wipe` check reads the decoy kernel's configuration (`CONFIG_INIT_ON_FREE_DEFAULT_ON`)
  when the kernel command line is silent, from the running kernel's own `/proc/config.gz` (NixOS and
  Arch) or the copy in `/boot` or `/usr/lib/modules`, warns when the decoy kernel does not zero freed
  memory, and notes a RAM-wipe-on-shutdown mechanism (the dracut `ram-wipe` module) when one is
  installed. It counts `init_on_free` as off when `page_poison=1` takes precedence over it, and reads
  `init_on_free=enable` and `=disable` as the kernel does from Linux 6.16. The operator guide of the
  0.3.0 pre-releases advised `init_on_free=1 page_poison=1`; if you followed it, remove
  `page_poison=1`: on a kernel built with page poisoning, the NixOS kernel among them, it turns
  `init_on_free` off, and freed slab objects keep their contents.
- `nails activate` refuses a host NAILS does not support before it writes anything to the hidden
  volume, so a refused host is left byte-identical, with no state lock and no log line, and the
  command exits with the unsupported-platform status (8). The refusal previously came after the state
  lock and the log file had already been written.
- The optional NixOS module `nix/modules/hidden-network-identity.nix` now builds. NixOS refused its
  placeholder hostname `localhost`, which it would have mapped to 127.0.0.2 in `/etc/hosts`, so a
  hidden configuration that imported the module as shipped did not build. The module now leaves that
  mapping out while the hostname is `localhost`, and a VM test builds a hidden system with it.
- The way back now puts the decoy's network state back before returning to it, after a `deactivate`
  and after a plain `emergency`. It deletes the virtual links a session brought up (a tunnel, a
  dummy or a bridge) and, with `iw`, the Wi-Fi interfaces it added on one of the decoy's radios, and
  counts a link as the decoy's only when it has the index it had at entry, so a tunnel the session
  brought up under the name of one of the decoy's goes too, while a link the session only renamed
  stays. It sets each device's hardware address and the hostname back, deletes the policy-routing
  rules and nftables tables the session added (those of wg-quick, NetworkManager, a VPN app, a
  container runtime or libvirt), writes back the network settings for all devices and for new ones
  (`net.ipv4.ip_forward` and the `all` and `default` keys of `net.ipv4.conf` and `net.ipv6.conf`),
  and puts the per-link state NetworkManager and systemd-resolved keep under `/run`,
  NetworkManager's in-memory profiles included, back in place, so every file keeps its owner and
  mode. A part of that state activation could not read in full is left as the session leaves it
  rather than deleted as if the decoy had none. The decoy's NetworkManager therefore no longer
  adopts a session link and records a profile for it on disk. The way back does not put back the
  addresses and routes a session gave the decoy's own devices, what it added inside a firewall table
  the decoy already had or with legacy iptables, the settings of a single device, anything it
  deleted or the name it gave one of the decoy's links, or any firewall table on a decoy without
  `nft`. A Wi-Fi interface of the decoy's that software in the session replaced with its own, as iwd
  does by default and airmon-ng does for monitor mode, is not made again either, so the decoy has no
  Wi-Fi on that radio until it powers off or reboots. Take VPN connections down, end monitor mode
  and stop containers and virtual machines before you deactivate, or end the session with
  `--poweroff`.
- `nails activate` and `nails check` refuse a host without `ip`, or without `dmsetup` when the hidden
  volume is on device-mapper (dm-crypt, LUKS or a VeraCrypt mapping) or its backend cannot be read.
  The way back runs both and skipped their work without a word when one was missing: without
  `dmsetup` the hidden mapping and its key stayed open on the decoy, listed in `/dev/mapper`, and
  without `ip` the links and hardware addresses a session changed were not put back. The refusal
  names the package to install: `iproute2` (`iproute` on Fedora) and `dmsetup` (`device-mapper` on
  Fedora and Arch). On NixOS the refusal now says to add a missing tool to the decoy's
  `environment.systemPackages`, where the check looks for it, rather than the hidden system's.
- The way back now sets a device's MAC address back also when its driver refuses to change the address
  of a device that is up, as USB Ethernet adapters such as the ASIX AX88179 and many Wi-Fi drivers do.
  The change used to fail silently there: the decoy came back with the hidden session's random address,
  which its NetworkManager keeps when the decoy's profile sets none, and which can reach the decoy disk
  in a DHCP lease. The way back now takes such a device down for the change and brings it up again, as
  NetworkManager does, leaves a device that was down as it was, and reads every address back. A device
  whose address it still cannot set back keeps the session's address until power-off, and nothing tells
  you so: end a session that changed a MAC address with `--poweroff` when that address must never reach
  the decoy. A VM test checks the change on an emulated NE2000 network card, whose driver refuses it
  in the same way, after `deactivate` and after a plain `emergency`.
- `activate --json` and `deactivate --json` print their one envelope only once the soft-reboot (or
  the power-off) is enqueued, so it reports whether that worked. They printed a success envelope
  before enqueueing it, and a failure to enqueue it followed as a second, error envelope: a script
  that read the first line took a failed switch for a success. A failure is now the only envelope,
  with `ok` false and exit 1. The switch stops the reader too, so a reader stopped first may not
  read a success. Without `--json` the output is unchanged: it still comes before the switch, which
  ends the terminal.
- `nails deactivate` in a hidden root whose session plan in `/run` is missing or cannot be read
  refuses at once, before it asks anything, with exit 6 and `emergency --poweroff` as the next step.
  It asked for confirmation, printed that the session was ending and that the decoy would start in
  a few seconds, and only then failed with exit 1, pointing at a plain `emergency`, which finds no
  plan there either and does nothing. After a way back that fails, its hint no longer says a plain
  `emergency` returns to the decoy: it returns where it can prepare the return and powers off where
  it cannot.
- `nails deactivate` and `nails emergency` name each hidden backend device they could not mark for
  deferred removal (the hidden session removed `dmsetup`, say) once the soft-reboot is enqueued:
  it stays open after the switch, its key in RAM, until power-off. `deactivate` logged such a
  device only at debug level and `emergency` left it out of its report. Under `--json` both list
  it as `backend_left_open`, `deactivate` with a sentence in its new `warnings`, and
  `emergency --quiet` no longer stays silent about it.
- `nails deactivate` warns before it asks when the last step of the way back will find no `ip`
  (iproute2), no `nft` (nftables) or, on a machine with a Wi-Fi interface, no `iw`, in the hidden
  session's system directories or, on NixOS, in the decoy's system it returns to. Without `ip` the
  policy-routing rules the session added stay on the decoy until power-off, and a virtual link it
  made or a MAC address it changed makes the machine power off instead of returning; without `nft`
  the nftables tables it added stay (a VPN app's table that blocks all traffic outside its tunnel
  keeps the decoy offline); and without `iw` a Wi-Fi interface it added on the decoy's radios, iwd's
  own in place of the decoy's included, makes the machine power off instead. `deactivate --poweroff`
  leaves none of them. Under `--json` each warning is in the envelope's `warnings`.
- `nails deactivate` says before it asks, and `nails emergency` in its report, when the way back is
  bound to power off instead of returning over what is there now: a link the kernel keeps when it is
  deleted (the fallback device a tunnel module makes when it loads, `tunl0` once a session loads
  `ipip`), or a link or MAC address of the session's it finds no `ip` or `iw` for, unless that
  changes before it runs. Both said the decoy would start at its own login screen without a
  condition; where they cannot tell, they now add that the machine powers off instead if a link, MAC
  address, rule or table the way back sets out to undo is still the session's afterwards. Under
  `--json`, `deactivate` carries the reason first in `warnings`.
- `nails check` and activation warn when the decoy has no `nft` (nftables), or has a Wi-Fi interface
  and no `iw` (the new `network-tools` check). Activation lists the decoy's own firewall tables with
  `nft`, and the way back deletes the tables a session added with it, and a Wi-Fi interface a
  session added on one of the decoy's radios with `iw`. Without `nft` the way back leaves those
  tables on the decoy until power-off, without `iw` such a Wi-Fi interface (iwd's own in place of
  the decoy's included) makes it power off instead of returning, and nothing said so before the
  session: a VPN app's table that blocks all traffic outside its tunnel keeps the decoy offline, and
  a stock NixOS decoy has no `nft`. The warning names the package to install, on NixOS with
  `networking.nftables.enable` as the other way to get `nft`, and looks for the tools where the way
  back does. It warns and does not refuse.
- The `activate --json` schema now ties `ok` to the outcome, as the output always did: a document
  that is not `ok` carries its error, and a failed activation (data status `failed`) is never
  `ok`. It accepted both contradictions, so a reader that validated a document could not tell a
  refused activation read as a success.
- `nails activate` refuses a state file it is not allowed to read (a permission denied, as an
  SELinux or AppArmor label can cause) as an unknown state, with exit 6, as the 0.3.0-rc.2 notes
  say it refuses an unreadable one. It took such a file for a state it could trust and went on.
- `nails activate` refuses a state file it is not allowed to read, or even to look up (a permission
  denied on the file or on a directory above it, as an SELinux or AppArmor policy can cause), as an
  unknown state, with exit 6, as the 0.3.0-rc.2 notes say it refuses an unreadable one. It took a
  file it could not read for a state it could trust, and one it could not look up for no state file
  at all, and went on. Every command now treats a denied lookup of the state file as it treats a
  denied read.
- `nails init` refuses a host NAILS does not support with exit 8, the unsupported-platform status,
  before it probes or writes anything, also with `--no-hardware-config` or `--hardware-config`, as
  the 0.3.0-rc.2 notes say unsupported hosts are refused. With either flag it skipped the platform
  check and wrote the layout on such a host; without them it refused with exit 4, after it had
  created and removed a probe file and symlink in the target. A release NAILS has not been tested on
  now warns with either flag too. The probes now come only after every precondition that can be
  read, so an obstruction or a missing base hardware configuration is refused with the target
  untouched.
- `nails discard` deletes a symlink the hidden session left at the path also when it points to
  nothing on the decoy, as a staged update's `/system-update` does; it reported nothing to delete.
  A symlink is deleted itself, never what it points at.
- `nails discard` refuses a path that lies below a symlink in the hidden session's copy (a
  `/home/alice` that the session linked to `/data/alice`) and names the link to discard instead.
  Followed on the decoy, the link led the deletion out of the hidden copy, onto the decoy's own
  files at the path it names.
- The pieces the way back leaves in `/run` for a Debian or Ubuntu decoy's first start (a copy of the
  binary, a one-shot unit and the wtmpdb writer's drop-in) are removed again when writing them fails
  part-way, and `nails verify` reports them when their step never ran. They stayed in RAM until
  power-off, with `/run` left executable. The drop-in is written last, after the copy it starts, so
  a way back cut short leaves the writer as the decoy has it, never pointing at a missing file. The
  threat model now also lists what they show until the next power-off: the one-shot's start in the
  decoy's journal and both units in `systemctl status`.
- `check`, the `inherited-autostart` warning and activation read only the autostart entries that are
  regular files once their links are followed, as systemd's autostart generator does. A FIFO named
  `*.desktop` in `~/.config/autostart`, `/etc/xdg/autostart` or the autostart directory of a NixOS
  profile blocked them, as reading it waits for a writer, and a link to a device such as `/dev/zero`
  was read without end. Such an entry, a directory or a link to nothing is now skipped unread, and a
  file of the same name in a later directory of the search path decides.
- `verify --offline` no longer reports the state file on the hidden volume. Run from a hidden
  session, as the operator guide suggests for a scan of the decoy, it printed
  `State file status: present at /mnt/data/state.json (active)` in a report about the decoy
  image: the record of the live session, which says nothing about the image. An offline scan now
  leaves the file unread, and under `--json` `state_file_status` has the kind `not_checked`; a
  live scan reports it as before.
- At the question of `activate`, `deactivate` and `discard`, the end of the input (Ctrl+D) cancels
  as a "no" does, and its notice now starts on a line of its own. It began on the question's row,
  as the terminal echoes no newline for Ctrl+D.

### Security

- `check` and activation refuse a hidden volume whose filesystem is also mounted at another place in
  the decoy's mount table. A desktop that mounts drives by itself (gnome-shell through gvfs and
  udisks2, KDE Plasma, udiskie) can mount a volume unlocked from a terminal again under
  `/media/<user>` or `/run/media/<user>`, where the decoy's desktop reaches the hidden files, and on
  Debian and Ubuntu that directory, named after the volume's label or UUID, is made on the decoy's
  root filesystem. The `hidden-volume` check counts every mount there with the device number of the
  mount at the root, a bind of a folder of the volume and another btrfs subvolume of it included,
  names each, says a desktop may have mounted it by itself, and gives the `sudo umount` line, the
  mount over one that this line cannot reach, and the advice to turn the automatic mounting of
  removable media off long before the next use. No flag lifts it. A bind of the volume at the root
  itself passes. For a root on a filesystem the decoy uses that `--allow-decoy-storage` accepted,
  the decoy's own mounts of that filesystem do not count, the one at `/` and those a line of
  `/etc/fstab` makes (a line that names the mount's device, or the ZFS dataset, and mounts what it
  shows, on btrfs the subvolume its `subvol=` or `subvolid=` names as the mount table shows that
  subvolume's path and id, so a `subvolid=` that cannot be read on either side makes none, or a bind
  line of any type from another of the decoy's own mounts of it whose source has no symbolic link in
  it, which NAILS does not follow; a line that is not plain makes none), and neither does a mount
  that shows none of
  the root's folder (NixOS's read-only bind of `/nix/store`, another btrfs subvolume). So
  `hidden-volume` passes a bind of a folder of `/` and a subvolume beside the fstab's `/home` with
  the flag's warning, and so does `backend-entries`, which lets be the decoy's own fstab lines for
  `/` and its system folders that mount another part of that filesystem, while their mounts are
  there, and the crypttab lines its boot opens for the device that filesystem lies on (see Fixed),
  on an encrypted decoy too, while a line for another folder still fails it. On NixOS
  `suspicious-nails-reference` still refuses such a root while the decoy's `/etc/nixos` names its
  filesystem's device, as `hardware-configuration.nix` usually does. A separate drive that a line of
  the fstab mounts at `/srv` passes `hidden-volume` with the flag's warning, and `backend-entries`
  refuses that line, which mounts the volume itself. One also mounted at `/srv` by hand is refused,
  and so is the copy that mount propagation makes of a mount at or below a bind line's source, and a
  root whose folder a mount that no fstab line makes shows too (a `/home` or `/srv` partition that
  systemd-gpt-auto-generator mounts, ostree's `/sysroot`, a ZFS dataset that ZFS mounts by its
  mountpoint property). That refusal first says not to unmount a mount the computer makes by itself,
  then how to unmount one made by hand. A directory of a disk bound at the root now needs the disk's
  own mount gone. `docs/decoy-requirements.md` says where GNOME, KDE Plasma and udiskie keep the
  setting, which is not verified for every release. A VM test records whether udiskie mounts a drive
  that cryptsetup unlocked, and in it udiskie did.
- An armed kdump on the decoy now refuses activation instead of only warning. If the kernel panics
  during a hidden session, kdump's crash kernel writes a dump of the session's memory, which can hold
  the hidden volume's key, and its kernel log to `/var/crash` on the decoy disk, outside the
  overlay. kdump counts as armed when `/sys/kernel/kexec_crash_loaded` reads `1` or
  `kdump-tools.service` or `kdump.service` is enabled or active, and Ubuntu arms kdump-tools by
  default from 24.10. An enabled unit counts even when it is stopped: the soft-reboot into the
  hidden session starts it again, and it loads the crash kernel there. A `kexec_crash_loaded` that
  cannot be read or holds anything but `0` or `1` is refused the same way.
  `--allow-persistent-decoy` accepts it for one run, with a warning. `nails status` shows an armed
  kdump on the decoy, and `status --json` carries it as `decoy_kdump_armed`.
- The way back from a hidden session powers off instead of returning to the decoy when what it sets
  out to undo of the network state is still the session's afterwards: a device of the decoy's that
  keeps the MAC address the session gave it, a virtual link or Wi-Fi interface the session added
  that is still there, a policy-routing rule or nftables table the session added that is still
  loaded (where activation listed the decoy's own and the way back finds `ip` and `nft`), or a part
  it cannot read back (the kernel's list of links, or `ip` or `nft` failing to list the rules or
  tables). That state lives only in the kernel, so a power-off erases it, where a return would hand
  it to the decoy, and a changed MAC address can reach a DHCP lease on the decoy disk. `deactivate`
  and a plain `emergency` behave the same, since both return through the same last step, and nothing
  on the screen says why: a line there would tell anyone watching that a hidden session had just
  ended. A missing tool alone changes nothing: activation and `deactivate` still only warn, and a
  session that left nothing for that tool to undo returns as before. Where the way back sees what
  the session left without the tool (a changed MAC address or a link without `ip`, a Wi-Fi interface
  without `iw`, the one iwd makes in place of the decoy's by default included), it powers off as
  well, and the warnings say so. The network settings, the hostname and the per-link runtime state
  below `/run` do not count, also when writing them back fails, and neither does what the way back
  leaves alone, such as what the session deleted or added inside a table of the decoy's.
- At every way back the hidden session's PID 1 named the decoy filesystems the session carries as it
  unmounted them: `Unmounting /mnt/data/root/decoy/boot...` and
  `Unmounted /mnt/data/root/decoy/boot.` on a console that shows its status lines (the default
  without `quiet` on the kernel command line), and the same with
  `mnt-data-root-decoy-boot.mount: Deactivated successfully.` in its log, which reaches a console
  that shows the kernel's info lines. Anyone watching read the word decoy. The entry now gives those
  mount units a runtime drop-in with `LogLevelMax=notice`, so PID 1 says nothing about them unless
  an unmount fails, and every way back and every rollback removes it. The layout on the hidden
  volume is unchanged.
- The hidden session masks systemd's GPT auto-generator, which mounts the partitions it finds by
  their type on the root filesystem's disk and turns on a swap partition where the fstab does not
  cover them, so the generator never mounts a decoy partition the fstab policy did not decide on. On
  the root overlay it finds no disk, so the mask is a defence in depth for a decoy where it would:
  one whose separate `/usr` is mounted read-only. The hidden root gets that `/usr` as a read-only
  bind, and with `/` on no disk the generator takes the disk of `/usr`. The mask is written at the
  switch and lives in `/run` for the session alone; a switch whose masks cannot be written is
  refused, and `nails verify` warns about a mask left on the decoy.
- `check` and `activate` no longer mount the trial overlay of the `upper-fs-capability` probe where
  the rest of the system can see it. The probe mounted it for a moment in PID 1's mount namespace,
  at `<hidden-root>/.probe-<pid>-<time>/merged`, and when systemd noticed the mount the journal got
  a line such as `mnt-data-.probe\x2d1141\x2d….mount: Deactivated successfully.`, which names the
  hidden root's mount point and the time of the run. A decoy whose journal was still persistent
  (a run before the decoy was made amnesic, or one with `--allow-persistent-decoy`) may hold such a
  line on its disk. The trial overlay is now mounted detached, through the kernel's mount API: no
  mount table lists it, and it is gone when the probe ends or the process dies. Where the kernel
  cannot mount it that way (without root, before Linux 5.2, or in a sandbox that blocks the call),
  the check fails before it writes anything. The README, the help and the next step `init` prints
  said that `check` (and `activate --dry-run`) changes nothing, and the 0.3.0-rc.2 notes called it a
  read-only report that writes nothing; the README, the help and `init` now say that it leaves no
  file or mount behind, and the operator guide says what it touches: probe files on the hidden
  volume that it removes again, the modification times they leave there, and no mount.
- On Debian 13 the way back now has the decoy's wtmpdb boot writer record the decoy's start as an
  ordinary `reboot`, stamped with the time of the switch. The 0.3.0-rc.3 notes said the way back
  already kept the writer from recording `soft-reboot`; that was wrong. Kept from the system bus,
  wtmpdb 0.73.0 still named the boot row `soft-reboot` once the decoy had been up for five minutes,
  and before that it dated a `reboot` row to the decoy's cold boot, which `wtmpdb last` lists as a
  crash. The way back now starts the writer in a time namespace whose boot clock starts at the
  switch, so it writes the row a power cycle writes and `soft-reboot` never reaches the disk. The
  cross-distro records test checks this in a VM on Debian 13, with the way back past five minutes
  of uptime.
- A backdated classic-`wtmp` boot record (systemd 255 and earlier, as on Ubuntu 24.04) is now
  corrected to the time of the switch, before anyone can log in, instead of the moment the
  correcting step ran, which dated the boot after the first records of its own start. The step no
  longer updates the file's access time on every way back.
- The 0.3.0-rc.3 notes and the threat model called the process numbers of the getty and login
  records written after the way back a weaker tell that needs a cold-boot baseline and is gone at
  the next power-off. Where the decoy keeps classic `wtmp` (Ubuntu 24.04, Debian 13 and NixOS), those
  records stay on the decoy disk, next to the low numbers of every earlier boot in the same file.
  Debian 13 is among them although `last` there reads wtmpdb, which keeps no process numbers: its
  getty still writes `/var/log/wtmp`. Only a session ended with `--poweroff`, which has no way back,
  leaves none of them.
- The way back now sets the kernel's process-number counter back, so that the decoy's getty gets
  about the process number its own boot gave it where the way back measures by that getty. A
  soft-reboot keeps the counter, so the getty the decoy started on the way back, and the records it
  writes to `/var/log/wtmp`, carried numbers that continued from the decoy's boot and the hidden
  session. Activation records the number the decoy's boot gave its getty (else logind), the hidden
  session's own start shows how many numbers a start uses up to its copy of it, and the way back's
  last step, once every hidden process has stopped and before the decoy starts a single unit, sets
  `/proc/sys/kernel/ns_last_pid` that many below. That assumes a hidden start that runs about as
  many processes up to its getty as the decoy's. The difference adds up over sessions without a
  power-off between them. A getty or logind that started more than a minute after the oldest process
  of its start that still runs, such as a getty started again after a logout, is passed over. When
  the getty is passed over, the way back measures by logind, and without either the counter goes
  just below the lowest number the decoy's own userspace held at entry. No test checks where the
  getty lands then. A process that a soft-reboot leaves running, in a unit with
  `SurviveFinalKillSignal=yes` or a root storage daemon, is left out of the measure, so the second
  and later sessions without a power-off measure by the getty the last way back started, as the
  first does by the boot's. The decoy's other units are not measured, so their numbers can land
  further from their boot's. The step is best effort and never stops the way back. Where it cannot
  set the counter (no number recorded, or a kernel without `CONFIG_CHECKPOINT_RESTORE`), or finds
  neither a getty nor logind to measure by, `deactivate` warns before the switch. The forensic
  oracle's allowlist no longer holds the getty records of the way back: in the oracle-images test
  they now fall in the range of a fresh boot's getty and subtract like it, so a getty record of
  another range fails the oracle again.
- Ctrl+C at the `deactivate` and `discard` prompts cancels at once, with the cancelled notice and
  exit 130 (under `--json` the cancel envelope). The signal handlers these commands install restart
  an interrupted read, so Ctrl+C only echoed `^C` there, and a "y" typed afterwards went on. The
  prompts now wait for the answer as `activate`'s does.
- Ctrl+C during `emergency --countdown` cancels the emergency before it acts, with the cancelled
  notice and exit 130 (under `--json` the cancel envelope). Run as root it ended the process by the
  signal with nothing reported; run without root it was ignored. A terminal hangup during the
  countdown no longer aborts it as root: only Ctrl+C or SIGTERM does, so a closed terminal does not
  stop the emergency.
- An internal error (a panic) exits 1, a code of the exit table, where it exited 101; under `--json`
  it prints the error `internal_error`. `config path`, `config show` and `config validate` with
  `--json` no longer crash on a configuration path that is not valid UTF-8.
- A hint that names a command to run names it by the binary's real path, quoted for the shell when
  the path holds a space or another special character (a volume mounted by its label, say), so it
  pastes as it is. The DMA-protection warning, the warning on an untested release or derivative,
  `verify`'s guidance for a stale record and for RAM, the configuration-not-found error and `init`'s
  errors named a bare `nails` command, which `sudo` cannot run because the binary is not on its
  `PATH`; so did the comment on the emergency unit in the hidden NixOS module written to a fresh
  volume.
- `recover` gives each refusal the next step that fits it: in the hidden session `deactivate`, where
  it pointed at `emergency`, which kills the session and loses unsaved work; while an activation is
  entering, none, with the advice to wait for its soft-reboot. A recovery that itself fails (the
  record cannot be written) exits 1 with the error `recover_failed` instead of 6.
- `status` shows a state file it cannot read or trust as an unknown state, wherever the machine is,
  with what to do about it unless something more urgent comes first (a hidden root without a way
  back, an interrupted activation). In the hidden session it showed the inactive default that stands
  in for the record, with no word of the damage.
- The autologin that `check` and the `inherited-autostart` warning list is read as each display
  manager reads its files. A key counts only in its own group: `[daemon]` for GDM, `[Autologin]` for
  SDDM, and for LightDM `[Seat:*]`, `[SeatDefaults]` and the `[Seat:…]` groups that match the first
  seat. The files are read in the display manager's order, and a later one overrides an earlier one,
  an empty value too: an empty `User=` in `/etc/sddm.conf` or `autologin-user=` in
  `/etc/lightdm/lightdm.conf` now turns off the autologin a drop-in sets, where it was skipped and the
  drop-in's account listed. SDDM's vendor drop-ins in `/usr/lib/sddm/sddm.conf.d` and LightDM's in
  `lightdm/lightdm.conf.d` below `/usr/share`, `/usr/local/share` and `/etc/xdg` are read too, which
  were not; in SDDM's every file but the hidden ones is read, as SDDM reads them, not only the
  `*.conf` ones. GDM's `AutomaticLoginEnable=1` turns autologin on, as for GDM, and each GDM file that
  turns it on is listed, not only the first. A file a display manager refuses as malformed counts as
  it does for that display manager: GDM keeps what it read before the bad line, LightDM skips such a
  drop-in and does not start on such a `lightdm.conf`. SDDM and Plasma Login Manager sort a
  directory's drop-ins by the collation of their locale, which the files do not tell, so where
  collations disagree on the order of two (`kde_settings.conf` and `kde-autologin.conf`, say) the
  account either order ends with is listed. A line that holds a NUL is read as GLib and SDDM read
  it, and one a display manager may read two ways counts both ways: SDDM reads a line up to a NUL on
  Qt 5 and whole on Qt 6, and GLib judges a language tag beyond ASCII by its own Unicode tables. Only
  regular files are read: a FIFO, socket or device in one of these places is skipped, where `check`,
  the warning and activation could hang reading it.
- In the `fresh-home` persona, activation no longer follows a symbolic link in the upper when it
  makes the operator's home. Where a hidden session had replaced `/home`, or a directory below it on
  the way to the home, with a link, absolute (to `/var/home`, say) or relative, that leads out of
  the upper, the next activation could make the home, with its mode, owner and opaque attribute,
  wherever the link led, which can be the decoy disk. Each directory on the way is now opened in the
  one above it without following a link and made there when it is missing, and a link, or anything
  else that is not a directory, on the way refuses the activation, which makes nothing and names
  it: delete the link from the upper on the hidden volume and activate again. A home already in
  place is kept as it is, as before. A new home now takes its opaque attribute first, and it is
  removed again when its mode or owner cannot be set either: a home whose mode or owner failed was
  left without the attribute, and every later activation kept it, with the decoy home showing
  through.
- The NixOS reference check (`suspicious-nails-reference`) knows more names of the storage the
  hidden volume is on: the kernel's name of each layer and of the volume's own device, alone as a
  udev rule writes it (`KERNEL=="sdb2"`) or as its device node (`/dev/dm-0`), and its
  `/dev/block/<major>:<minor>` link. A decoy configuration that named the hidden storage in one of
  these ways passed the check. A path now counts however many slashes separate its parts
  (`/mnt//data`, `/dev/mapper//data`), and behind the prefixes systemd allows before a path where
  they start the value (`EnvironmentFile=-/mnt/data/app.env`, `ExecStart=+/mnt/data/bin/app`),
  which passed too. `/srv//mnt/data`, which is `/srv/mnt/data`, no longer counts as `/mnt/data`. A kernel name counts as the kernel gives it while the check runs, so a
  decoy line that names a device of its own as `/dev/dm-1` is refused while the hidden volume's
  storage holds that number; name such a device by its uuid. The check still does not follow a
  mapping defined through a `let` binding, `lib.listToAttrs` or an interpolated name, or a path
  with a `.` or `..` component, and does not know the units systemd names after the storage's
  devices.

### Known issues

- A switch into or out of a hidden session can stop halfway: the programs have closed, but the
  screen stays dark or still and no login screen comes. Once the old system's units have stopped,
  PID 1 can go to sleep with work still queued and wait until something wakes it. This matches a
  fault in systemd ([systemd issue #44107](https://github.com/systemd/systemd/issues/44107)). In
  NAILS's NixOS VM tests 7 of about 13,000 switches stopped this way, all on the way in, and one
  on the way back in a test run set up to provoke it. Pressing Alt+Up with the left Alt key on the
  computer's keyboard woke PID 1 in the tests, and the switch went on. If that does nothing, power
  off rather than wait: after 30 minutes systemd switches by force and skips NAILS's last step
  before the switch, so the hidden session would start without the masks that keep its systemd
  from swapping onto a decoy disk or mounting one read-write, or the decoy with the hidden
  session's files in `/run`. systemd fixed the issue in 259.10, 260.6, 261.4 and 262.1. On
  3 November 2026 no release of 254 to 258 had the fix, and no supported decoy had it, neither in
  its systemd release nor as a patch of its package: Debian 13 had systemd 257.13, Ubuntu 24.04
  255.4, Ubuntu 26.04 259.9, NixOS 26.05 260.5 and NixOS unstable 262. See docs/operator-guide.md.

## [0.3.0-rc.3] - 2026-10-20

### Changed

- The release binary is built with Rust 1.99.1; 0.3.0-rc.2 was built with 1.93.0.
- A release run boots every NixOS VM test on the tagged commit. Until now it took a test whose
  derivation had passed in an earlier run from the project's binary cache, without booting it.
- NAILS's automated VM tests cover Debian 13 and Ubuntu 24.04, and Ubuntu 26.04 is a supported target checked by hand (its automated image is still to be added). A later release, such as Ubuntu
  26.10 (released on 2026-10-15), still runs, but `init`, `check` and `activate` now warn that
  NAILS has not been tested on it; 0.3.0-rc.2 accepted every release from Debian 13 and Ubuntu
  24.04 on without a word. `check` names the detected host in a new `platform` row, which carries
  that warning.

### Fixed

- The attach gate and the storage checks resolve an `/etc/fstab` or `/etc/crypttab` entry that
  names its device by a tag (`LABEL=`, `UUID=`, `PARTLABEL=`, `PARTUUID=`) whose value holds a
  space, a slash or another character udev encodes in the link it makes for the tag, or is in
  single quotes. Such an entry named a path that no link has, and a value starting with a slash
  named that path itself.
- A command no longer hangs on a mount table that names one mount ID twice, as a read of
  `/proc/self/mountinfo` can while a mount is replaced: the lookup of the mount at a path went
  round in a circle for ever.
- A `utab` line with an empty value is skipped, as libmount skips it, instead of surviving a
  switch under its mount ID.
- The `decoy-persistence` and `sleep-policy` checks read the journald, logind and
  systemd-coredump configuration as systemd reads it: a line also ends at a carriage return or a
  NUL byte, a section name with a control character, a quote or a backslash stops the reading of
  that file and of every file after it, and a byte order mark is dropped from the first line that
  starts with one, not only from the first line. Assignments that systemd never applies counted,
  so a check could pass or fail on a setting the daemon does not use.
- `nails rehearse scan --offline` finds the UTF-16 form of the canary in a sparse disk image also
  when it ends where a hole starts; it reported such a canary as not found.
- `nails verify --disk` no longer wraps round the block numbers of a GPT whose byte offsets do not
  fit in 64 bits, which let a corrupt or crafted table place a partition, the free space or the
  partition entries anywhere on the disk.
- The refusal of a Debian or Ubuntu host below the minimum release, or whose release cannot be
  read, names the minimum as the distribution writes it, `Debian 13` and `Ubuntu 24.04`, instead of
  `Debian 13.0` and `Ubuntu 24.4`.
- `nails check` could report a host ready that `activate` then refused with exit 8, such as Fedora,
  Arch or a Debian host without the merged `/usr`. Its new `platform` row fails there, with the
  reason `activate` gives.

### Security

- The way back no longer leaves a login or boot record on the decoy that an ordinary power cycle
  never writes. On Debian with wtmpdb the boot writer named the boot row `soft-reboot` when the
  service manager reported a soft-reboot; on a service manager that keeps the userspace start time
  across a soft-reboot (systemd 255 and earlier, as on Ubuntu 24.04) the classic-`wtmp` boot record
  carried the decoy's first boot time, so the file held a boot stamped before the shutdown that
  precedes it. The way back now keeps the wtmpdb boot writer from recording `soft-reboot` and
  corrects a backdated `wtmp` boot record to the time the decoy came back, without masking either
  writer, so no shutdown row goes missing and the decoy's login and boot records read as one clean
  power cycle. The process numbers of the getty and login records written after the way back still
  continue from the decoy's boot, a weaker tell a later release will address.
  **Until you run a build with this fix**, end Debian 13 and Ubuntu 24.04 sessions with
  `nails deactivate --poweroff` (or `nails emergency --poweroff`): a power-off has no way back, so
  none of these records are written.
- The hidden session masks a decoy swap or mount under the unit name systemd gives it also when its
  `/etc/fstab` entry names the device by a tag whose value holds a character udev encodes in its
  link or is in single quotes (`LABEL=swap\040space`), or has a path with a `.` component or `..`
  right after the leading `/` (`/dev/disk/by-id/./x`, `/mnt/./backup`). NAILS masked a name systemd
  never generates and left the real unit free, so the hidden session could swap onto a decoy disk or
  mount a decoy filesystem. A decoy filesystem overlaid at such a mount point now keeps its hidden
  layers under the simplified name, the name of its unit (`<hidden-root>/root/mounts/mnt-backup` for
  `/mnt/./backup`, where 0.3.0-rc.2 used `mnt-.-backup`): rename the directory while NAILS is
  inactive, or the hidden files in it stay out of view.
- A release can be verified without a GitHub account. It carries its three attestations as
  Sigstore bundles (`provenance.sigstore.json`, `sbom.sigstore.json`, `vex.sigstore.json`), which
  cosign 3.1.3 or later checks against the downloaded files, also on a computer without a network
  connection; `docs/verify-release.md` shows how. The release workflow runs the same check before
  it drafts the release.

### Known issues

- On Ubuntu 26.04, chrony (time sync) and CUPS (printing) fail after the switch into the hidden
  session: AppArmor blocks their messages to systemd and to the journal, whose sockets were set up
  before the switch. Other services that AppArmor confines may fail the same way. In the hidden
  session the clock is not synchronized and printing times out, and after the way back the decoy
  lists chrony as failed until its next full reboot, which hints that a soft-reboot happened.
  Reboot fully after a session to clear it. The fault lies outside NAILS: a plain
  `systemctl soft-reboot` into another root, without NAILS, breaks chrony the same way.

## [0.3.0-rc.2] - 2026-10-16

NAILS 0.3.0 replaces the per-directory live overlays of 0.2 with one design: the hidden session is
an overlay over the whole decoy root, entered and left with `systemctl soft-reboot`.
Debian 13 or newer, Ubuntu 24.04 or newer and, provisionally, their derivatives join NixOS as
decoys.

0.3.0-rc.1 was tagged but never published: its release run stopped at the SBOM attestation.

### Upgrade notes

Upgrade only while NAILS is inactive: end a 0.2 session with its own `nails deactivate` (a reboot
ends it too) before replacing the binary. This release breaks compatibility with earlier state,
config and CLI surfaces; there are no compatibility shims.

- The decoy needs systemd 254 or newer. The hidden root lives under `<hidden-root>/root/`
  (among them `upper`, `work` and `mounts`); the uppers of the 0.2 per-directory overlays
  (`<hidden-root>/<name>`, `<hidden-root>/.work`) are not read. Move what you need into a hidden
  session and delete them. On NixOS the hidden hardware configuration now lives in
  `<hidden-root>/root/upper/etc/nixos/`; run `nails init` again to place it.
- On NixOS, a decoy whose `/etc/nixos` is a flake needs a hidden flake. 0.2 built that flake through
  its overlay of `/etc`; 0.3 refuses to build the decoy's own flake (`nixos-build-target`,
  `--no-preflight` included), also when `nixos_flake` or `--nixos-flake` names it
  (`/etc/nixos#host`, the form 0.2's examples used, `path:/etc/nixos`, `git+file:///etc/nixos`,
  `path:/etc?dir=nixos` or a link to it) and when `<hidden-root>/nixos` is a link to it, because the
  build would read only the decoy's files and leave out the hidden module and the hidden hardware
  configuration. Write a self-contained flake in `<hidden-root>/nixos` that imports the hidden
  module (`<hidden-root>/config/nixos/configuration.nix`) and reads none of the decoy's files, write
  and lock it inside a hidden session (`activate --overlay-only` enters one), never on the decoy,
  and build it there with `nixos-rebuild build --flake <hidden-root>/nixos#<host> --impure`,
  `<host>` being the decoy's hostname; `nixos_flake` names such a flake elsewhere.
- The hidden root must be a volume of its own. NAILS now refuses a root that 0.2 accepted: a folder
  (no mount point), a btrfs subvolume or bind of a folder of a filesystem the decoy uses, a logical
  volume in the decoy's volume group, an image file on a decoy filesystem, and an overlay, FUSE,
  network or ZFS filesystem. Move the hidden volume to a device of its own (see "Where setup
  happens" in the operator guide). An unprivileged `check` or `status` on a distribution whose
  `/etc/crypttab` only root can read gets `storage_unjudged` and logs to stderr only; run it with
  `sudo`.
- Configuration moves from `config/nails.yaml` (YAML) to strict `config/nails.toml` (TOML) next to
  the binary. 0.3 never reads `config/nails.yaml` and does not warn about it: an unconverted setup
  runs with the defaults. Convert each key by hand: `hidden_volume_path` is now `hidden_volume_root`
  (leave it unset to derive it from the binary's location), unknown keys are rejected, and the keys
  listed under "Removed" must be deleted. `nails init` writes a documented template and
  `nails config show --example` prints every key.
- Invoke the binary from the hidden volume by full path (`sudo "$ROOT/nails" …`); nails is never on
  the decoy `PATH`. `activate --flake` is now `--nixos-flake`, `status -v` is now
  `status --details`, `--plain` and `--no-color` are replaced by `--ascii` and
  `--color auto|always|never`, and `--no-logs` by `--no-log-file`; see "Removed" for the flags
  that are gone.
- `activate` and `deactivate` now ask for confirmation, and without a terminal they refuse with
  exit 2 (`needs_confirmation`); 0.2 skipped the prompt unless `--interactive` was given. Add `-y`
  to every script, keybinding or unit that runs them; `emergency` never prompts.
- Exit codes and JSON output changed. JSON output carries `schema_version = 1`; scripts that
  parsed the old output must be updated against the exit-code table in `nails --help` and the
  schemas under `docs/schemas/`.
- The on-disk state schema changed. 0.3 cannot verify a `state.json` that 0.2 wrote: `status`
  reports the state as unknown and `activate` refuses (exit 6) until you delete the file, from a
  clean inactive system; do not hand-edit it. `nails recover` removes what an interrupted activation
  left.

### Added

- The whole-root session. `nails activate` builds one overlay over the whole decoy root at
  `/run/nextroot` (the decoy root read-only as the lower, `<hidden-root>/root/upper` as the upper),
  applies a fixed policy to every other decoy filesystem (the ESP and `/boot` bound read-only, other
  mounted local filesystems overlaid with an upper under `<hidden-root>/root/mounts/`, swap,
  unmounted disks, network filesystems and disk-backed overlay entries masked), binds `/run` and the
  hidden volume into it, writes the session plan with a RAM copy of the binary and configuration to
  `/run/overlay-runtime`, and soft-reboots. An `/etc/fstab` that cannot be read refuses the entry.
  Every mount below `/run/nextroot` is private from the moment it exists, so none of them propagates
  into the decoy's own mounts; only the next root's own mount stays shared until the switch, so that
  the mount namespaces made before the entry (logind's, a sandboxed service's) see the next root and
  lose it again on a rollback. The policy's mount points and the decoy filesystems the session
  carries for the way back are placed as the hidden root resolves their paths, so an absolute link
  on the way (a `/home` linked elsewhere) never takes them onto the decoy disk. The boot-loader
  units that would write to the read-only ESP and `/boot` at every start
  (`systemd-boot-random-seed`, `grub-common`, `grub-initrd-fallback`) are masked in the hidden
  session only. Every process of the hidden session starts inside the overlay. Activation logs you
  out after a confirmation (`-y` skips it) and, as its last step, kills the decoy's interactive
  shells, so a shell that saves history on exit never writes the activation command (the
  `incremental-history-flush` check warns about shells that save after every command).
- On NixOS the hidden system is built into the next root's store (`nix build --store /run/nextroot`,
  the evaluation cache on the hidden volume), activated chrooted, and entered by repointing
  `/run/current-system` after every decoy unit has stopped: one soft-reboot, no bootloader install,
  no system profile change. It is built from the first of: a flake given with `--nixos-flake` or
  `nixos_flake`, a flake in `<hidden-root>/nixos`, and the legacy configuration (the decoy's
  `/etc/nixos` with the hidden hardware configuration, which imports the hidden module
  `<hidden-root>/config/nixos/configuration.nix`). A flake has the hidden module only if it imports
  it, and a decoy whose own `/etc/nixos` is a flake is refused (`nixos-build-target`,
  `--no-preflight` included) until a hidden flake is given; naming that flake with `--nixos-flake`
  or `nixos_flake` as a local path or a `path:`, `git+file:` or `file:` reference, also with a query
  (`?ref=main`), a `dir` parameter (`path:/etc?dir=nixos`) or through a link, or a
  `<hidden-root>/nixos` that is a link to it, is refused the same way. Inside the hidden session
  `nixos-rebuild test` applies changes: plain for the legacy configuration, and with
  `--flake <hidden-root>/nixos#<host> --impure` for a hidden flake, `<host>` being the decoy's
  hostname (on a flake decoy a plain `nixos-rebuild test` builds the decoy's own flake, without the
  hidden module). `--overlay-only` enters with the decoy's own system plus the hidden `/etc` and
  home; `check` says that no hidden system is built, and `activate` then names none. The paths of
  the hidden system's closure that still come from the decoy store are copied onto the hidden
  volume, so a decoy that garbage-collects or rebuilds between sessions does not break the hidden
  system. On Debian and Ubuntu the hidden configuration is the upper's `/etc`.
- The switch in both directions runs from the RAM copy (`ExecStart=` of
  `systemd-soft-reboot.service`) and acts only on an armed plan. On the way back it deletes the
  runtime journal, which the decoy's journald and the hidden one write alike, so a volatile decoy's
  journal starts again at the return, without the decoy's own records from before the session;
  scrubs the top of `/run` (two levels deep, three below `/run/systemd`) of what else the decoy did
  not leave there when it stopped for the entry, such as a PID file that the hidden session's copy
  of a decoy service wrote again; puts the decoy's name-server records below `/run/resolvconf` back
  as the decoy left them, so the hidden session's name servers and search domains (a VPN's, say) do
  not reach `/etc/resolv.conf` on the decoy disk; removes the session's drop-ins by name, leaving
  the decoy's own; resets units the session left failed; and, once the hidden units have stopped,
  gives the decoy's libmount `utab` lines back under the new mount IDs of the mounts the way back
  restores, without the hidden session's lines, and writes journald's kmsg cursor so the decoy
  journal imports no hidden kernel record. Each switch keeps only the `utab` lines whose mount it
  carries, by the line's mount ID or, for a line without one, by its path, source and root, and
  writes the file as libmount does (a new file renamed over the old one, under libmount's lock): the
  kernel hands the IDs of the mounts a switch leaves behind to later mounts, and a stale line would
  lend its options to one of those or to a new mount at its path; an `x-initrd.mount` lent that way
  could hang the next soft-reboot or power-off. After a session the decoy has its mounts back as it
  had them when the entry began: before the decoy's userspace starts, the way back makes again every
  mount it can take from the decoy root or a filesystem the session carried, in the decoy's order
  and with each mount's own options (NixOS's read-only bind over a store on the root filesystem, a
  mount stacked under a carried one, a RAM filesystem the initrd mounted), each with its `utab` line
  under its new mount ID, so those that the decoy's initrd marked `x-initrd.mount` are left to the
  final unmount at its next shutdown, as after a boot; a decoy line that names no mount the way back
  makes again is not given back. `activate` warns about a decoy mount the way back cannot make again
  where the session carries its filesystem, and about one that a plain soft-reboot keeps (NixOS's
  `/etc` overlay). Where the session itself puts a decoy filesystem behind an automount in place
  (`x-systemd.automount`, often the ESP), it masks that automount, and the way back leaves the
  automount to the decoy's start. Every way back to the
  decoy (the return, an emergency, an entry rolled back or recovered, a leftover next root disarmed
  at a reboot) also writes back the kernel's module loader, hotplug and firmware paths, which every
  entry records before anything runs and which a NixOS activation in the session points at the
  hidden store, and removes the session's unit masks. The session's drop-ins and runtime units are
  readable by all, so PID 1 logs no warning that names them as world-inaccessible. The session keeps
  working with `blk-availability.service` (Debian, Ubuntu), Ubuntu 26.04's D-Bus units and NixOS
  static addresses (`networking.interfaces`), whose stop would otherwise unmount the hidden volume,
  stall the login screen or drop the network.
- `nails deactivate` runs in the hidden session and soft-reboots back to the plain decoy after a
  confirmation (`-y` skips it); `--poweroff` powers off instead. The hidden volume is unmounted and
  its device-mapper stack closed by the switch itself, so dm-crypt wipes the master key from RAM; a
  backend that is not device-mapper based is unmounted but not closed.
- `nails emergency` acts at once, before argument parsing, configuration and logging: in the hidden
  session it prepares the way back, marks the backend for closing, enqueues the soft-reboot with
  PID 1 and kills every hidden cgroup (`cgroup.kill`); the machine returns to the decoy's login
  screen (NAILS logs nobody in, but a display manager set to log an account in automatically logs it
  in again, as at boot). `--countdown <SECS>` waits first with a Ctrl+C hint, `--poweroff` and
  `--reboot` replace the soft-reboot back, and a way back that cannot be prepared powers off. The
  result names the action and any fallback, the cgroups and processes killed, the timed phases and
  any mount left behind; an emergency that leaves a mount behind, or can only ask the kernel to
  power off, exits 7. On the decoy, it removes what an interrupted activation left and enqueues a
  requested `--poweroff` or `--reboot` right after; when it enqueues none, it also reloads PID 1,
  which would otherwise keep the removed drop-ins and masks loaded, and makes `/run` `noexec` again
  where the decoy had it so.
- `nails recover` removes an interrupted activation's leftovers on the decoy (`/run/nextroot`,
  `/run/overlay-runtime`, the session's drop-ins and unit masks), gives the kernel back the decoy's
  helper paths, closes the hidden backend where nothing uses it and resets the state. Like a
  rollback and an emergency on the decoy, it also removes the copies of the next root's mounts that
  every mount namespace made before the activation received (logind's, a sandboxed service's).
- `nails check` (alias `doctor`, and what `activate --dry-run` runs): a read-only readiness report
  built from the same pre-flight registry as activation, with each check's result and fix, the
  effective configuration, the decision for every decoy filesystem and the persona mode. It writes
  nothing, supports `--json` and exits 4 when a check fails.
- The attach gate: `init`, `activate`, `check`, `deactivate`, `reset-upper`, `rehearse plant` and
  the log and state writers accept only a hidden root that is a mounted volume of its own, before
  anything is written or probed. They refuse a folder, a second filesystem mounted over the root
  and, outside the session, storage the decoy uses (per its mount table, `/etc/fstab`,
  `/etc/crypttab` and sysfs); in the session only the volume the session started from is accepted.
  A refusal is one neutral message with exit 4 and a code (`not_separate_volume`, `root_covered`,
  `storage_unjudged`) that names no storage tool or device, and `--no-preflight` does not skip it.
  `--allow-decoy-storage` (`init`, `activate`, `check`) turns a refusal of decoy storage into a
  warning for storage the operator knows the decoy does not use; `status` shows the choice. Run as
  root, the gate reads `/etc/fstab` and `/etc/crypttab` without updating their access time.
- New pre-flight checks: `systemd-version`, `soft-reboot-units` (prints the module an older nixpkgs
  needs), `decoy-root` (refuses a tmpfs, ZFS or overlay decoy root), `session-state`,
  `fstab-policy`, `mount-namespace` (activation must share PID 1's mount namespace),
  `upper-fs-capability` (the hidden filesystem can host an overlay upper), `host-tools` (names any
  missing tool and its package), `backend-entries` (refuses a decoy crypttab or fstab line that
  opens or mounts the hidden volume), `decoy-persistence` (refuses a persistent journal or an active
  rsyslog, syslog-ng or auditd unless `accept_persistent_decoy` or `--accept-persistent-decoy` is
  set; warns about atime, crash-dump channels, sudo's own log files and the NixOS auto-upgrade
  timer, and passes systemd-coredump only when it has both `Storage=none` and `ProcessSizeMax=0`),
  and the warn-only `backend-detect` (discard, file container timestamps, copy-on-write hosts),
  `binary-location`, `inherited-autostart`, `incremental-history-flush`, `sleep-policy` (a lid or
  idle setting that would suspend the session, or a closed lid set to `ignore`, which leaves the
  session running and unlocked) and `residue-catalog`, and the informational `memory-wipe`
  (`init_on_free=1`). Failures end with one ordered list of fixes, and checks that depend on a
  failed one are skipped with a reason.
- Disks during the session (`[session_mounts]`): the session watcher raises a neutral desktop alert
  for every read-write mount of a disk outside the hidden volume and for a disk mounted over the
  hidden root or one of its parents, which `status` also names (`hidden_root_covered_by`); nothing
  NAILS writes reaches such a cover. Opt-in `read_only` makes every disk the session does not use
  read-only at the block layer until the way back. The alerts go to the account logged in on the
  machine's own screen and run as that account, since a desktop session bus admits no other (the
  child drops root's groups and ids before it starts), through `notify-send` or, where it is
  missing, `busctl`. Each alert runs in a session of its own with `no_new_privs` set, waits at most
  10 s for the notification daemon, and is sent from a thread of its own, so a daemon that never
  answers holds up no probe, no other alert and no emergency.
- The backend watcher (`[backend_watch]`) alerts when the hidden backend fails mid-session and,
  only when opted in, runs the emergency after a debounce.
- `[sleep_policy]` (`warn` by default, `block` or `teardown`): `block` holds sleep and idle block
  inhibitors, and the lid switch's when a closed lid would sleep; `teardown` powers off through the
  emergency before the machine sleeps.
- Persona options (`[persona]`): `mode = "fresh-home"` gives the operator an empty home in the upper
  instead of the decoy home, and `mask_inherited` lists inherited decoy autostart entries and user
  units to hide from the hidden session (`["*"]` hides all; empty by default), also one the
  inventory does not list: a name with a unit suffix as a user unit, any other as an autostart
  entry. The masks are written as the hidden root resolves their paths, so an absolute link on the
  way (a `/home` linked elsewhere, a `~/.config` linked to a dotfiles directory) never takes them
  onto the decoy disk. An optional NixOS module and NetworkManager drop-in give the hidden session
  its own MAC addresses and hostname; the way back can leave the random MAC address on the decoy's
  device, and the hostname on a decoy without `/etc/hostname`, so end a session that used them with
  `deactivate --poweroff` (or `emergency --poweroff`).
- Inherited decoy state: `nails check` and the `inherited-autostart` check report what the hidden
  session would inherit and needs review: autostart entries and user units in the decoy home,
  system-wide ones that are not part of the desktop or the distribution, lingering, display-manager
  autologin, and every entry on a documented list of known trace writers (sync, backup, messaging,
  mail and account clients, phone links). The desktop's and the distribution's own components are
  counted, not reported, and an entry `mask_inherited` names counts as handled. Autologin has a
  remedy of its own: turn it off for the hidden session only; it stays listed while the decoy keeps
  it. On NixOS the autostart directories of the system and user profiles are read too. `nails check`
  names a `mask_inherited` name that matches nothing, says on a line of its own when the hidden
  session starts in the decoy home (`shared-home`), and in JSON gives every entry its origin and
  status.
- `nails rehearse`: `plant` puts a random canary into a hidden session, and after the way back
  `scan` searches the raw decoy devices (or disk images with `--offline`) for it; `status` and
  `reset` follow the rehearsal. A scan is refused only inside the session the canary was planted
  in, which `plant` records by the session's entry time, so it runs on the decoy after a plain
  `nails deactivate` on every systemd version. The result lists the channels the canary could not
  be planted in (the notification, when no desktop session could show it) as not tested. The scan
  exits 0 when the canary is not found, 11 when it is and 9 when a device could not be read in
  full.
- `nails verify --offline --root <mount>` scans a mounted decoy image, and `--examiner` reports the
  setup traces an examiner looks for (encryption headers, containers, crypttab lines of every
  TrueCrypt and VeraCrypt kind, LVM archives, tooling and history), grouped by what they suggest;
  `--disk <device>` adds partition-level checks. A residue catalog names every class of trace a
  session or its setup can leave, with its mitigation; `verify` and the `residue-catalog` check run
  its probes, and the residue tables in the docs are generated from it.
- `nails activate` writes a read-only decoy residue report under `<hidden-root>/reports/` before
  the switch and prints a one-line summary: no known residue, or how many warnings and critical
  findings the report holds.
- `nails config path|show|validate`: `show` prints every effective value and its source
  (default, file, cli, derived), `--example` prints every key, and `validate` checks a file
  strictly.
- `nails reset-upper <PATH>` deletes a path's hidden copy from the upper, so the decoy's own files
  show through again (for example after a decoy update); it is refused in the hidden session.
- `nails completions <shell>`, a man page (`nails.1`), a Markdown CLI reference (`docs/cli.md`),
  JSON schemas under `docs/schemas/`, and EXAMPLES and an exit-code table in `--help`. The release
  archive ships the man page, the CLI reference, the operator guide and the threat model.
- `nails status` reports the live session from the mount table and the session plan (posture
  `decoy`, `active`, `transitioning`, `degraded` or `unknown`), the policy for every decoy
  filesystem, whether the decoy keeps a persistent log store, the persona mode and how long the last
  activation took, as `activate` printed it. It shows times in local time with their UTC offset;
  the JSON keeps UTC. An interrupted entry exits 7 and points at `nails recover`; a record that
  still says active after a power loss is named as such, and `nails recover` resets it.
- Ctrl+C (SIGINT) or SIGTERM cancels an activation at its next step up to the soft-reboot, during
  the residue baseline, the pre-flight checks and the hidden system's store copy too, and removes
  everything it built (exit 130); at the confirmation prompt it ends the prompt at once. A cancel
  reads "Activation cancelled; nothing was changed.", as an answer of n does (exit 1), and
  `activate --json` gives it the status `cancelled`. An answer of n at the `deactivate` and
  `reset-upper` prompts prints the same kind of notice ("Deactivation cancelled; nothing was
  changed.", "Reset cancelled; nothing was removed.") and exits 1; their JSON is the error envelope
  with the code `cancelled`. The hidden system's activation runs in a process group of its own,
  which a Ctrl+C on the terminal does not reach, and finishes first. SIGHUP no longer aborts a
  running command, and NAILS lowers its own OOM score.
- NAILS disables its own core dumps before parsing its arguments, so a crash cannot write its
  memory to the decoy.
- Documentation: an operator guide organised by where each step runs, with a recovery runbook,
  `docs/threat-model.md`, `docs/configuration.md`, `docs/backends.md`,
  `docs/decoy-requirements.md`, `docs/architecture.md`, `docs/distribution.md` and
  `docs/verify-release.md`.

### Changed

- Configuration is strict TOML: unknown keys are rejected with a did-you-mean hint, most keys of the
  old live-overlay design say they were removed, configured paths are validated when the file is
  loaded (relative, `..`, symlinked or out-of-root paths are rejected), and a missing or invalid
  `--config` file exits 3. So does a configuration the command cannot read: `init` writes it
  readable by root only, and a run without root then names the full `sudo` line to use, every
  argument included, in the text and as the hint of the JSON error. Without a config file,
  `activate` says before its confirmation that it uses the built-in defaults, under `-q` too.
- One stable machine interface: a typed JSON envelope (`schema_version`, `command`, `ok`, and `data`
  or `error`; `activate --json` prints a progress line and then its result, one JSON object per
  line, and every log line goes to stderr) and one exit-code table for every command (pre-flight
  refusals 4, not run as root 5, untrusted state 6, degraded or interrupted 7, unsupported host 8,
  completed with warnings 9, `verify` warnings and critical findings 10 and 11, cancelled 130).
  `activate --json` lists the boot-loader units in `masked_units`, as `status --json` does.
- Output flags (`-c`, `-v`/`-q`, `--color`, `--ascii`, `--json`, `--no-log-file`) are global. Colour
  is never used on piped output and honours `NO_COLOR` and `CLICOLOR_FORCE`; console lines no longer
  carry a timestamp. At the default verbosity the console is compact: a log event prints its
  message, a warning or error its mark, message and details, and routine events (each passed check,
  the store and staging steps) go to the log file only; `-v` and `-vv` show the full records. Counts
  on the console take the singular for one and the plural otherwise (`1 residue channel is live`,
  `4 catalog probes`).
- `activate`, `deactivate`, `emergency` and `recover` refuse to run without root before writing
  anything, with exit 5 and the full `sudo` line to use, every argument included.
- `nails init` checks the target, the attach gate first, before writing anything, supports `--json`,
  `--hardware-config` and `--no-hardware-config`, reports each item as created or already present,
  and ends with numbered next steps that keep editing off the decoy (prepare `nails.toml` on another
  machine, or as `nails.toml.new` in a hidden session), then `check` and `activate`. On Debian and
  Ubuntu the root overlay's upper is made by the first activation, with the decoy root's mode and
  owner; `storage-readiness` counts that as part of its pass.
- The swap check classifies each device: RAM-only zram passes, swap on dm-crypt with a random key
  warns, and disk or file swap, fixed-key encrypted swap and hibernation are refused. A hidden
  NixOS hardware configuration that NAILS seeds has the decoy's `swapDevices` and `resumeDevice`
  commented out.
- The disk-space check is one floor (`minimum_space_mb`, 500 MB); `rebuild_space_mb` (4096 MB) is
  checked before a hidden NixOS build.
- `nails verify` names the checks it ran and the areas it did not, reports session leftovers, and
  counts only warnings and critical findings in its header. Inside the hidden session it tells the
  session's own files from traces on the decoy: its runtime files, the mounted hidden volume and its
  state make one note, and a NAILS path that the hidden layer holds (on NixOS, the module link
  `nails init` stages) is a note that points to `verify --offline --root` instead of advice to
  delete it. On the decoy, the runtime directory of an interrupted activation is reported once, as
  critical, with `nails recover` as its fix; a read-only disk rule that an unfinished way back left
  says to power off or to remove it as root, and the fixed `/run` paths of an earlier release say to
  power off. The memory note no longer suggests a cold boot: it says to power off (in the hidden
  session, `nails deactivate --poweroff`) and to leave the machine off for a few minutes. `--deep`
  also searches the journal for the tool, the configuration file, `cryptsetup` and the hidden volume
  path, and names sudo's records of your own commands as such: notes while the journal is in RAM,
  warnings when it keeps files on disk. Artifact paths are probed without following links, so a
  leaked link is found even where its target does not resolve.
- On NixOS the hidden `hardware-configuration.nix` wraps the original (kept as
  `hardware-configuration.base.nix`) instead of patching it, a `nix-instantiate --parse` check
  rejects an unparseable configuration, and the hidden NixOS module forces
  `system.autoUpgrade.enable = false`. The base-configuration check (`suspicious-nails-reference`)
  reads every `.nix` file under `/etc/nixos`, following strings, `with` and `let … in` and reading
  comments as code, and refuses a line that names the hidden environment: the hidden volume's mount
  point or device as a whole path (`/mnt/data2` is not `/mnt/data`) and the units systemd names
  after them, in both spellings of an escaped name; what the volume is stored on, unless the decoy's
  own volumes sit on it too: the partition or disk and an image file behind a loop device by their
  paths, every link udev made for them or for the volume's own device (`/dev/disk/by-id`, `by-path`,
  `by-partlabel`, `by-uuid`, `by-label` and the LVM path `/dev/<vg>/<lv>` among them), the
  partition, LUKS and filesystem uuids, and the labels as `LABEL=`, `PARTLABEL=` or a `fileSystems`
  or `swapDevices` entry's `label`; its mapping name where a line opens the volume: a
  `boot.initrd.luks.devices` or `clevis.devices` entry, in nested blocks and in a block commented
  out line by line whose lines are indented at least as deep as its first, the `name` of such an
  entry, `encrypted.label`, crypttab text, `systemd-cryptsetup@<name>.service`, or a word after
  `cryptsetup` and a verb that opens, closes or asks about a mapping (`open`, `create`, `close`,
  `status` and the like), up to the end of the command, continued lines, comments and prose
  included; or NAILS itself. Ordinary configuration passes: the mapping name as an ordinary word
  (`description = "Back up user data"` with the mapping `data`, `cryptsetup` next to it in a package
  list or in prose that puts none of those verbs between `cryptsetup` and the name, or the comment
  `nixos-generate-config` writes above `system.stateVersion`), the decoy's own mapping whose name
  merely ends like the hidden one, and the word `hidden` and options such as `services.plausible`,
  which 0.2 refused. The check does not follow a mapping defined through a `let` binding,
  `lib.listToAttrs` or an interpolated name, and does not know the storage's kernel name without
  `/dev/` (as a udev rule writes it), `/dev/dm-<n>`, `/dev/block/<major>:<minor>` or a path written
  with a doubled slash. A refusal names the file, the line and the text, why it counts and what to
  do; with no `.nix` file under `/etc/nixos`, the check says it inspected nothing. Only `.nix` files
  are read: keep the other files in `/etc/nixos`, and its history where it is a git repository, free
  of the hidden volume too.
- Unsupported hosts are refused before any write, with exit 8: Debian before 13, Ubuntu before
  24.04, non-merged-`/usr` Debian-family layouts, ostree or image-based systems, systems without
  systemd, and distributions not yet validated (Fedora, Arch). Hosts with systemd older than 254
  fail the `systemd-version` check (exit 4). Derivatives whose `ID_LIKE` names debian or ubuntu are
  accepted provisionally.
- A corrupt or unreadable state file is reported as an unknown state: `status` shows it and
  `activate` refuses, instead of treating it as inactive.
- `nails --help` now describes the tool as "Run a hidden session on a decoy Linux system". Sources
  carry SPDX headers, and `REUSE.toml`, `NOTICE` and DCO sign-off guidance are added.
- Vulnerabilities are reported through GitHub private vulnerability reporting first, with
  `security@nails.run` as the fallback; conduct reports go to `contact@nails.run`.
- Releases come from one tag-triggered workflow that checks the tag against the version,
  `Cargo.lock` and this changelog, builds from source, rebuilds on a fresh runner, runs the full
  E2E suite, attests the assets and an SBOM, and drafts the release with this section as its
  notes. `docs/verify-release.md` explains how to verify the assets.
- Development: the library is split into crates along the session's boundaries, unsafe
  code is denied outside scoped, commented sites, the toolchain is pinned in
  `rust-toolchain.toml` (1.93.0), the flake pins nixos-unstable of 2026-10-11, and a `justfile` is
  the single source of local and CI commands. The VM tests cover the session on NixOS, Debian 13
  and Ubuntu 24.04, with host-side checks of the decoy disk image.
- CI: one required `gate` check per pull request, E2E VM tests on GitHub-hosted runners (affected
  tests per pull request, the full suite on `main` and nightly), scheduled advisory, stress,
  mutation and benchmark jobs, and dependency checks through cargo-deny only.

### Removed

- The per-directory live overlays (`/etc`, `/home`, `/var`, … on the running decoy) and everything
  that served them: process detection, restart and kill, the display-manager restart, the
  overlay pivot, the shell-history cleaner, the shell prompt marker and terminal colour scheme, and
  the desktop notifications after activation with their XDG autostart entry.
- The `notify-dispatch` command; the `activate` flags `--no-clear-history`, `--kill-session`,
  `--no-kill-session`, `--accept-pivot-risks`, `--no-pivot` and `--interactive`;
  `deactivate --no-clear-history`; `emergency --no-countdown` (emergency now acts at once); and the
  per-command `--plain` and `--no-color` flags and the global `--no-logs`.
- The configuration keys `overlays`, `overlay_mode`, `overlay_exclusions`,
  `overlay_exclusions_remove`, `extended_overlays` and the ephemeral overlays, `clear_history`,
  `color_scheme`, `preflight_checks`, `default_verbosity`, `color_output`, `verify_on_deactivate`,
  `milestone_tips`, `max_log_size_mb` and `retention_days`.
- The XOR string obfuscation: the binary is identifiable, and the documentation says so.
- `docs/USER-SECURITY-GUIDE.md` and `docs/vulnerability-handling.md`, replaced by the operator
  guide, the threat model and `SECURITY.md`.

### Fixed

- On NixOS, `activate`, `deactivate` and `emergency` work when a systemd unit starts them (a panic
  key, `systemd-run`): the Nix tools are found in the root-owned system directories when the
  caller's `PATH` lacks them, and a legacy build without `NIX_PATH` takes `nixpkgs` from root's
  `nixos` channel.
- Pre-flight results are reported once and honour `--quiet` and `--json`.
- Updated dependencies to clear the RUSTSEC advisories that affect the shipped binary (anyhow,
  crossbeam-epoch) and restored the Nix release build
  ([#54](https://github.com/WitteShadovv/nails/pull/54)).

### Security

- Nothing NAILS writes reaches the decoy: the state file, its lock, logs, reports and staged
  configuration are written only onto an attached hidden root, through `openat2` beneath it, so a
  planted symlink or `..` cannot redirect them; log files are created mode 0600, and a panic goes
  to the hidden-root log, not stderr.
- Commands NAILS starts run from a cleared environment with a fixed, root-owned `PATH`, so a
  caller's `PATH` or `NIX_*` cannot steer which binaries a root child runs.
- The release binary carries no test hook: test-only code compiles only under a non-default
  `test-hooks` feature.
- The release binary links the musl of the pinned nixpkgs (1.2.6, with nixpkgs' patches for
  CVE-2026-6042 and CVE-2026-40200) instead of the musl 1.2.5 that ships with the Rust toolchain,
  so the musl the release SBOM names is the one in the binary. The build fails if its linker map
  shows `libc.a` or one of musl's crt files from anywhere else.
- The release binary no longer refers to the Rust toolchain that built it, so installing the
  `nails` package through Nix no longer keeps the toolchain (about 2.6 GB) alive.
- The release SBOM records the CVEs that nixpkgs patches musl against as backported fixes in the
  musl component's `pedigree` and gives musl its CPE. A new attested release asset,
  `musl.openvex.json`, marks those CVEs as fixed; scan with
  `grype sbom:sbom.cdx.json --vex musl.openvex.json`.
- The way back keeps the network state the hidden session set up: its links, addresses, routes and
  VPN tunnels stay up in the decoy until power-off, the decoy's NetworkManager records a link it
  adopts, with the time, in `/var/lib/NetworkManager/timestamps` as soon as the decoy starts, the
  random MAC address of the network-identity snippet can stay on the decoy's device, and so can the
  hidden hostname on a decoy without `/etc/hostname`. Take down the connections and tunnels you
  brought up and delete the links you created before deactivating, or end with
  `deactivate --poweroff`; end a session that used the network-identity snippet with
  `deactivate --poweroff` (or `emergency --poweroff`).

## [0.2.0] - 2026-05-08

### Changed

- Bumped the Rust workspace version to `0.2.0`.
- Hardened release publication around immutable tag-based workflows: exact stable tags are
  verification-only, stable publication is deliberate/manual, and prerelease publication is tied to
  suffixed prerelease tags.
- Refined release workflow permissions and repository targeting so GitHub release automation works
  reliably under repository rulesets.

### Fixed

- Created `state.json` during `nails init` and preflight when needed, preventing init/preflight
  flows from missing expected state metadata.
- Fixed release workflow regressions after the immutable-release restructuring.

## [0.1.0] - 2026-04-27

### Added

- Established the Rust workspace split between `nails-cli` and `nails-core`, including shared
  workspace metadata, custom error types, a filesystem abstraction for testing, and the initial
  quality-gate infrastructure.
- Implemented the core lifecycle model: typed state transitions, state-file serialization,
  checksummed state metadata, RAII state guards, and the `NailsManager` orchestration layer.
- Added the preflight validation system with checks for hidden storage readiness, swap exposure,
  available space, overlay directories, current state, NixOS configuration, symlink support, and
  selected flake build targets.
- Implemented activation support for OverlayFS-based hidden sessions, NixOS configuration overlays,
  deterministic mount ordering, reverse-order rollback, process/session handling, display-manager
  restart behavior, and NixOS build/switch integration.
- Added support for flake-based activation via `--flake`, config-fingerprint fast paths,
  missing-only build paths, automatic overlay strategy selection, `/var` overlays, optional `/boot`
  pivoting, and bind-mounted fallbacks for overlay-incompatible targets.
- Implemented deactivation and emergency cleanup flows, including standard reboot-based cleanup,
  emergency no-reboot cleanup, force-unmount fallback behavior, cleanup reporting, and post-cleanup
  verification hooks.
- Added user-facing commands and output for status reporting, verification scans, emergency
  deactivation, progress indicators, verbosity controls, no-color handling, desktop notifications,
  and notification dispatch.
- Added shell integration and forensic-safety support, including prompt/alias management,
  in-memory and on-disk history cleanup, automatic terminal color-scheme switching, structured
  logging, sanitized log paths, and timestamp-based log rotation.
- Added Nix-based end-to-end validation infrastructure covering the basic workflow, emergency
  deactivation, forensic cleanliness, snapshot diffs, and performance scenarios.
- Added reproducible Nix release packaging for the canonical Linux artifact, checksum generation,
  SBOM/supply-chain checks, dependency auditing, coverage gates, and release-path verification.
- Added public project documentation and governance files, including release reproducibility
  guidance, CI documentation, support and security policies, issue templates, code of conduct,
  roadmap updates, and public README guidance.

### Changed

- Migrated the project surface from early prototype planning into a Rust-first implementation with a
  focused CLI crate and domain-oriented core library.
- Refactored the CLI and core library into focused modules for activation, deactivation, cleanup,
  config, filesystem access, logging, manager orchestration, NixOS integration, overlays,
  preflight checks, shell integration, state, status, and verification.
- Reworked CI from the initial pipeline into consolidated, cached workflows using `cargo-llvm-cov`,
  pinned tooling, reusable release/reproducibility jobs, and trusted full E2E validation.
- Replaced deprecated `serde_yaml` usage with `serde-saphyr` and refreshed Rust/GitHub Actions
  dependencies, including `thiserror`, `colored`, `signal-hook`, and Node.js 24-compatible actions.
- Aligned public documentation with the current alpha threat model, release process, support scope,
  NAILS OS separation, artifact format, and AI-assisted development disclosure.

### Removed

- Removed the legacy Python implementation after the Rust migration became the maintained code path.

### Fixed

- Hardened activation and deactivation around partial overlays, same-device submounts, overlay
  permission mismatches, display-manager restart timing, NixOS generation switching, fast-path
  activation, and deactivation base-configuration checks.
- Hardened hidden configuration and hardware-configuration handling to fail earlier and avoid unsafe
  or ambiguous activation states.
- Improved forensic cleanup by addressing shell-history persistence, alias stdout leakage,
  cleanup/log formatting, temporary-file cleanup, and post-deactivation artifact checks.
- Stabilized E2E and unit coverage by serializing fragile switch-to-configuration tests, moving real
  filesystem tests into test-only paths, expanding activation/deactivation guard coverage, and
  bringing measured coverage above the documented threshold.
- Fixed release and CI regressions around workflow permissions, reproducibility comparisons,
  GitHub CLI repository targeting, artifact naming, release tag handling, cargo-sbom output format,
  Dependabot configuration, and pre-commit coverage parity.

### Security

- Added comprehensive shell-history protection and cleanup verification for forensic-safety goals.
- Added SBOM generation, dependency/security audit workflows, cargo-geiger integration, and public
  vulnerability-handling documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for public contribution guidance.

[Unreleased]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.3...HEAD
[0.3.0-rc.3]: https://github.com/WitteShadovv/nails/compare/v0.3.0-rc.2...v0.3.0-rc.3
[0.3.0-rc.2]: https://github.com/WitteShadovv/nails/compare/v0.2.0...v0.3.0-rc.2
[0.2.0]: https://github.com/WitteShadovv/nails/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WitteShadovv/nails/releases/tag/v0.1.0
