// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Session-residue rows for the decoy's own services and mechanisms that act
//! across a switch: what they do when the service manager starts again in the
//! hidden root, and what they record about the hidden session where NAILS
//! cannot reach it. Data only; [`super`] appends them to the catalog after
//! the rows of [`super::session`], before the setup traces.

use crate::residue_catalog::{Channel, E2e, Platforms, Probe, ResidueClass, ResidueKind};

/// The decoy's services and mechanisms, in the order the catalog lists them.
pub(super) const ROWS: &[ResidueClass] = &[
    ResidueClass {
        id: "pending-offline-update",
        title: "Pending offline update",
        kind: ResidueKind::Session,
        channel: Channel::Mechanism(
            "systemd's offline updates: a /system-update or /etc/system-update link to a staged update makes the next start of the service manager, a soft-reboot's included, start system-update.target instead of the default target",
        ),
        platforms: Platforms::ALL,
        risk: "A soft-reboot starts the service manager again, and its generators run in the new root as at a boot. A link the hidden root shows, the decoy's own or one a session staged in the upper, would turn the start of the hidden session into the update: the decoy's updater would install it into the upper on the hidden volume and then reboot or power off the machine, ending the session without its way back. That run deletes the link only in the upper, so the decoy keeps its own and installs the update itself at its next boot. A link a session stages stays in the upper: the way back is a soft-reboot into the decoy root, which does not show it, so the decoy starts as usual.",
        preflight: Probe::Check("pending-offline-update"),
        preflight_blocks: true,
        verify: Probe::None(
            "an update staged on the decoy is the decoy's own state, not a trace of a session, and one a session staged sits in the upper, where activation finds it",
        ),
        mitigation: "Activation refuses while a link is staged on the decoy or in the upper: install or cancel the decoy's pending update before activating, and delete a link a session staged with `nails discard`.",
        doc_anchor: "decoy-requirements.md#pending-offline-updates",
        e2e: E2e::Test("preflight-checks"),
        residual: false,
        conclusion: None,
    },
    ResidueClass {
        id: "sssd-domain-records",
        title: "sssd and the domain controller's records",
        kind: ResidueKind::Session,
        channel: Channel::Mechanism(
            "the domain controller's own records of the logins and account lookups sssd makes on a decoy joined to a domain, and sssd's caches under /var/lib/sss and logs under /var/log/sssd",
        ),
        platforms: Platforms::ALL,
        risk: "On a decoy joined to a domain (Active Directory or FreeIPA, through sssd) the hidden session's logins and account lookups reach the domain controller as the decoy's do, and the controller keeps its own records of them, with their times, where nothing NAILS does reaches them. In the hidden session sssd's caches and logs land in the upper; the decoy's own sssd, stopped before the switch and started again after the way back, logs both under /var/log/sssd on the decoy disk by default, as at any shutdown and boot.",
        preflight: Probe::Check("decoy-persistence"),
        preflight_blocks: false,
        verify: Probe::None(
            "the domain controller keeps its records on the controller, out of reach of any scan of this computer",
        ),
        mitigation: "NAILS is not tested on decoys joined to a domain; check and activation warn while sssd is in use on the decoy. Use a decoy that is not joined to a domain, and where nothing on it needs sssd, disable it.",
        doc_anchor: "decoy-requirements.md#decoys-joined-to-a-domain",
        e2e: E2e::None("no VM test runs a domain controller; the warning is unit-tested"),
        residual: true,
        conclusion: None,
    },
];
