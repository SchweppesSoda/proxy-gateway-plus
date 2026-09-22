# 2026-09-22 WLOC retirement

The user requested removal when unavailable on iOS 27. The [WLOC website](https://wloc.app/)
reports that iOS 27 beta 6 and later certificate restrictions currently block its workflow.
This gateway also relies on Apple location MITM; that is a compatibility inference, not a
fresh device test or a claim about every iOS 27 build. Historical iOS 26 success remains historical.

The Bot no longer offers WLOC. Stale callbacks and direct mutation functions refuse without
writing stored locations or invoking services. Restored enabled configuration cannot register
the plugin or add Apple location interception routes. New installs, updates and platform repair
do not install the WLOC-specific module. The generic MITM host/CA and transaction resources stay:
the shared force-hijack sequence also serves ordinary proxy rules and must not be removed.

Doctor fails on an old enabled flag, Apple location domains in the MITM DNS list, or matching
MITM-OUT core routes; unreadable/malformed state is not a successful retirement. It reports only
residue categories. Private locations, CA material, snapshots and frozen history are preserved.
The prior notification and rule-status fixes remain in this branch.

## Deployment gate

This local patch does not clean or stop a running server. Before replacing live code, the authorized
operator must preserve rollback material, disable the existing WLOC plugin using the old validated
transaction, verify both Apple domains are absent from the active DNS/core interception and confirm
normal DNS/proxy service. Stop the old WLOC-serving process before replacing it. If cleanup fails,
stop deployment; do not report source retirement as runtime completion. Do not delete locations/CA
or disable shared force-hijack/proxy features. A later backup restore must pass the same residue gate.
An old full-software rollback remains historical code and is not evidence of a safe current release.

## Validation scope

The offline retirement regression covers direct functions, stale callbacks, restored config,
domain filtering, preservation of other plugin routes, and doctor residue/error reporting. Shared
platform and wording checks are updated for retirement. Former WLOC-enable/transaction/hotload E2E
jobs are replaced by the retirement regression; their files and codec history remain for archaeology.
The platform-switch E2E now seeds a synthetic historical residue instead of enabling the retired API.
Shell/YAML/Python syntax and local links are checked. Linux service/platform E2E, real certificates,
live cleanup and iOS compatibility have not run in this Windows local step. No push or deployment.
