# Protected live dashboard compatibility

`live-dashboard-p2.patch` contains this implementation task's narrow compatibility changes to three preexisting, uncommitted source files. It does **not** contain or publish those full files and is **not applicable to a clean repository HEAD**. The protected local dashboard/attribution baseline must already exist and match the accompanying manifest before hashes.

The patch preserves the new standalone display module's API through local attribution re-exports and a dashboard lease adapter. It also changes the resource-v2 admission preview to use the same frame, allocation projection and blockers as Coordinator and Maintainer. Logical CPU count is captured before the read transaction; the shared allocation projection and per-request checks use that single read-only transaction. Reservation age, expiry, missing observed owners, and local worker aliases do not remove ledger demand. Independent queued Commit requirements remain independent. An invalid ledger makes the observation unknown. Legacy preview behavior remains separate and retains its previous grace/pool calculations.

Fixture changes preserve the original failing blocker-parity assertion. The older routed fixture is upgraded to the actual Maintainer schema with explicit local/remote locality. New cases cover a retained expired bound allocation floor, aged local aliases across pools, missing locality, independent Commit demand, a read-only transaction with OS inputs already collected, and preserved legacy behavior. Two exemption display expectations separately adopt `identity_mismatch` and `identity_unknown` in place of inferring process exit from incomplete observations. These are intentional accuracy corrections, not a reclassification of the historical P0 baseline.

The manifest records raw file hashes and UTF-8/LF-normalized hashes. Apply only to private copies of the three exact protected baselines, verify the normalized after hashes, and run the targeted tests before considering any integration. The new `lease_display`, shared accounting, adaptive contracts/store, and P2 Coordinator/Maintainer source dependencies must be present. This artifact neither installs those dependencies nor performs runtime activation.

This source-only patch excludes configuration, environment variables, databases, runtime logs and unrelated working-tree diffs. Private before copies and complete local evidence remain outside Git. Full baseline files must not be staged merely to make this patch directly applicable to HEAD.

Root verification passed: applying the patch to private copies of all three
manifest-matched baselines reconstructed the exact normalized after hashes and
current sources. The final live-baseline suite passed 279 tests and the complete
Node dashboard renderer suite. Git may emit CRLF for the reconstructed files;
use the explicitly recorded LF-normalized hashes for that comparison. Blank
context lines in the unified patch retain their required single-space prefix;
they are patch syntax, not trailing whitespace introduced into Python source.
