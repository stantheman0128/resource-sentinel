# Exemption session visibility checkpoint — 2026-09-19

## Goal and verified root cause

Show sessions occupying temporary exemption slots directly on the dashboard while preserving authorization, original deadlines and the three-slot cap.

The production read-only lease query and published `data.js` both contained one occupied lease. Its `owner_metadata` was empty, so no session label was available. The installed dashboard matched the protected main source, but `dashboard/dashboard.html` placed the entire lease table inside a default-collapsed `details` element. There was no evidence of an active-lease filter or publication schema mismatch.

## Isolated changes

- `dashboard/dashboard.html`: show up to three `occupies_slot === true` cards outside collapsed details, including known session name, agent, project and original expiry. Missing names explicitly say `尚未記錄 session 名稱` with a process label/PID. Exited processes still appear while their lease occupies a slot; expired/revoked rows remain in the details/history. Escape all display metadata.
- `tests/test_change_dashboard.cjs`: fixtures cover visible occupied cards, unknown labels, original expiry, expired/revoked exclusion from cards, the three-card bound and escaped metadata.
- `sentinel/attribution.py` and `sentinel/dashboard.py`: a display-only Claude fallback reads the registry for the exact lease PID. A held native process handle, full native FILETIME and its exact lease birth-time conversion establish the identity before exposing registry session ID/name and project basename. Existing recorded metadata takes precedence. Missing, dead, malformed, reused or unverifiable identities remain unrecorded. The fallback does not write the lease database or change grant state, occupancy or deadlines.
- Backend coverage includes 18 identity/fallback tests, including held-handle cleanup, exact legacy timestamp conversion, bounded lookups and unchanged fixture DB bytes.

The bounded investigation read only the exact PID's Claude session registry JSON, not transcripts, prompts, authentication key files or environment values. No session title is copied into this checkpoint.

## Backups and integration boundary

Implementation edits are isolated in `.worktrees/adaptive-scheduler-implementation`. The initial `.local-adaptive/dashboard-exemptions-before.html` preserves the older implementation copy; it is not the live baseline. The additional `.local-adaptive/dashboard-exemptions-live-before.html` preserves protected main with SHA-256 `71BD11BCCAE44838C983CA517346A08587C3019AD098859A55658E8D3C34A938`. Both initial and live-before test backups have SHA-256 `A7B017F39CD6B43E13401EC0235C585FEFFB50F01F689268BABA883F05B39F0B`.

The dashboard/attribution dependency baseline includes preexisting dirty or
untracked work: do not wholesale stage those files or treat the full diff against
HEAD as this task's patch. The display implementation and tests remain as local
changes in both working trees; only this new evidence document is independently
committable. Preserve unrelated disk/P1 implementation changes.

## Validation and activation

- Normal admission: P2, 1 CPU unit, 0.5 GiB RAM, zero heavy-I/O slots; no exemption.
- `py -m unittest tests.test_claude_session_attribution tests.test_dashboard_observability tests.test_exemptions`: **51 tests passed**, 69.857 seconds, exit 0, no skips/failures/errors.
- `node tests/test_change_dashboard.cjs`: passed; rerun with the installed `data.js` also passed, including full rendering without errors.
- Real read-only lookup of the occupied Claude lease returned a name only after exact native identity verification. The title itself is omitted from public evidence.
- Applied only the two display backend modules, HTML and their tests after all six base-file checks matched the protected original bytes. Installed HTML SHA-256 is `417366281da86ec66088d85c07173cbcd8b2484a5880cfac217486beab69740f`, matching the tested source. Private before copies and the activation manifest are preserved.
- Two advancing collector publications (05:32:50 and 05:34:20) contain the verified session name from `claude_session_registry`; occupancy remains **1/3** and the original expiry exactly matches the live read-only lease row. Second completion: 05:34:22, health healthy/stable, recovery streak 17.
- No grant was created, renewed, revoked or edited. No Scheduled Task restart or runtime configuration change was needed. Adaptive remains off; the separate disk collector patch is not activated.

This confirms live publication and tested rendering, not browser visual
acceptance. File-URL browser navigation remained unavailable and was not bypassed.
Reloading an already-open dashboard once loads the new HTML. Subsequent data
updates use the existing refresh behavior.

## Remaining integration boundary

The requested local display fix is active. A clean checkout of the implementation
branch does not yet contain the preexisting uncommitted dashboard/attribution
baseline. Integrate that baseline through its own reviewed commit before trying
to publish this dependent source delta; do not silently scoop it into an adaptive
commit. Original empty-metadata leases can use the verified Claude fallback;
partially recorded metadata remains authoritative and is not merged automatically.
