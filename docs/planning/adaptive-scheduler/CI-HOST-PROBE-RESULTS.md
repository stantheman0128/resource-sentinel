# Existing Windows CI host observation

This is a P1 prerequisite observation, not an S1/S2/S3 capability pass or a
production deployment. Adaptive remains off. The continuous-admission guard
and existing native experiment entrypoints are unchanged.

## Scope and authorization

The formal plan's section 12.1 permits one existing Windows CI environment.
The repository's existing GitHub Actions service was verified enabled, with no
previous workflows. This probe uses its standard `windows-2025` hosted runner;
it does not install a CI platform, service, shell, VM or self-hosted runner on
the user's machine. Only the implementation branch triggers the workflow, and
only changes to that workflow or its probe script trigger another observation.

The workflow has a five-minute job deadline, one-minute observation step,
read-only repository token and immutable checkout action pin. It uses the
preinstalled Python and does not install packages, read secrets, upload
artifacts, create Jobs, create Scheduled Tasks or write OS controls. Standard
GitHub checkout/setup logs remain public. The probe's own stdout contains only
allowlisted OS/version, image, processor/affinity and Job/session booleans,
numeric CPU flags and error codes. It does not collect SID, logon LUID, process
identity, command lines, private paths, configuration, databases or environment
dumps.

## Interpretation

- A valid observation may report an unsupported host; exit 0 means observation
  completed, not that a capability gate passed.
- `in_any_job=true` remains a foreign/unknown Job blocker, even if the immediate
  Job's CPU flags are zero. A NULL `QueryInformationJobObject` query sees only
  the immediate Job, not every ancestor's constraints.
- Unknown membership, affinity or processor shape cannot make a candidate.
- `topology_candidate=true` only identifies a candidate for further checks.
  It does not establish interactive-desktop behavior, continuous capacity
  accounting, Job-list launch, effective throttling, recovery or an allowlist.
- No result from this workflow unlocks native tests or production enrollment.

## Validation and result

On Windows 11 x64 / Python 3.13.3, through normal Sentinel P2 admission:

```text
py -X utf8 -m unittest tests.test_adaptive_ci_host_probe -v
9 passed; 0 failures/errors/skips; 0.002 seconds
```

These are portable report/redaction tests. They cover missing and mistyped
observations, restricted affinity/groups, inherited Jobs with zero CPU flags,
exception redaction, unsupported platforms and the distinction between a
successful observation and capability authority. They are not native evidence.

The first remote observation completed at 2026-09-19 22:09:23 UTC
(2026-09-20 06:09:23 Asia/Taipei), on exact source
`b590b276fcc778f8ed5965a39b7e0ec592a8dfef`:

[GitHub Actions run 35472488128](https://github.com/stantheman0128/resource-sentinel/actions/runs/35472488128)

| Field | Observed result |
|---|---|
| Workflow | Completed / success; valid observation, not capability success |
| OS | Windows Server 2025, build 26100 |
| Runner image in setup log | `windows-2025-vs2026`, `20260907.229.1` |
| Python | 3.12.10, 64-bit |
| Processor topology | 1 group, 4 logical processors |
| Process/system affinity | 15 / 15 |
| In any Job | **true** |
| Immediate Job CPU flags | 0; ancestor chain still unknown |
| Session zero | false; does not independently prove interactive context |
| Native query errors | None |
| Topology candidate | **false**: `foreign_or_unknown_parent_job` |
| P1 / continuous admission / interactive verification | All false |
| New OS control writes / created test Jobs | None |

The script's `runner_image_os` is null because the observed image alias is
outside its intentionally narrow environment-value allowlist. The official
runner setup log supplies the image label above; no broader environment dump
was used. The image version was returned by the probe as well.

This existing Windows CI route therefore does not resolve the unknown-parent
blocker. S1/S2/S3 remain unrun here. No breakaway, parent substitution, nested
Sentinel Job or CI configuration workaround was attempted. Further native
promotion needs a supported launch host plus real continuous admission and
recovery custody; a valid observation alone supplies neither.

## Official contracts

- [Workflow selection for push events](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows)
- [Hosted runner environment](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners)
- [Workflow permissions and timeouts](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)
- [QueryInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)
- [GetProcessAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessaffinitymask)
