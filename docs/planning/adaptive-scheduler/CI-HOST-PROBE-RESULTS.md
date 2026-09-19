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

The first remote result will be recorded after the reviewed source is pushed
and the exact-commit workflow completes. No remote execution is claimed here.

## Official contracts

- [Workflow selection for push events](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows)
- [Hosted runner environment](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners)
- [Workflow permissions and timeouts](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)
- [QueryInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)
- [GetProcessAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessaffinitymask)
