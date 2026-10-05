# Local CPU admission reserve

On this 12-logical-CPU Windows host, Resource Sentinel's local admission budget is 10.8 CPU units, leaving 1.2 units (10%) outside the managed-work budget. The live setting is `local_allocatable_cpu` in `%USERPROFILE%\.resource-sentinel\config.json`; the collector and local worker bootstrap use the same value by default.

This is an admission budget, not a Windows-enforced CPU cap. Resource Sentinel continues to measure actual CPU pressure independently, and each request still needs enough capacity under the current measurements.
