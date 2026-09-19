"""Admission stop for native P1 experiments until real lifetime coverage exists.

An ordinary reservation ID/expiry or heartbeat does not establish a demand floor
retained through restore and verified Job empty. No trusted provider currently
exists. There is deliberately no environment, CLI, receipt or injection unlock.
"""


class ContinuousAdmissionUnavailable(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def require_continuous_admission() -> None:
    """Reject new experiments; restore-only paths must remain available."""
    raise ContinuousAdmissionUnavailable("continuous_admission_provider_unavailable")
