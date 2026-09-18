"""TTL clamp — spec Ch. 25 / A2. The 3600 s ceiling is physical (role chaining), never tunable."""

from dataclasses import dataclass

TTL_FLOOR = 900
TTL_DEFAULT = 900
TTL_CEILING = 3600


class TtlExceedsAllowed(Exception):
    """Raised only when the grant opts into strict mode (`deny_on_ttl_excess`)."""

    def __init__(self, requested: int, allowed: int) -> None:
        super().__init__(f"requested ttl {requested}s exceeds allowed {allowed}s")
        self.requested = requested
        self.allowed = allowed


@dataclass(frozen=True, slots=True)
class TtlDecision:
    effective: int
    clamped: bool
    raised: bool


def clamp_ttl(
    requested: int | None,
    *,
    policy_cap: int,
    registry_max: int,
    deny_on_excess: bool = False,
) -> TtlDecision:
    if not TTL_FLOOR <= policy_cap <= TTL_CEILING or not TTL_FLOOR <= registry_max <= TTL_CEILING:
        raise ValueError("policy_cap and registry_max must both lie within [900, 3600]")
    allowed = min(policy_cap, registry_max, TTL_CEILING)
    wanted = TTL_DEFAULT if requested is None else requested
    if wanted < TTL_FLOOR:
        return TtlDecision(effective=TTL_FLOOR, clamped=False, raised=True)
    if wanted > allowed:
        if deny_on_excess:
            raise TtlExceedsAllowed(wanted, allowed)
        return TtlDecision(effective=allowed, clamped=True, raised=False)
    return TtlDecision(effective=wanted, clamped=False, raised=False)
