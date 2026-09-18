"""TTL clamp lattice (Ch. 25 / A2, table-driven per Ch. 58)."""

import pytest

from keystone.broker.ttl import TTL_CEILING, TTL_FLOOR, TtlDecision, TtlExceedsAllowed, clamp_ttl


@pytest.mark.parametrize(
    ("requested", "policy_cap", "registry_max", "expected"),
    [
        (None, 3600, 3600, TtlDecision(900, False, False)),  # default is the floor
        (900, 3600, 3600, TtlDecision(900, False, False)),
        (1800, 3600, 3600, TtlDecision(1800, False, False)),
        (3600, 3600, 3600, TtlDecision(3600, False, False)),
        (3600, 1800, 3600, TtlDecision(1800, True, False)),  # policy cap wins
        (3600, 3600, 1200, TtlDecision(1200, True, False)),  # registry max wins
        (3000, 1800, 1200, TtlDecision(1200, True, False)),  # tightest of the three
        (1, 3600, 3600, TtlDecision(900, False, True)),  # below floor is raised
        (899, 900, 900, TtlDecision(900, False, True)),
        (86400, 3600, 3600, TtlDecision(3600, True, False)),  # API max input clamps to ceiling
        (0, 900, 900, TtlDecision(900, False, True)),
    ],
)
def test_clamp_lattice(
    requested: int | None, policy_cap: int, registry_max: int, expected: TtlDecision
) -> None:
    assert clamp_ttl(requested, policy_cap=policy_cap, registry_max=registry_max) == expected


def test_effective_never_leaves_the_physical_bounds() -> None:
    for requested in (None, -5, 0, 1, 899, 900, 901, 3599, 3600, 3601, 10**9):
        for cap in (900, 1234, 3600):
            for reg in (900, 2000, 3600):
                effective = clamp_ttl(requested, policy_cap=cap, registry_max=reg).effective
                assert TTL_FLOOR <= effective <= min(cap, reg, TTL_CEILING)


def test_strict_mode_denies_instead_of_clamping() -> None:
    with pytest.raises(TtlExceedsAllowed) as info:
        clamp_ttl(3600, policy_cap=1800, registry_max=3600, deny_on_excess=True)
    assert (info.value.requested, info.value.allowed) == (3600, 1800)
    # Raising to the floor is not an excess and is never denied.
    assert clamp_ttl(10, policy_cap=1800, registry_max=3600, deny_on_excess=True).raised


@pytest.mark.parametrize(
    ("policy_cap", "registry_max"), [(899, 3600), (3601, 3600), (3600, 0), (3600, 3601)]
)
def test_out_of_range_caps_are_registry_or_policy_bugs(policy_cap: int, registry_max: int) -> None:
    with pytest.raises(ValueError, match=r"\[900, 3600\]"):
        clamp_ttl(900, policy_cap=policy_cap, registry_max=registry_max)
