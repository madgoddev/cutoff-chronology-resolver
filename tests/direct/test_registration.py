"""CutoffChronologyResolver registration tests."""

from __future__ import annotations

import pytest

from fixtures.chronologies import (
    CHRONOLOGY_KEY,
    CUTOFF_UNIX,
    EVIDENCE_TEXT,
    POLICY_VERSION,
    PROPOSITION,
    REGISTRATION_DATETIME,
    TIMESTAMP_RULE,
    build_fingerprint,
)
from tests.conftest import CONTRACT_PATH, DIRECT_SDK_VERSION


def register(contract, **overrides):
    values = {
        "chronology_key": CHRONOLOGY_KEY,
        "proposition": PROPOSITION,
        "cutoff_unix": CUTOFF_UNIX,
        "timestamp_rule": TIMESTAMP_RULE,
        "evidence_text": EVIDENCE_TEXT,
    }
    values.update(overrides)
    return contract.register_chronology(**values)


def test_policy_and_constructor(chronologyresolver, direct_alice):
    policy = chronologyresolver.get_policy()
    assert policy["owner"].lower() == f"0x{bytes(direct_alice).hex()}"
    assert policy["policy_version"] == POLICY_VERSION
    assert policy["strict_before_semantics"] is True
    assert policy["event_at_cutoff_is_after"] is True


def test_zero_policy_rejected(direct_vm, direct_deploy, direct_alice):
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("invalid_policy_version"):
        direct_deploy(str(CONTRACT_PATH), 0, sdk_version=DIRECT_SDK_VERSION)


def test_register_and_fingerprint(chronologyresolver, direct_alice):
    chronology_id = register(chronologyresolver)
    record = chronologyresolver.get_chronology(chronology_id)
    creator = f"0x{bytes(direct_alice).hex()}"
    assert chronology_id == f"{creator}:{CHRONOLOGY_KEY}"
    assert record["chronology_fingerprint"] == build_fingerprint(creator)
    assert record["registered_at"] == REGISTRATION_DATETIME
    assert chronologyresolver.get_chronology_count() == 1


def test_normalized_duplicate_idempotent(chronologyresolver):
    first = register(chronologyresolver)
    second = register(
        chronologyresolver,
        chronology_key=f" {CHRONOLOGY_KEY.lower()} ",
        proposition=f"\r\n{PROPOSITION}\r\n",
    )
    assert first == second
    assert chronologyresolver.get_chronology_count() == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("proposition", PROPOSITION + " Changed."),
        ("cutoff_unix", CUTOFF_UNIX + 1),
        ("timestamp_rule", TIMESTAMP_RULE + " Changed."),
        ("evidence_text", EVIDENCE_TEXT + " Changed."),
    ],
)
def test_same_key_changed_core_rejected(chronologyresolver, direct_vm, field, value):
    register(chronologyresolver)
    with direct_vm.expect_revert("chronology_registration_conflict"):
        register(chronologyresolver, **{field: value})


def test_creator_scoped_ids(chronologyresolver, direct_vm, direct_bob):
    first = register(chronologyresolver)
    direct_vm.sender = direct_bob
    second = register(chronologyresolver)
    assert first != second


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"chronology_key": ""}, "invalid_chronology_key"),
        ({"chronology_key": "BAD KEY"}, "invalid_chronology_key"),
        ({"chronology_key": "X" * 49}, "invalid_chronology_key"),
        ({"proposition": "short"}, "invalid_proposition"),
        ({"cutoff_unix": 0}, "invalid_cutoff_unix"),
        ({"cutoff_unix": 4_102_444_801}, "invalid_cutoff_unix"),
        ({"timestamp_rule": "short"}, "invalid_timestamp_rule"),
        ({"evidence_text": "short"}, "invalid_evidence_text"),
        ({"evidence_text": "Evidence with a forbidden\ttab here."}, "invalid_evidence_text"),
    ],
)
def test_invalid_registration_rejected(chronologyresolver, direct_vm, overrides, message):
    with direct_vm.expect_revert(message):
        register(chronologyresolver, **overrides)


def test_missing_and_bounds(chronologyresolver, direct_vm):
    with direct_vm.expect_revert("chronology_not_registered"):
        chronologyresolver.get_chronology("missing")
    with direct_vm.expect_revert("chronology_index_out_of_bounds"):
        chronologyresolver.get_chronology_id(0)

