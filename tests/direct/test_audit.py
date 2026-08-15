"""CutoffChronologyResolver audit and gate tests."""

from __future__ import annotations

import json

import pytest

from fixtures.chronologies import BEFORE_RESPONSE, CUTOFF_UNIX, build_fingerprint
from tests.direct.test_registration import register

LLM_PATTERN = r"independent event-chronology auditor"


def mock(direct_vm, response):
    direct_vm.mock_llm(LLM_PATTERN, json.dumps(response))


def test_before_cutoff_and_gate(chronologyresolver, direct_vm):
    chronology_id = register(chronologyresolver)
    mock(direct_vm, BEFORE_RESPONSE)
    chronologyresolver.resolve_chronology(chronology_id)
    record = chronologyresolver.get_chronology(chronology_id)
    audit = chronologyresolver.get_audit(chronology_id)
    assert audit["verdict"] == "BEFORE_CUTOFF"
    assert audit["event_time_unix"] < CUTOFF_UNIX
    assert chronologyresolver.matches_verdict(
        chronology_id, record["chronology_fingerprint"], "BEFORE_CUTOFF"
    ) is True


@pytest.mark.parametrize(
    ("event_time", "verdict"),
    [(CUTOFF_UNIX - 1, "BEFORE_CUTOFF"), (CUTOFF_UNIX, "AFTER_CUTOFF"), (CUTOFF_UNIX + 1, "AFTER_CUTOFF")],
)
def test_strict_cutoff_boundary(chronologyresolver, direct_vm, event_time, verdict):
    chronology_id = register(chronologyresolver, chronology_key=f"BOUNDARY-{event_time}")
    mock(
        direct_vm,
        {
            "finding": "EVENT_FOUND",
            "event_time_unix": event_time,
            "publication_time_unix": event_time + 100,
            "issue_codes": [],
        },
    )
    chronologyresolver.resolve_chronology(chronology_id)
    assert chronologyresolver.get_audit(chronology_id)["verdict"] == verdict


def test_no_event_and_indeterminate(chronologyresolver, direct_vm):
    no_event_id = register(chronologyresolver, chronology_key="NO-EVENT")
    mock(
        direct_vm,
        {
            "finding": "NO_QUALIFYING_EVENT",
            "event_time_unix": 0,
            "publication_time_unix": 0,
            "issue_codes": [],
        },
    )
    chronologyresolver.resolve_chronology(no_event_id)
    assert chronologyresolver.get_audit(no_event_id)["verdict"] == "NO_QUALIFYING_EVENT"

    direct_vm.clear_mocks()
    uncertain_id = register(chronologyresolver, chronology_key="UNCERTAIN")
    mock(
        direct_vm,
        {
            "finding": "INDETERMINATE",
            "event_time_unix": 0,
            "publication_time_unix": 0,
            "issue_codes": ["CONFLICTING_TIMESTAMPS"],
        },
    )
    chronologyresolver.resolve_chronology(uncertain_id)
    assert chronologyresolver.get_audit(uncertain_id)["issue_mask"] == 2


@pytest.mark.parametrize(
    ("code", "mask"),
    [
        ("MISSING_EVENT_TIME", 1),
        ("CONFLICTING_TIMESTAMPS", 2),
        ("UNCLEAR_TIMESTAMP_RULE", 4),
        ("SOURCE_AUTHORITY_UNCLEAR", 8),
        ("INSUFFICIENT_EVIDENCE", 16),
        ("ADVERSARIAL_INSTRUCTION", 32),
    ],
)
def test_each_issue_bit(chronologyresolver, direct_vm, code, mask):
    chronology_id = register(chronologyresolver, chronology_key=f"ISSUE-{mask}")
    mock(
        direct_vm,
        {
            "finding": "INDETERMINATE",
            "event_time_unix": 0,
            "publication_time_unix": 0,
            "issue_codes": [code],
        },
    )
    chronologyresolver.resolve_chronology(chronology_id)
    assert chronologyresolver.get_audit(chronology_id)["issue_mask"] == mask


@pytest.mark.parametrize(
    "response",
    [
        {},
        [],
        {**BEFORE_RESPONSE, "extra": 1},
        {**BEFORE_RESPONSE, "finding": "UNKNOWN"},
        {**BEFORE_RESPONSE, "event_time_unix": "1786490000"},
        {**BEFORE_RESPONSE, "publication_time_unix": 0},
        {**BEFORE_RESPONSE, "issue_codes": ["UNKNOWN"]},
        {"finding": "NO_QUALIFYING_EVENT", "event_time_unix": 1, "publication_time_unix": 0, "issue_codes": []},
        {"finding": "INDETERMINATE", "event_time_unix": 0, "publication_time_unix": 0, "issue_codes": []},
    ],
)
def test_malformed_output_no_state(chronologyresolver, direct_vm, response):
    chronology_id = register(chronologyresolver)
    mock(direct_vm, response)
    with direct_vm.expect_revert("[LLM_ERROR]"):
        chronologyresolver.resolve_chronology(chronology_id)
    assert chronologyresolver.is_resolved(chronology_id) is False


def test_creator_only_and_immutable(chronologyresolver, direct_vm, direct_alice, direct_bob):
    chronology_id = register(chronologyresolver)
    direct_vm.sender = direct_bob
    mock(direct_vm, BEFORE_RESPONSE)
    with direct_vm.expect_revert("only_creator_may_resolve"):
        chronologyresolver.resolve_chronology(chronology_id)
    direct_vm.sender = direct_alice
    chronologyresolver.resolve_chronology(chronology_id)
    with direct_vm.expect_revert("chronology_already_resolved"):
        chronologyresolver.resolve_chronology(chronology_id)


def test_gate_fails_closed_on_tamper(chronologyresolver, direct_vm):
    chronology_id = register(chronologyresolver)
    mock(direct_vm, BEFORE_RESPONSE)
    chronologyresolver.resolve_chronology(chronology_id)
    record = chronologyresolver.get_chronology(chronology_id)
    fingerprint = record["chronology_fingerprint"]
    assert fingerprint == build_fingerprint(record["creator"])
    altered = fingerprint[:-1] + ("0" if fingerprint[-1] != "0" else "1")
    assert chronologyresolver.matches_verdict(chronology_id, altered, "BEFORE_CUTOFF") is False
    audit = json.loads(chronologyresolver.audits[chronology_id])
    audit["event_time_unix"] = False
    chronologyresolver.audits[chronology_id] = json.dumps(audit, sort_keys=True, separators=(",", ":"))
    assert chronologyresolver.matches_verdict(chronology_id, fingerprint, "BEFORE_CUTOFF") is False

