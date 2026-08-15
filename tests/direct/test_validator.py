"""CutoffChronologyResolver validator tests."""

from __future__ import annotations

import json

import pytest

from fixtures.chronologies import BEFORE_RESPONSE
from tests.direct.test_registration import register

LLM_PATTERN = r"independent event-chronology auditor"


def capture(chronologyresolver, direct_vm):
    chronology_id = register(chronologyresolver)
    direct_vm.mock_llm(LLM_PATTERN, json.dumps(BEFORE_RESPONSE))
    chronologyresolver.resolve_chronology(chronology_id)
    return direct_vm._captured_validators[-1][0]


def test_validator_repeats_exact_chronology(chronologyresolver, direct_vm):
    leader = capture(chronologyresolver, direct_vm)
    assert direct_vm.run_validator(leader_result=leader) is True
    direct_vm.clear_mocks()
    changed = dict(BEFORE_RESPONSE)
    changed["event_time_unix"] += 1
    direct_vm.mock_llm(LLM_PATTERN, json.dumps(changed))
    assert direct_vm.run_validator(leader_result=leader) is False


@pytest.mark.parametrize(
    "tampered",
    [
        {},
        {"finding": "EVENT_FOUND", "event_time_unix": 1, "publication_time_unix": 2},
        {"finding": "EVENT_FOUND", "event_time_unix": False, "publication_time_unix": 2, "issue_mask": 0},
        {"finding": "EVENT_FOUND", "event_time_unix": -1, "publication_time_unix": 2, "issue_mask": 0},
        {"finding": "EVENT_FOUND", "event_time_unix": 1, "publication_time_unix": 0, "issue_mask": 0},
        {"finding": "INDETERMINATE", "event_time_unix": 0, "publication_time_unix": 0, "issue_mask": 0},
        {"finding": "NO_QUALIFYING_EVENT", "event_time_unix": 0, "publication_time_unix": 0, "issue_mask": 0, "extra": 0},
    ],
)
def test_validator_rejects_tampering(chronologyresolver, direct_vm, tampered):
    capture(chronologyresolver, direct_vm)
    assert direct_vm.run_validator(leader_result=tampered) is False


def test_validator_rejects_error(chronologyresolver, direct_vm):
    capture(chronologyresolver, direct_vm)
    assert direct_vm.run_validator(leader_error=RuntimeError("broken")) is False
