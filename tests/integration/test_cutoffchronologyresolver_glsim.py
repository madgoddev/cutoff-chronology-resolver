"""Five-validator GLSim tests for CutoffChronologyResolver."""

from __future__ import annotations

import json
from pathlib import Path

from gltest import get_contract_factory, get_validator_factory
from gltest.assertions import tx_execution_failed, tx_execution_succeeded
from gltest.types import TransactionStatus
from gltest.utils import extract_contract_address

from fixtures.chronologies import (
    BEFORE_RESPONSE,
    CHRONOLOGY_KEY,
    CUTOFF_UNIX,
    EVIDENCE_TEXT,
    POLICY_VERSION,
    PROPOSITION,
    REGISTRATION_DATETIME,
    TIMESTAMP_RULE,
)

PROMPT_KEY = "independent event-chronology auditor"


def context(response):
    validators = get_validator_factory().batch_create_mock_validators(
        5, mock_llm_response={"nondet_exec_prompt": {PROMPT_KEY: json.dumps(response)}}
    )
    return {
        "validators": [validator.to_dict() for validator in validators],
        "genvm_datetime": REGISTRATION_DATETIME,
    }


def deploy():
    path = (
        Path(__file__).resolve().parents[2]
        / "contracts"
        / "cutoff_chronology_resolver.py"
    )
    factory = get_contract_factory(contract_file_path=path)
    receipt = factory.deploy_contract_tx(
        args=[POLICY_VERSION], wait_transaction_status=TransactionStatus.FINALIZED
    )
    assert tx_execution_succeeded(receipt)
    return factory.build_contract(extract_contract_address(receipt))


def register(contract, key=CHRONOLOGY_KEY):
    receipt = contract.register_chronology(
        args=[key, PROPOSITION, CUTOFF_UNIX, TIMESTAMP_RULE, EVIDENCE_TEXT]
    ).transact(wait_transaction_status=TransactionStatus.FINALIZED)
    assert tx_execution_succeeded(receipt)
    return contract.get_chronology_id(args=[0]).call()


def resolve(contract, chronology_id, response):
    return contract.resolve_chronology(args=[chronology_id]).transact(
        transaction_context=context(response),
        wait_transaction_status=TransactionStatus.FINALIZED,
    )


def test_glsim_before_and_gate():
    contract = deploy()
    chronology_id = register(contract)
    assert tx_execution_succeeded(resolve(contract, chronology_id, BEFORE_RESPONSE))
    record = contract.get_chronology(args=[chronology_id]).call()
    assert contract.get_audit(args=[chronology_id]).call()["verdict"] == "BEFORE_CUTOFF"
    assert contract.matches_verdict(
        args=[chronology_id, record["chronology_fingerprint"], "BEFORE_CUTOFF"]
    ).call() is True


def test_glsim_exact_cutoff_is_after():
    contract = deploy()
    chronology_id = register(contract, "AT-CUTOFF")
    response = {
        "finding": "EVENT_FOUND",
        "event_time_unix": CUTOFF_UNIX,
        "publication_time_unix": CUTOFF_UNIX + 1,
        "issue_codes": [],
    }
    assert tx_execution_succeeded(resolve(contract, chronology_id, response))
    assert contract.get_audit(args=[chronology_id]).call()["verdict"] == "AFTER_CUTOFF"


def test_glsim_malformed_fails_without_state():
    contract = deploy()
    chronology_id = register(contract)
    response = {**BEFORE_RESPONSE, "publication_time_unix": 0}
    assert tx_execution_failed(resolve(contract, chronology_id, response))
    assert contract.is_resolved(args=[chronology_id]).call() is False


def test_glsim_immutable_second_resolution_fails():
    contract = deploy()
    chronology_id = register(contract)
    assert tx_execution_succeeded(resolve(contract, chronology_id, BEFORE_RESPONSE))
    assert tx_execution_failed(resolve(contract, chronology_id, BEFORE_RESPONSE))

