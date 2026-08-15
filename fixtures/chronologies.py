"""Canonical CutoffChronologyResolver fixtures and fingerprint helper."""

from __future__ import annotations

import hashlib
import json

POLICY_VERSION = 1
REGISTRATION_DATETIME = "2026-08-12T10:00:00Z"
CHRONOLOGY_KEY = "FILING-BEFORE-CUTOFF"
PROPOSITION = "Did the registered corporate filing become effective before the cutoff?"
CUTOFF_UNIX = 1_786_500_000
TIMESTAMP_RULE = (
    "Use the filing's explicitly stated effective Unix time, not its later publication "
    "or discovery time. Strictly before means event_time_unix is less than cutoff_unix."
)
EVIDENCE_TEXT = (
    "The registered filing states effective_time_unix=1786490000. The official portal "
    "states publication_time_unix=1786510000. Both values refer to this exact filing."
)
BEFORE_RESPONSE = {
    "finding": "EVENT_FOUND",
    "event_time_unix": 1_786_490_000,
    "publication_time_unix": 1_786_510_000,
    "issue_codes": [],
}


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def build_fingerprint(
    creator: str,
    *,
    policy_version: int = POLICY_VERSION,
    chronology_key: str = CHRONOLOGY_KEY,
    proposition: str = PROPOSITION,
    cutoff_unix: int = CUTOFF_UNIX,
    timestamp_rule: str = TIMESTAMP_RULE,
    evidence_text: str = EVIDENCE_TEXT,
) -> str:
    key = chronology_key.strip().upper()
    binding = {
        "schema": "cutoffchronologyresolver/fingerprint/v1",
        "policy_version": policy_version,
        "chronology_id": f"{creator.lower()}:{key}",
        "creator": creator.lower(),
        "chronology_key": key,
        "proposition": proposition.strip(),
        "cutoff_unix": cutoff_unix,
        "timestamp_rule": timestamp_rule.strip(),
        "evidence_text": evidence_text.strip(),
    }
    return "sha256:" + hashlib.sha256(canonical_json(binding).encode("ascii")).hexdigest()

