from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import List

from ..schemas.forensic_report import ChainOfCustodyEntry


def append_custody_entry(
    ledger: List[ChainOfCustodyEntry],
    action: str,
    actor: str = "system/engine",
) -> List[ChainOfCustodyEntry]:
    """Create a new ChainOfCustodyEntry object and add it to ledger.

    The function is deliberately side‑effecting – it mutates the supplied ledger
    list and also returns it for convenience.

    Parameters:
    ledger => Existing list of entries; may be empty.
    action => Human‑readable description of the action being recorded.
    actor => Identifier of the system component or analyst performing the action.

    Returns: 
        List[ChainOfCustodyEntry]
    """

    # Resolve immutable components of the entry.
    sequence = len(ledger)
    timestamp = datetime.now(timezone.utc).isoformat()
    prev_hash = ledger[-1].entry_hash if ledger else "0" * 64

    # Build the deterministic hash payload and calculate the SHA‑256.
    hash_payload = f"{sequence}|{timestamp}|{action}|{actor}|{prev_hash}"
    entry_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()

    # Construct the Pydantic model.
    entry = ChainOfCustodyEntry(
        sequence=sequence,
        timestamp=timestamp,
        action=action,
        actor=actor,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )

    # Mutate the ledger in‑place and return it.
    ledger.append(entry)
    return ledger


# Verify ledger integrity.

def verify_ledger_integrity(ledger: List[ChainOfCustodyEntry]) -> bool:
    """
    The verification checks three invariants for every entry:

    1. sequence: matches the entry's position in the list.
    2. prev_hash: matches the preceding entry_hash (or the genesis
       zero‑hash for the first entry).
    3. entry_hash: is the correct SHA‑256 of the canonical payload.

    The function returns TRUE only if all entries satisfy the above,
    otherwise FALSE.
    """

    zero_hash = "0" * 64
    for idx, entry in enumerate(ledger):
        # 1. Sequence must be monotonic and start at 0.
        if entry.sequence != idx:
            return False

        # 2. Verify ``prev_hash``.
        expected_prev = zero_hash if idx == 0 else ledger[idx - 1].entry_hash
        if entry.prev_hash != expected_prev:
            return False

        # 3. Re‑compute the entry hash.
        payload = f"{entry.sequence}|{entry.timestamp}|{entry.action}|{entry.actor}|{entry.prev_hash}"
        expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if entry.entry_hash != expected_hash:
            return False

    return True
