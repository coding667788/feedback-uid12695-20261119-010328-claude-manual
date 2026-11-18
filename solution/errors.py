"""Stable error codes.

Ranges
------
E1xx  malformed input (request shape, case file, records)
E2xx  identity / ordering / binding / window of an attempt or proof
E3xx  signature authentication
E4xx  channel lifecycle (existence, revocation, generation, type)
E5xx  request-level and account-level invariants
E6xx  harness / protocol misuse (never a business outcome)
E7xx  platform or internal failure (never a business outcome)

``BUSINESS_ERRORS`` are recorded in the persisted receipt of the request that
caused them: a repeated request with identical parameters replays that failure
forever, even if the underlying state later changes.  Everything else leaves no
receipt behind, so the request can be retried.
"""

from __future__ import annotations

E_BAD_REQUEST = "E100"
E_BAD_CASE = "E101"
E_UNKNOWN_OP = "E102"
E_DUPLICATE_ID = "E103"
E_BAD_RECORD = "E104"

E_UNKNOWN_ID = "E201"
E_SAME_SIGNER = "E203"
E_PROOF_EXPIRED = "E204"
E_BINDING = "E205"
E_PROOF_CONSUMED = "E206"
E_SAME_CHANNEL = "E207"
E_SAME_CHANNEL_TYPE = "E208"
E_NO_STRONG_CHANNEL = "E209"
E_PROOF_NOT_YET_VALID = "E210"
E_ATTEMPT_EXPIRED = "E211"
E_ACCOUNT_FROZEN = "E212"
E_ATTEMPT_NOT_YET_ACTIVE = "E213"
E_CHANNEL_TIME = "E214"

E_BAD_SIGNATURE = "E301"

E_UNKNOWN_CHANNEL = "E401"
E_CHANNEL_REVOKED = "E402"
E_CHANNEL_GEN_STALE = "E403"
E_CHANNEL_GEN_UNKNOWN = "E404"

E_REQUEST_CONFLICT = "E501"
E_ATTEMPT_ACCOUNT = "E502"
E_ACCOUNT_GEN_STALE = "E503"
E_ATTEMPT_CLOSED = "E504"
E_ATTEMPT_SUPERSEDED = "E505"
E_NO_VALID_PAIR = "E506"

E_BUSY = "E602"

E_TIMEOUT = "E701"
E_INTERNAL = "E799"

BUSINESS_ERRORS = frozenset(
    {
        E_BAD_REQUEST,
        E_UNKNOWN_OP,
        E_DUPLICATE_ID,
        E_UNKNOWN_ID,
        E_SAME_SIGNER,
        E_PROOF_EXPIRED,
        E_BINDING,
        E_PROOF_CONSUMED,
        E_SAME_CHANNEL,
        E_SAME_CHANNEL_TYPE,
        E_NO_STRONG_CHANNEL,
        E_PROOF_NOT_YET_VALID,
        E_ATTEMPT_EXPIRED,
        E_ACCOUNT_FROZEN,
        E_ATTEMPT_NOT_YET_ACTIVE,
        E_CHANNEL_TIME,
        E_BAD_SIGNATURE,
        E_UNKNOWN_CHANNEL,
        E_CHANNEL_REVOKED,
        E_CHANNEL_GEN_STALE,
        E_CHANNEL_GEN_UNKNOWN,
        E_REQUEST_CONFLICT,
        E_ATTEMPT_ACCOUNT,
        E_ACCOUNT_GEN_STALE,
        E_ATTEMPT_CLOSED,
        E_ATTEMPT_SUPERSEDED,
        E_NO_VALID_PAIR,
    }
)

#: Codes that abort a whole case file (no tenant can be judged).
LOAD_ERRORS = frozenset({E_BAD_CASE, E_BAD_RECORD, E_DUPLICATE_ID})

DESCRIPTIONS = {
    E_BAD_REQUEST: "request is structurally invalid",
    E_BAD_CASE: "case file or case is malformed",
    E_UNKNOWN_OP: "unknown operation name",
    E_DUPLICATE_ID: "duplicate id in a case file",
    E_BAD_RECORD: "loaded record is malformed",
    E_UNKNOWN_ID: "referenced object does not exist in this tenant",
    E_SAME_SIGNER: "the two proofs were signed by the same verifier",
    E_PROOF_EXPIRED: "proof is past not_after at the request time",
    E_BINDING: "proof / attempt / account / profile digest binding mismatch",
    E_PROOF_CONSUMED: "proof was already consumed by another recovery",
    E_SAME_CHANNEL: "both proofs come from the same channel",
    E_SAME_CHANNEL_TYPE: "both proofs are of the same channel type",
    E_NO_STRONG_CHANNEL: "no human or admin proof in the pair",
    E_PROOF_NOT_YET_VALID: "proof is before not_before at the request time",
    E_ATTEMPT_EXPIRED: "attempt is past expires_at at the request time",
    E_ACCOUNT_FROZEN: "account is frozen; recovery is not allowed",
    E_ATTEMPT_NOT_YET_ACTIVE: "attempt starts after the request time",
    E_CHANNEL_TIME: "channel lifecycle events are not in time order",
    E_BAD_SIGNATURE: "signature does not verify",
    E_UNKNOWN_CHANNEL: "channel is unknown in this tenant",
    E_CHANNEL_REVOKED: "channel generation was revoked before the request time",
    E_CHANNEL_GEN_STALE: "proof carries an old channel generation",
    E_CHANNEL_GEN_UNKNOWN: "proof carries a channel generation that does not exist yet",
    E_REQUEST_CONFLICT: "request id already used with different parameters",
    E_ATTEMPT_ACCOUNT: "attempt belongs to a different account",
    E_ACCOUNT_GEN_STALE: "attempt was opened against an older account generation",
    E_ATTEMPT_CLOSED: "attempt is closed",
    E_ATTEMPT_SUPERSEDED: "a recovery already happened at this attempt's generation",
    E_NO_VALID_PAIR: "no valid proof pair is available",
    E_BUSY: "database stayed locked past the busy timeout",
    E_TIMEOUT: "synchronisation point timed out",
    E_INTERNAL: "unexpected internal failure",
}


class RecoveryError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class HarnessError(Exception):
    """Raised when a test-harness precondition is violated."""
