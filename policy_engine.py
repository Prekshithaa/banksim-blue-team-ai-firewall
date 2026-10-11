from security_engine import detect_threat
from ai_security import analyze_with_ai


# Supported simulated balance inquiries.
BALANCE_REQUESTS = {
    "show balance",
    "check balance",
    "what is my balance",
    "show my balance",
    "check my balance",
    "what's my balance",
}


# Supported account-activity inquiries.
ACCOUNT_ACTIVITY_REQUESTS = {
    "summarize my account activity",
    "summarize the recent activity on my bank account",
    "please summarize the recent activity on my bank account",
    "show my recent transactions",
    "show my account activity",
    "show recent account activity",
    "show my transaction history",
    "show my recent account transactions",
}


# Requests that are too vague to process.
AMBIGUOUS_REQUESTS = {
    "do something with my bank account",
    "do something with my account",
    "help me with my bank account",
    "do something",
    "help me",
    "do my banking",
}


# Threat categories recognized by the security system.
ATTACK_CATEGORIES = {
    "INSTRUCTION_OVERRIDE",
    "PROTECTED_DATA_REQUEST",
    "JAILBREAK_ATTEMPT",
    "MALICIOUS_MEMO",
}


# Markers that indicate a transaction memo or description.
MEMO_MARKERS = (
    "memo:",
    "memo ",
    "description:",
    "note:",
    "message:",
)


def make_result(
    status,
    risk_score,
    threat_category,
    explanation,
    action,
    ai_analysis=None,
    simulated_balance=None,
):
    result = {
        "status": status,
        "risk_score": risk_score,
        "threat_category": threat_category,
        "explanation": explanation,
        "transaction_executed": False,
        "action": action,
        "ai_analysis": ai_analysis,
    }

    if simulated_balance is not None:
        result["simulated_balance"] = simulated_balance

    return result


def evaluate_request(user_input):

    # 1. Validate the input.
    if not isinstance(user_input, str) or not user_input.strip():
        return make_result(
            "BLOCKED",
            100,
            "INVALID_INPUT",
            "The input is empty or invalid.",
            "BLOCK",
        )

    # Normalize spaces, capitalization, and trailing punctuation.
    normalised = " ".join(user_input.lower().split())
    normalised = normalised.rstrip(" .!?")

    # 2. Check known attack patterns using the rule-based detector.
    rule_result = detect_threat(user_input)

    if rule_result.get("is_suspicious", False):
        return make_result(
            "BLOCKED",
            95,
            rule_result.get(
                "threat_category",
                "SUSPICIOUS_ACTIVITY",
            ),
            "A security rule detected a potentially malicious "
            "instruction. The request was blocked.",
            "BLOCK",
        )

    # 3. Handle supported simulated balance inquiries.
    if normalised in BALANCE_REQUESTS:
        return make_result(
            "APPROVED",
            0,
            "NONE_DETECTED",
            "The simulated balance inquiry passed the "
            "configured security checks.",
            "BALANCE_INQUIRY",
            simulated_balance=10000,
        )

    # 4. Handle account-activity inquiries.
    # Account information must not be displayed until
    # authentication and authorization are verified.
    # Handle supported account-activity inquiries.
    is_account_activity_request = (
        normalised in ACCOUNT_ACTIVITY_REQUESTS
        or (
            "account activity" in normalised
            and any(
                word in normalised
                for word in ("summarize", "summary", "show", "recent")
            )
        )
        or (
            "transaction history" in normalised
            or "recent transactions" in normalised
            or "recent account transactions" in normalised
        )
    )

    if is_account_activity_request:
        return make_result(
            "REQUIRES_VALIDATION",
            20,
            "ACCOUNT_ACTIVITY_REQUIRES_VALIDATION",
            "The request appears to be a legitimate account-activity "
            "inquiry. Authentication and authorization must be "
            "verified before any account information is displayed. "
            "No account data was accessed.",
            "ACCOUNT_ACTIVITY_REQUEST",
        )
        

    # 5. Ask for clarification when the request is ambiguous.
    if normalised in AMBIGUOUS_REQUESTS:
        return make_result(
            "REQUIRES_CLARIFICATION",
            30,
            "AMBIGUOUS_REQUEST",
            "Please specify the banking action you want.",
            "NONE",
        )

    # 6. Identify transfer requests.
    is_transfer = normalised.startswith("transfer ")

    contains_memo = any(
        marker in normalised
        for marker in MEMO_MARKERS
    )

    # 7. Plain transfer requests require additional validation.
    # No real transaction is ever executed here.
    if is_transfer and not contains_memo:
        return make_result(
            "REQUIRES_VALIDATION",
            20,
            "TRANSACTION_REQUIRES_VALIDATION",
            "The request passed the configured rule-based checks. "
            "Additional validation is required. "
            "No transaction has been executed.",
            "TRANSFER_REQUEST",
        )

    # 8. Analyze other requests and transfers containing memos.
    ai_result = analyze_with_ai(user_input)

    # Fail safely if the AI analyzer returns an invalid result.
    if not isinstance(ai_result, dict):
        ai_result = {
            "available": False,
            "explanation": (
                "The AI analyzer returned an invalid result."
            ),
        }

    # Require review if AI analysis is unavailable.
    if not ai_result.get("available", False):
        return make_result(
            "REQUIRES_REVIEW",
            60,
            "AI_ANALYSIS_UNAVAILABLE",
            "The AI security check is unavailable. "
            "The request requires review before proceeding.",
            "REVIEW",
            ai_analysis=ai_result,
        )

    # 9. Validate the AI security decision.
    ai_suspicious = ai_result.get("suspicious", False)

    ai_action = str(
        ai_result.get("recommended_action", "REVIEW")
    ).upper()

    ai_category = ai_result.get(
        "threat_category",
        "NEEDS_REVIEW",
    )

    ai_risk = ai_result.get("risk_score", 50)

    if (
        not isinstance(ai_risk, int)
        or isinstance(ai_risk, bool)
        or not 0 <= ai_risk <= 100
        or not isinstance(ai_suspicious, bool)
        or ai_action not in {"BLOCK", "REVIEW", "ALLOW"}
    ):
        return make_result(
            "REQUIRES_REVIEW",
            60,
            "INVALID_AI_RESULT",
            "The AI returned an invalid or incomplete "
            "security decision. Manual review is required.",
            "REVIEW",
            ai_analysis=ai_result,
        )

    # 10. Block recognized attacks.
    if (
        ai_category in ATTACK_CATEGORIES
        and (ai_suspicious or ai_action == "BLOCK")
    ):
        return make_result(
            "BLOCKED",
            max(80, ai_risk),
            ai_category,
            ai_result.get(
                "explanation",
                "A potentially malicious instruction was detected.",
            ),
            "BLOCK",
            ai_analysis=ai_result,
        )

    # 11. Send suspicious or uncertain requests for review.
    if (
        ai_suspicious
        or ai_action in {"BLOCK", "REVIEW"}
        or ai_category == "NEEDS_REVIEW"
    ):
        return make_result(
            "REQUIRES_REVIEW",
            max(30, ai_risk),
            ai_category,
            ai_result.get(
                "explanation",
                "The request requires additional security review.",
            ),
            "REVIEW",
            ai_analysis=ai_result,
        )

    # 12. Do not automatically execute unsupported requests.
    return make_result(
        "REQUIRES_CLARIFICATION",
        30,
        "UNSUPPORTED_REQUEST",
        "The request does not match a supported banking action. "
        "Please clarify your request.",
        "NONE",
        ai_analysis=ai_result,
    )