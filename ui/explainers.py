"""Per-category and per-rule explainers used by the findings UI.

The auditor emits compact, machine-friendly fields:
  - `Finding.message`      e.g. "ES-PRINT-CRED-01 matched on line 23."
  - `Finding.snippet`      e.g. 'print(f"key={KEY}")'
  - `Finding.suggested_fix` e.g. "Remove the print() or redact the credential…"
  - `Finding.category`     e.g. "credential_leak"

That's enough for an analyst, but the dashboard audience is "the developer who
just downloaded a third-party skill and wants to know if it's safe." This
module decorates each finding with three pieces of *plain English*:

  1. `why`            — one sentence: why this is dangerous.
  2. `before_caption` — what you'd call the offending line aloud.
  3. `after_template` — a tiny code template showing the safe shape, or "" if
                        we can't honestly auto-suggest one (e.g. for LLM
                        findings whose specifics we don't know).

Per-rule overrides win over per-category defaults. Anything not covered falls
back to a generic "review and remove the leak" template.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Explainer:
    why: str
    before_caption: str
    after_template: str = ""  # "" → no code template; show prose only


# --- Per-category defaults -------------------------------------------------

_CATEGORY: dict[str, Explainer] = {
    "credential_leak": Explainer(
        why=(
            "An agent that runs this skill will see the raw secret in tool "
            "output. From there it lives in the model's context window, "
            "transcripts, and any sub-agent it spawns."
        ),
        before_caption="Secret value sent to a printable channel:",
        after_template=(
            "# Use the Estes Wrapper to redact secrets in flight.\n"
            "from wrapper import redact_text\n"
            "print(redact_text(f\"key={KEY}\"))   # → key=<REDACTED:OPENAI_API_KEY>"
        ),
    ),
    "wallet_secret": Explainer(
        why=(
            "Crypto wallet keys grant *irreversible* control of on-chain "
            "funds. A leaked private key is a drained wallet — usually "
            "within minutes of being indexed by sweep bots."
        ),
        before_caption="Wallet secret material in source / env / output:",
        after_template=(
            "# Never source-control or print wallet keys.\n"
            "# Sign transactions through a hardware wallet or KMS:\n"
            "from eth_account.signers.local import LocalAccount\n"
            "acct: LocalAccount = kms_client.sign_for(account_id)   # signing happens server-side"
        ),
    ),
    "wallet_action": Explainer(
        why=(
            "The skill talks to a wallet RPC or signs transactions. Even "
            "without an obvious key leak, an attacker who can change the "
            "RPC URL or contract address can siphon funds."
        ),
        before_caption="Wallet operation worth a manual review:",
        after_template=(
            "# Pin the RPC + contract addresses, never read them from\n"
            "# untrusted input or the agent's chat context.\n"
            "RPC_URL = os.environ[\"PINNED_RPC\"]   # set in deploy config, not chat\n"
            "CONTRACT = \"0xAbC…\"                  # constant, code-reviewed"
        ),
    ),
    "cloud_credential": Explainer(
        why=(
            "Cloud provider keys can spin up resources, exfiltrate buckets, "
            "or pivot inside your account. They should *never* sit in source."
        ),
        before_caption="Cloud credential committed to the skill:",
        after_template=(
            "# Drop the literal; use the SDK's default credential chain:\n"
            "import boto3\n"
            "client = boto3.client(\"s3\")   # picks up IAM role / env / SSO automatically"
        ),
    ),
    "db_credential": Explainer(
        why=(
            "A connection string with a password lets anyone reading the "
            "skill connect to your database — read, write, or drop tables."
        ),
        before_caption="Database connection string with embedded password:",
        after_template=(
            "# Move the DSN into env, rotate the user, and never log it:\n"
            "DSN = os.environ[\"DATABASE_URL\"]   # do not print(DSN)"
        ),
    ),
    "ssh_key": Explainer(
        why=(
            "An SSH private key in source gives anyone with the file shell "
            "access to whatever hosts trust it."
        ),
        before_caption="SSH private key material in the skill:",
        after_template=(
            "# Remove the key file from the skill bundle.\n"
            "# Use ssh-agent forwarding or short-lived OIDC certs instead."
        ),
    ),
    "high_value_token": Explainer(
        why=(
            "High-value SaaS tokens (GitHub, Stripe, Slack, etc.) can move "
            "money, push code, or post in your name. Treat exposure as "
            "compromise."
        ),
        before_caption="High-value vendor token committed to the skill:",
        after_template=(
            "# Revoke immediately, then load from the vendor's recommended\n"
            "# secret store (1Password / Doppler / Vault / KMS).\n"
            "TOKEN = os.environ[\"GITHUB_TOKEN\"]"
        ),
    ),
    "exfiltration_risk": Explainer(
        why=(
            "The skill sends data to an outbound endpoint. If a secret ever "
            "flows through this code path, it leaves your perimeter."
        ),
        before_caption="Outbound network call worth pinning:",
        after_template=(
            "# Allow-list outbound hosts and redact payloads before sending:\n"
            "if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
            "    raise ValueError(\"blocked outbound host\")\n"
            "requests.post(url, data=redact_text(payload))"
        ),
    ),
    "dangerous_call": Explainer(
        why=(
            "The skill uses a primitive that can execute arbitrary code "
            "(eval, exec, pickle.loads, shell=True, …). One prompt-injected "
            "input becomes remote code execution."
        ),
        before_caption="Dynamic execution sink worth eliminating:",
        after_template=(
            "# Replace eval/exec with an explicit dispatch table or parser:\n"
            "OPS = {\"add\": op_add, \"sub\": op_sub}\n"
            "OPS[name](*args)   # no eval, no exec"
        ),
    ),
    "possible_secret": Explainer(
        why=(
            "A high-entropy literal sits in source. It might be a token, a "
            "hash, or harmless test data — but the auditor can't tell the "
            "difference and neither can an attacker grepping the repo."
        ),
        before_caption="High-entropy literal worth confirming:",
        after_template=(
            "# If this is a real secret, move it to env:\n"
            "VALUE = os.environ[\"VALUE\"]\n"
            "# If it's test data, mark it: noqa-style\n"
            "TEST_FIXTURE = \"...\"   # estes: ignore"
        ),
    ),
    "manifest": Explainer(
        why=(
            "Without a SKILL.md, the LLM semantic pass can't compare what "
            "the skill *says* it does to what it *actually* does — half the "
            "value of the audit."
        ),
        before_caption="Skill is missing its manifest:",
        after_template=(
            "# Add a SKILL.md at the skill root:\n"
            "# Name: <one-line name>\n"
            "# Description: <what this skill does, plainly>\n"
            "# Capabilities: [lists tools / network / disk it touches]"
        ),
    ),
    "parse_error": Explainer(
        why=(
            "Estes couldn't parse this Python file, so AST taint-tracking "
            "skipped it. Static regex still ran, but the deep pass didn't."
        ),
        before_caption="File the AST pass could not parse:",
        after_template="",
    ),
    "scan_skipped": Explainer(
        why="The auditor skipped this file (size limit, binary, or denylist).",
        before_caption="File excluded from the scan:",
        after_template="",
    ),
}

# --- Per-rule overrides ----------------------------------------------------

_RULE: dict[str, Explainer] = {
    "ES-PRINT-CRED-01": Explainer(
        why=(
            "A `print()` call is sending what looks like a secret to stdout. "
            "In an agent context, stdout *is* the model's tool-output channel."
        ),
        before_caption="`print()` of a credential:",
        after_template=(
            "from wrapper import redact_text\n"
            "print(redact_text(f\"key={KEY}\"))   # → key=<REDACTED:OPENAI_API_KEY>"
        ),
    ),
    "ES-LOG-CRED-01": Explainer(
        why=(
            "A logger call carries a credential. Logs are written to disk, "
            "shipped to log aggregators, and frequently end up in shared "
            "dashboards."
        ),
        before_caption="Logger call carrying a credential:",
        after_template=(
            "logger.debug(\"key=%s\", redact_text(KEY))   # filter at the source"
        ),
    ),
    "ES-PRINT-ENV-01": Explainer(
        why=(
            "An `os.environ` read is being printed. Environment variables "
            "are where agent frameworks pass credentials at startup; "
            "echoing them effectively publishes them."
        ),
        before_caption="`print(os.environ[...])` — direct env-var leak:",
        after_template=(
            "value = os.environ[\"OPENAI_API_KEY\"]\n"
            "# operate on `value`, never print it. If you must log:\n"
            "logger.debug(\"OPENAI_API_KEY len=%d\", len(value))"
        ),
    ),
    "ES-WALLET-PK-FROM-ENV-01": Explainer(
        why=(
            "A wallet private key is being read from env *and* flowed into "
            "a printable / loggable / network-bound sink. This is the "
            "single highest-impact pattern Estes detects — leaks here "
            "drain wallets in minutes."
        ),
        before_caption="Wallet private key on its way to a printable channel:",
        after_template=(
            "# Never load wallet keys into the agent's process at all.\n"
            "# Sign on a hardware wallet / KMS and only return the signed tx:\n"
            "signed = kms.sign_eth_tx(account_id, unsigned_tx)\n"
            "w3.eth.send_raw_transaction(signed.rawTransaction)"
        ),
    ),
    "ES-WALLET-SIGN-PY-01": Explainer(
        why=(
            "The skill signs a transaction in-process. If the key was ever "
            "loaded from env or a file, the AST pass already flagged it. "
            "This call is where a leak turns into spent funds."
        ),
        before_caption="In-process transaction signing:",
        after_template=(
            "# Sign on a remote signer; never hold the key in this process:\n"
            "signed_tx = remote_signer.sign(unsigned_tx)\n"
            "w3.eth.send_raw_transaction(signed_tx)"
        ),
    ),
    "ES-PARSE-ERR-01": Explainer(
        why=(
            "Estes couldn't parse this Python file. The static regex pass "
            "still ran, but the deeper AST taint analysis was skipped — "
            "so review this file by hand."
        ),
        before_caption="File the AST pass could not parse:",
        after_template="",
    ),
    "ES-LLM-MISMATCH-01": Explainer(
        why=(
            "The LLM compared the skill's stated purpose (SKILL.md) against "
            "what the code actually does and found a gap. Skills that claim "
            "X but do Y are the textbook supply-chain attack pattern."
        ),
        before_caption="Behavior the LLM flagged as off-manifest:",
        after_template="",
    ),
}


_GENERIC = Explainer(
    why=(
        "Estes flagged this line as a likely leak path. Review it and "
        "either remove the secret, redact before output, or mark with "
        "`# estes: ignore` if it's a deliberate test fixture."
    ),
    before_caption="Offending line:",
    after_template="",
)


def explain(category: str, rule_id: str) -> Explainer:
    """Return the best explainer for this finding (rule beats category)."""
    if rule_id in _RULE:
        return _RULE[rule_id]
    if category in _CATEGORY:
        return _CATEGORY[category]
    return _GENERIC


def humanize_message(rule_id: str, raw_message: str) -> str:
    """Turn the auditor's terse "X matched on line N." into a sentence.

    AST and LLM findings already produce prose messages — those pass through
    untouched. Static rules emit a fixed shape we can rewrite.
    """
    if " matched on line " not in raw_message:
        return raw_message
    rule_name = raw_message.split(" matched on line ")[0]
    return f"{rule_name} detected — see the offending line below."


__all__: Iterable[str] = ("Explainer", "explain", "humanize_message")
