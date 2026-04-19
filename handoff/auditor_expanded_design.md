# Auditor Module Design — Step 2 (Expanded Scope)

*Written by Architect. Read by Builder and Reviewer. Supersedes `handoff/auditor_design.md` for the next build of `auditor.py`.*

---

## Goal

Phase 1 shipped a 3‑pass scanner (regex + AST + LLM) that is solid for traditional credential leaks. Step 2 expands the scanner to the **2026 attack surface** that matters most to the demo audience and to real users running agent skills against personal/treasury wallets:

1. **Crypto wallet secrets** — private keys (0x hex, raw 64‑hex, Base58, WIF), BIP‑39 seed phrases (12 / 15 / 18 / 21 / 24 words), keystore JSON blobs, derivation‑path leaks.
2. **Smart wallet & transaction risk** — code that signs transactions, calls wallet RPCs, talks to known node providers (Infura, Alchemy, QuickNode, Helius, etc.), interacts with smart contracts, or executes `sendRawTransaction` / `eth_sendTransaction`.
3. **High‑impact non‑crypto secrets** — SSH keys, database connection strings, cloud‑provider keys (AWS, GCP, Azure), GitHub / Slack / Stripe / OpenAI / Anthropic / Google tokens.
4. **Traditional API keys and tokens** (carried over from Phase 1).

Risk scoring is rebalanced so a single confirmed wallet seed phrase or private key produces an immediate **Critical** verdict — these leaks cannot be rotated, only drained.

LLM provider order is changed to **Gemini → Grok → Anthropic (fallback)** so the deep pass uses Google's higher free quota by default and degrades cleanly when keys are missing.

The public surface (`scan_skill`, `scan_path`, `scan_text`, `redact_text`, `SECRET_PATTERNS`) stays backwards compatible. Existing callers (`app.py`, `wrapper.py`) need no change.

---

## What changes vs. Phase 1

| Area | Phase 1 | Step 2 |
|---|---|---|
| Severity ladder | `info` / `warning` / `high` | `info` / `warning` / `high` / **`critical`** |
| Overall verdict | `Safe` / `Warning` / `High Risk` | `Safe` / `Warning` / `High Risk` / **`Critical`** |
| Categories | `credential_leak`, `dangerous_call`, `exfiltration_risk`, `semantic_mismatch`, `manifest`, `parse_error`, `scan_skipped`, `possible_secret` | adds **`wallet_secret`**, **`wallet_action`**, **`db_credential`**, **`cloud_credential`**, **`ssh_key`**, **`high_value_token`** |
| LLM order | Anthropic → xAI | **Gemini → xAI → Anthropic** |
| Score weights | high=40, warn=12, info=3 | **critical=80, high=30, warn=10, info=2** with category multipliers |
| Scannable types | code + config + docs | adds `.rs`, `.sol`, `.move`, `.cairo` for smart‑contract / wallet ecosystems |
| Static rules | 6 regex + entropy | **~30 regex** covering wallet, cloud, vendor‑prefixed tokens, mnemonics |
| AST coverage | env‑var leaks, exec, subprocess, secret file reads, phone‑home | adds **wallet‑signing detection**, **RPC call detection**, **JS/TS pattern matching for `ethers` / `web3` / `@solana/web3.js`** (regex‑level for non‑Python) |
| LLM prompt | "manifest vs code" mismatch | extended with **wallet‑specific red flags** (signs without disclosure, exfiltrates seed phrase, hidden RPC) |

---

## Public API (unchanged signatures)

```python
def scan_skill(
    source: str | Path,
    *,
    llm: bool = True,
    timeout_s: float = 30.0,
    max_bytes: int = 5 * 1024 * 1024,
) -> ScanReport: ...

def scan_path(root: str | Path) -> ScanReport: ...   # = scan_skill(root, llm=False)

def scan_text(text: str, filename: str = "<input>") -> list[Finding]: ...

def redact_text(text: str, marker: str = "[REDACTED by Estes]") -> tuple[str, int]: ...
```

Inputs accepted (unchanged):

- Local file (any extension)
- Local directory
- Local `.zip` archive
- `https://github.com/<owner>/<repo>[/tree/<branch>[/<subpath>]]`

`scan_skill` continues to never raise; all errors land in `report.warnings`.

---

## Expanded Data Model

```python
Severity         = Literal["info", "warning", "high", "critical"]
OverallSeverity  = Literal["Safe", "Warning", "High Risk", "Critical"]
FindingSource    = Literal["static", "ast", "llm"]

Category = Literal[
    # carried over
    "credential_leak", "possible_secret", "dangerous_call",
    "exfiltration_risk", "semantic_mismatch", "manifest",
    "parse_error", "scan_skipped",
    # new in Step 2
    "wallet_secret",     # private key / mnemonic / keystore in source
    "wallet_action",     # signs a tx, calls wallet RPC, sends raw tx
    "db_credential",     # postgres://, mongodb+srv://, etc.
    "cloud_credential",  # AWS / GCP / Azure provider keys
    "ssh_key",           # OpenSSH / id_* / authorized_keys patterns
    "high_value_token",  # vendor‑prefixed tokens (ghp_, sk_live_, xoxb-, …)
]
```

`Finding`, `SkillManifest`, and `ScanReport` keep the same fields. `ScanReport.severity` widens to include `"Critical"`. `risk_label` (Phase 0 compat) stays a 4‑value derivative of `risk_score`; we add a fifth bucket:

| `risk_score` | `risk_label` (legacy) |
|---|---|
| 0 | `clean` |
| 1–24 | `low` |
| 25–69 | `medium` |
| 70–94 | `high` |
| 95+ | **`critical`** |

`app.py`'s `label_color` dict gets one new key (`critical → red`) — that's the only required UI change to stay compatible.

---

## Risk Score Formula (rebalanced)

```
base = 80*count(critical) + 30*count(high) + 10*count(warning) + 2*count(info)

# Category multiplier — applied per finding before the sum.
# Wallet secrets are unrotatable; they dominate the score.
weight(category) = {
    "wallet_secret":    2.0,
    "wallet_action":    1.5,
    "ssh_key":          1.5,
    "cloud_credential": 1.3,
    "db_credential":    1.2,
    "high_value_token": 1.2,
    # everything else: 1.0
}

score = min(100, round(sum(severity_weight(f) * weight(f.category) for f in findings)))
```

Severity bands:

| Condition | Overall verdict |
|---|---|
| `count(critical) >= 1` OR `score >= 95` | **`Critical`** |
| `count(high) >= 1` OR `score >= 70` | `High Risk` |
| `count(warning) >= 1` OR `score >= 25` | `Warning` |
| otherwise | `Safe` |

This guarantees a single `wallet_secret` `critical` finding → `Critical` verdict, and a single confirmed seed phrase alone caps the score.

---

## Pass A — Static (regex + entropy)

`SECRET_PATTERNS` stays exported for `wrapper.py /redact`, but is reorganized into three dicts that all feed the live ruleset:

```python
SECRET_PATTERNS_LEGACY: dict[str, re.Pattern]   # Phase 0/1 rules — UNCHANGED
SECRET_PATTERNS_WALLET: dict[str, re.Pattern]   # new wallet/crypto rules
SECRET_PATTERNS_VENDOR: dict[str, re.Pattern]   # vendor‑prefixed tokens

# Backwards‑compat alias used by wrapper.py:
SECRET_PATTERNS = {
    **SECRET_PATTERNS_LEGACY,
    **SECRET_PATTERNS_WALLET,
    **SECRET_PATTERNS_VENDOR,
}
```

### New wallet & high‑impact regex rules

| Rule id | Category | Severity | Pattern (intent) |
|---|---|---|---|
| `ES-WALLET-EVM-PK-01` | `wallet_secret` | **critical** | `\b0x[a-fA-F0-9]{64}\b` and not a known contract address shape |
| `ES-WALLET-RAW-PK-01` | `wallet_secret` | **critical** | bare 64‑hex string assigned to a name containing `priv`/`secret`/`mnemonic` |
| `ES-WALLET-WIF-01` | `wallet_secret` | **critical** | Bitcoin WIF: `^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$` |
| `ES-WALLET-SOL-PK-01` | `wallet_secret` | **critical** | Solana base58 secret key length (87–88 chars) inside a string literal whose surrounding name is `secretKey`/`privateKey`/`keypair` |
| `ES-WALLET-BIP39-12-01` | `wallet_secret` | **critical** | regex sequence of 12 lowercase words from the BIP‑39 wordlist (loaded once at import) |
| `ES-WALLET-BIP39-24-01` | `wallet_secret` | **critical** | same, 24 words |
| `ES-WALLET-BIP39-PARTIAL-01` | `wallet_secret` | high | 15 / 18 / 21 word sequences from BIP‑39 list |
| `ES-WALLET-KEYSTORE-01` | `wallet_secret` | high | JSON blob containing both `"crypto"` and `"ciphertext"` and `"kdf"` keys |
| `ES-WALLET-DERIVPATH-01` | `wallet_action` | warning | string literal matching `m/44'/60'/0'/0/\d+` (or `/501'/` for Solana, `/0'` for BTC) — informational, often paired with leaks |

The BIP‑39 wordlist (2,048 words) is shipped as an embedded `tuple[str, ...]` constant or read lazily from a packaged `wordlist.txt`. Detection collapses whitespace to single spaces, lowercases, then walks the token stream looking for runs of N words where every word is in the set. Rule fires once per match, not per word.

### New cloud / DB / SSH / vendor regex rules

| Rule id | Category | Severity | Pattern |
|---|---|---|---|
| `ES-AWS-SECRET-01` | `cloud_credential` | high | `aws_secret_access_key\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]` |
| `ES-AWS-SESSION-01` | `cloud_credential` | high | `\bASIA[0-9A-Z]{16}\b` (temp creds) |
| `ES-GCP-SA-JSON-01` | `cloud_credential` | high | JSON containing both `"type": "service_account"` and `"private_key": "-----BEGIN` |
| `ES-GCP-API-KEY-01` | `cloud_credential` | high | `\bAIza[0-9A-Za-z_\-]{35}\b` (Google API key prefix) |
| `ES-AZURE-CONNSTR-01` | `cloud_credential` | high | `DefaultEndpointsProtocol=https;AccountName=…;AccountKey=` literal |
| `ES-DB-POSTGRES-01` | `db_credential` | high | `postgres(?:ql)?://[^:\s]+:[^@\s]+@` with non‑placeholder password |
| `ES-DB-MONGODB-01` | `db_credential` | high | `mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@` |
| `ES-DB-MYSQL-01` | `db_credential` | high | `mysql://[^:\s]+:[^@\s]+@` |
| `ES-DB-REDIS-01` | `db_credential` | warning | `redis(?:s)?://[^:\s]*:[^@\s]+@` |
| `ES-SSH-OPENSSH-01` | `ssh_key` | high | `-----BEGIN OPENSSH PRIVATE KEY-----` (separate id from generic PEM) |
| `ES-SSH-AUTHORIZED-01` | `ssh_key` | warning | line beginning with `ssh-(rsa|ed25519|ecdsa) AAAA` |
| `ES-TOK-GH-01` | `high_value_token` | high | `\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b` |
| `ES-TOK-SLACK-01` | `high_value_token` | high | `\bxox[abprs]-[A-Za-z0-9-]{10,}\b` |
| `ES-TOK-STRIPE-LIVE-01` | `high_value_token` | **critical** | `\bsk_live_[A-Za-z0-9]{20,}\b` |
| `ES-TOK-STRIPE-TEST-01` | `high_value_token` | warning | `\bsk_test_[A-Za-z0-9]{20,}\b` |
| `ES-TOK-OPENAI-01` | `high_value_token` | high | `\bsk-[A-Za-z0-9]{20,}\b` (skip if it also matches ANTHROPIC pattern) |
| `ES-TOK-ANTHROPIC-01` | `high_value_token` | high | `\bsk-ant-[A-Za-z0-9_\-]{40,}\b` |
| `ES-TOK-JWT-01` | `high_value_token` | warning | `\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b` (entropy gated) |

False‑positive guards:

- All wallet/token regexes ignore the line if it also matches `(?i)(example|sample|placeholder|fake|dummy|xxxx|0{20,}|1{20,})`.
- Vendor‑prefixed tokens require the surrounding string literal length to fall within the documented vendor format.
- BIP‑39 detection skips a match if the sequence appears inside a Markdown fenced code block annotated as `bash`/`text`/`example` — this lets docs reference test vectors without firing.
- `# estes: ignore` (or `// estes: ignore`) on the same line continues to suppress all rules.

Entropy pass: unchanged threshold (≥ 4.5 bits/char on quoted literals ≥ 20 chars). A new exemption: any literal already matched by a more specific wallet/vendor rule is dropped from the entropy report (dedupe by `(file, line)`).

---

## Pass B — AST + lightweight pattern pass

### Python AST (extends Phase 1 `_LeakVisitor`)

Existing rules (`ES-PRINT-ENV-01`, `ES-LOG-ENV-01`, `ES-EXEC-01`, `ES-SUBPROC-SHELL-01`, `ES-OS-SYSTEM-01`, `ES-FILE-SECRET-READ-01`, `ES-NET-PHONEHOME-01`) all retained.

New rules:

| Rule id | Category | Severity | Trigger |
|---|---|---|---|
| `ES-WALLET-SIGN-PY-01` | `wallet_action` | high | call to any of `Account.sign_transaction`, `Account.signTransaction`, `w3.eth.account.sign_transaction`, `eth_account.Account.from_key`, `Keypair.from_seed`, `Keypair.from_secret_key`, `solders.keypair.Keypair.from_bytes` |
| `ES-WALLET-SEND-PY-01` | `wallet_action` | high | call to `w3.eth.send_raw_transaction`, `w3.eth.sendRawTransaction`, `web3.eth.sendTransaction`, `solana.rpc.api.Client.send_transaction`, `AsyncClient.send_raw_transaction` |
| `ES-WALLET-RPC-PY-01` | `wallet_action` | warning | `requests.{get,post}` whose URL host matches the **RPC host allowlist** (`*.infura.io`, `*.alchemy.com`, `*.alchemyapi.io`, `*.quicknode.com`, `*.helius.xyz`, `*.ankr.com`, `*.blastapi.io`, `mainnet.solana.com`, `api.mainnet-beta.solana.com`, `polygon-rpc.com`, `arb1.arbitrum.io`, `mainnet.base.org`) |
| `ES-WALLET-CONTRACT-PY-01` | `wallet_action` | warning | call to `w3.eth.contract(...).functions.<name>(...).transact(...)` (chained `.transact` or `.send_transaction`) |
| `ES-WALLET-PK-FROM-ENV-01` | `wallet_secret` | **critical** | `Account.from_key(os.environ[...])` / `from_key(os.getenv(...))` — code is *designed* to handle a private key |
| `ES-DB-CONN-PY-01` | `db_credential` | high | call to `psycopg2.connect`, `pymysql.connect`, `pymongo.MongoClient`, `redis.Redis`, `sqlalchemy.create_engine` whose first positional arg is a non‑literal that touches `os.environ` AND the value is also `print()`/logged elsewhere in the same function (reuses Phase 1 taint table) |

The visitor's `env_names` symbol table is reused for taint tracking. We add a parallel `wallet_names: set[str]` table: any local bound to a wallet‑secret literal, a `from_key(...)` return, or `os.getenv("PRIVATE_KEY"|"MNEMONIC"|"SEED_PHRASE"|...)` flows through `_expr_touches_wallet`. Printing or logging a tainted wallet name yields:

| Rule id | Category | Severity |
|---|---|---|
| `ES-WALLET-PRINT-01` | `wallet_secret` | **critical** |
| `ES-WALLET-LOG-01` | `wallet_secret` | **critical** |
| `ES-WALLET-NET-EXFIL-01` | `wallet_secret` | **critical** | tainted wallet name passed into `requests.{get,post}` body/args |

### Lightweight JS/TS/Solidity pass (regex‑grade, no AST)

Python‑grade AST is out of scope for non‑Python in Step 2. Instead, files with suffix `.js`/`.mjs`/`.cjs`/`.ts`/`.tsx`/`.jsx`/`.sol` get a small set of compiled regexes that look for the wallet idioms most demos hit:

| Rule id | Category | Severity | Pattern (intent) |
|---|---|---|---|
| `ES-WALLET-ETHERS-WALLET-01` | `wallet_action` | high | `new\s+ethers\.Wallet\s*\(` with first arg not a function call returning random bytes |
| `ES-WALLET-ETHERS-SIGN-01` | `wallet_action` | high | `\.signTransaction\s*\(` or `\.sendTransaction\s*\(` |
| `ES-WALLET-WEB3-SEND-01` | `wallet_action` | high | `\.sendSignedTransaction\s*\(` or `eth_sendRawTransaction` literal |
| `ES-WALLET-SOLANA-SIGN-01` | `wallet_action` | high | `Keypair\.fromSecretKey\s*\(` or `sendAndConfirmTransaction\s*\(` |
| `ES-WALLET-PROVIDER-URL-01` | `wallet_action` | warning | hardcoded RPC URL containing `infura.io|alchemy.com|quicknode|helius|ankr` |
| `ES-SOLIDITY-SELFDESTRUCT-01` | `dangerous_call` | high | `\bselfdestruct\s*\(` inside a `.sol` file |
| `ES-SOLIDITY-DELEGATECALL-01` | `dangerous_call` | warning | `\.delegatecall\s*\(` inside a `.sol` file |

These live in a dict `JS_WALLET_PATTERNS` and are evaluated by a new `_scan_lightweight(file_path, rel_path)` invoked alongside `_scan_static`. They do **not** touch the entropy / `# estes: ignore` machinery — that is shared with `_scan_static`.

---

## Pass C — LLM Semantic Check (Gemini → xAI → Anthropic)

### Provider order

`ESTES_LLM_PROVIDER` env var still pins a single provider when set explicitly. When unset (or set to `auto`), the auditor walks this order and uses the first one whose API key is configured:

1. `gemini` — needs `GEMINI_API_KEY`. Default model: `gemini-2.5-flash`.
2. `xai` — needs `XAI_API_KEY`. Default model: `grok-4-mini`.
3. `anthropic` — needs `ANTHROPIC_API_KEY`. Default model: `claude-haiku-4-5`.

`ESTES_LLM_MODEL` overrides the default model for whichever provider ends up selected. Setting `ESTES_LLM_PROVIDER=off` disables the pass entirely (unchanged behavior). Each provider has its own dedicated `_call_<provider>` HTTPS function; no SDKs are added.

### Gemini call shape

```python
url = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{model}:generateContent?key={api_key}"
)
resp = requests.post(
    url,
    headers={"Content-Type": "application/json"},
    json={
        "systemInstruction": {"role": "system", "parts": [{"text": LLM_SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 1024,
            "responseMimeType": "application/json",
        },
    },
    timeout=timeout_s,
)
text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
```

`responseMimeType: application/json` enforces strict JSON output; the existing `_parse_llm_json` tolerator stays as a backstop.

xAI and Anthropic call shapes are unchanged from Phase 1.

### Updated prompt

`LLM_SYSTEM_PROMPT` is rewritten to call out the new categories explicitly. The model is told to look for, **in priority order**:

1. **Crypto wallet leaks** — code or strings that look like private keys, seed phrases, mnemonics, keystore JSON, or `os.environ["PRIVATE_KEY"]`‑style reads.
2. **Wallet actions** — code that signs or broadcasts a transaction, instantiates a wallet from a secret, or contacts a JSON‑RPC node provider.
3. **Manifest mismatch** — the skill says "X" but the code does "Y" (esp. silent network calls, unrelated file reads).
4. **High‑impact non‑crypto secrets** — SSH keys, DB connection strings, cloud provider keys, vendor‑prefixed tokens.
5. **Capability creep** — code exercises capabilities the manifest does not declare.

Output JSON schema gains the optional fields `category` (must be one of the new `Category` literals) and `severity` (now includes `critical`). The `_coerce_llm_findings` helper validates them against an allowlist and downgrades unknown values to `warning`/`semantic_mismatch`.

`user_prompt` template adds a single new line near the top:

```
You are looking at an AI agent skill that may be invoked from a chat session
where the user is connected to a crypto wallet or holds production credentials.
Treat any leak that the user cannot rotate (private keys, seed phrases) as
CRITICAL. Treat unannounced transaction signing or RPC calls as HIGH.
```

The rest of the template (`SKILL MANIFEST`, `FILE TREE`, `CODE`) is unchanged. Code dump cap stays at 32 KB.

---

## Source Resolution & Workspace Layout

Unchanged from Phase 1:

- Local file / dir / `.zip`
- GitHub URL (`/`, `/tree/<branch>`, `/tree/<branch>/<subpath>`)
- `_safe_extract` defends against traversal, symlinks, zip bombs, oversize entries.
- `_fetch_github_zip` streams to disk and aborts past `max_bytes`.

Discovery additions:

- `SCANNABLE_SUFFIXES` gains `.rs`, `.sol`, `.move`, `.cairo`, `.vy` (Vyper).
- `SKIP_DIRS` gains `target` (Rust), `.next`, `.cargo`, `out`, `artifacts`, `cache` (Hardhat/Foundry artifacts).
- New file‑name allowlist: `*.keystore.json`, `UTC--*` (Geth keystore exports), `*.wallet.json` are still scanned but capped to 100 KB each — they are exactly the format `ES-WALLET-KEYSTORE-01` looks for.

---

## Deduplication

The `_dedupe` key is unchanged: `(file, line, id)`. New post‑dedupe pass collapses overlapping wallet findings on the same line so we don't double‑count a single seed phrase that also trips entropy:

> If a `wallet_secret` finding and an `ES-ENTROPY-01` finding share `(file, line)`, drop the entropy one.

---

## Suggested‑Fix Roll‑up

`_rollup_suggested_fix` gains a critical tier:

```
n_crit = sum(1 for f in findings if f.severity == "critical")
n_high = sum(1 for f in findings if f.severity == "high")
n_warn = sum(1 for f in findings if f.severity == "warning")

if n_crit:
    base = (
        f"DO NOT INSTALL. {n_crit} critical leak(s) detected — likely an "
        "unrotatable wallet secret or live payment key. Treat any associated "
        "wallet/account as compromised and rotate or migrate funds immediately."
    )
elif n_high:
    base = f"Remove credential leaks before installing this skill. See the {n_high} high-severity finding(s)."
elif n_warn:
    base = f"Review the {n_warn} warning(s); this skill may exceed its declared capabilities."
else:
    base = "No actionable issues detected."
```

LLM `summary` is appended after a single line break (unchanged).

---

## Module Layout

`auditor.py` stays a single file:

```
auditor.py
├── constants & dataclasses (Severity widened to include "critical")
├── BIP-39 wordlist (embedded tuple OR loaded from packaged wordlist.txt)
├── pattern dicts: SECRET_PATTERNS_LEGACY / _WALLET / _VENDOR
│                  JS_WALLET_PATTERNS
├── _safe_extract / _resolve_source / _fetch_github_zip      (unchanged)
├── _discover_manifest / _discover_files                      (suffix list +5)
├── pass A — _scan_static  (regex + entropy + ignore directive)
├──         _scan_lightweight  (NEW — JS/TS/Sol regex pass)
├── pass B — _scan_ast (extended _LeakVisitor with wallet rules)
├── pass C — _llm_semantic_check (provider chooser: gemini → xai → anthropic)
│       └── _call_gemini / _call_xai / _call_anthropic
├── _aggregate (score + severity + suggested_fix roll-up)
└── public API: scan_skill, scan_path, scan_text, redact_text,
                SECRET_PATTERNS, SECRET_PATTERNS_WALLET, SECRET_PATTERNS_VENDOR
```

---

## Configuration (env vars)

| Env var | Default | Purpose |
|---|---|---|
| `ESTES_LLM_PROVIDER` | `auto` | `auto` / `gemini` / `xai` / `anthropic` / `off` |
| `ESTES_LLM_MODEL` | provider‑specific | overrides default model id |
| `GEMINI_API_KEY` | — | required when provider resolves to `gemini` |
| `XAI_API_KEY` | — | required when provider resolves to `xai` |
| `ANTHROPIC_API_KEY` | — | required when provider resolves to `anthropic` |
| `GITHUB_TOKEN` | — | optional, for higher GitHub rate limits |

`python-dotenv` already loads `.env` at import. No changes there.

---

## Dependencies

No new mandatory packages. All new detectors use the existing stack:

- `requests` (Gemini / xAI / Anthropic / GitHub)
- `PyYAML` (manifest parse, unchanged)
- `python-dotenv` (env loading, unchanged)
- stdlib `ast`, `re`, `math`, `zipfile`, `tempfile`, `pathlib`

The BIP‑39 wordlist ships as either a 28 KB embedded tuple in `auditor.py` or a sibling `bip39_wordlist.txt`. **Recommend** the sibling file: keeps `auditor.py` readable and lets us swap in extra languages later if needed.

---

## Backwards Compatibility

| Concern | Status |
|---|---|
| `SECRET_PATTERNS` import in `wrapper.py` | Kept (now a merged dict — superset of Phase 1) |
| `redact_text()` | Kept; redacts the union ruleset including wallet patterns |
| `scan_text()` | Kept; runs the merged regex set |
| `scan_path()` | Kept; static + AST + lightweight pass, no LLM |
| `Finding.rule` property | Kept |
| `ScanReport.risk_label` | Kept; widened to include `critical` |
| `ScanReport.severity` value `"Critical"` | NEW — `app.py` must add a color mapping (see UI hand‑off note) |
| `ScanReport.to_dict()` JSON shape | New keys are additive; existing keys unchanged |

---

## Definition of Done

- [ ] All Phase 1 tests still pass (zip‑bomb, traversal, weather demo at 3 high, clean skill, missing manifest).
- [ ] BIP‑39 detection: a 12‑word and a 24‑word phrase from the standard test vectors fire `critical` findings; a 13‑word run does not fire.
- [ ] EVM private key (`0x` + 64 hex) fires `ES-WALLET-EVM-PK-01` `critical`; a 64‑hex contract address (no `0x` literal in a known address‑typed assignment) does not.
- [ ] AST: `Account.sign_transaction(...)` in any code path fires `ES-WALLET-SIGN-PY-01` `high`.
- [ ] Wallet taint flow: `pk = os.getenv("PRIVATE_KEY"); print(pk)` fires `ES-WALLET-PRINT-01` `critical` (not just the env‑print rule).
- [ ] JS lightweight pass: `new ethers.Wallet(process.env.PK)` fires `ES-WALLET-ETHERS-WALLET-01`.
- [ ] LLM provider chooser picks Gemini when only `GEMINI_API_KEY` is set; falls through to xAI when only `XAI_API_KEY` is set; falls through to Anthropic when only `ANTHROPIC_API_KEY` is set; emits a single `warnings` entry and `llm_used=False` when none is set.
- [ ] Risk score: a single `wallet_secret` `critical` finding produces `severity == "Critical"` and `risk_score >= 95`.
- [ ] False‑positive guard: a SKILL.md that contains the literal `"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"` inside a fenced ` ```text ` block does NOT fire BIP‑39.
- [ ] No real keys, mnemonics, or tokens committed in source or tests. Test vectors use the canonical BIP‑39 zero entropy phrase (`abandon * 11 about`) only inside an exempted fixture string.
- [ ] `wrapper.py /redact` still passes its smoke test; `redact_text()` now also redacts a sample 0x EVM private key and a sample BIP‑39 phrase in‑place.

---

## Out of Scope for Step 2 (logged as future work)

- Full JS/TS AST (would require `tree-sitter` or `esprima` — defer until a real demo needs it).
- Solidity static analysis beyond `selfdestruct` / `delegatecall` keyword spotting.
- Detecting *encrypted* keystore files where the password is also leaked elsewhere in the repo (cross‑file taint).
- Wallet *behavioral* simulation (dry‑run RPC traffic) — that belongs in the runtime wrapper, not the auditor.
- LLM response caching.
- Auto‑patch generation.

---

## Open Questions for Project Owner

1. **Default LLM provider.** Confirm `gemini` first (free quota, fast, structured output) → `xai` → `anthropic`. We will cite Gemini's free tier in the README. OK?
2. **BIP‑39 wordlist shipping.** Embed as Python tuple (single‑file install, +28 KB to `auditor.py`) or ship as `bip39_wordlist.txt` next to `auditor.py` (cleaner code, one extra file)? Architect recommends the sibling file.
3. **Keystore detection sensitivity.** The `ES-WALLET-KEYSTORE-01` regex matches any JSON with `"crypto"`, `"ciphertext"`, `"kdf"` — strict enough for Geth/MyEtherWallet exports. Bump to `critical` instead of `high`? (They are encrypted, so technically not the secret itself — but encryption strength is unknowable from source.) Architect recommends keeping at `high`.
4. **`app.py` color for `Critical`.** Suggest `#ff2d2d` (deeper red than `High Risk`'s current red), with a small skull/lock icon. Confirm before Builder edits the UI.
