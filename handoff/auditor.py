"""Estes Auditor — Step 2 (expanded vulnerability detection).

Implements `scan_skill(source, *, llm=True)` per
`handoff/auditor_expanded_design.md`. Three passes share one ruleset:

    Pass A  static       — regex (legacy + wallet + vendor) + Shannon entropy
    Pass A* lightweight  — JS/TS/Solidity wallet-idiom regexes
    Pass B  ast          — Python AST visitor with env + wallet taint tables
    Pass C  llm          — semantic check (Gemini → xAI → Anthropic fallback)

The module is import-safe with no API keys configured: the LLM pass degrades
to a single warning string and the rest of the report is unaffected.

Backwards compatible with Phase 0/1: `SECRET_PATTERNS`, `scan_text`,
`scan_path`, `scan_skill`, `redact_text`, `Finding`, `ScanReport`,
`SkillManifest` keep the same shape so `wrapper.py` and `app.py` continue to
work unchanged. The `Severity` ladder gains `"critical"` and the
`OverallSeverity` ladder gains `"Critical"` — both are additive.
"""
from __future__ import annotations

import ast
import json
import logging
import math
import os
import re
import shutil
import tempfile
import time
import zipfile
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    # dotenv is optional at runtime — env vars work fine without it.
    pass

log = logging.getLogger("estes.auditor")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNABLE_SUFFIXES = {
    # Code
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".sh", ".rb", ".go", ".rs",
    # Smart-contract / wallet ecosystems (new in Step 2)
    ".sol", ".move", ".cairo", ".vy",
    # Config / data
    ".yaml", ".yml", ".json", ".env", ".toml", ".ini",
    # Docs
    ".md", ".txt",
}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build",
    "__pycache__", ".venv", "venv", ".tox", ".pytest_cache",
    # Smart-contract / Rust toolchain artifacts
    "target", ".next", ".cargo", "out", "artifacts", "cache",
}

MANIFEST_NAMES = (
    "SKILL.md", "SKILL.yaml", "SKILL.yml", "SKILL.json",
    "manifest.yaml", "manifest.yml", "manifest.json",
)

DEFAULT_MAX_BYTES = 5 * 1024 * 1024
DEFAULT_PER_FILE_BYTES = 500 * 1024
DEFAULT_TIMEOUT_S = 30.0

IGNORE_DIRECTIVE_RE = re.compile(r"(?:#|//)\s*estes\s*:\s*ignore", re.IGNORECASE)

# Hosts the AST pass treats as safe (loopback) when checking phone-home.
NETWORK_ALLOWLIST = {
    "localhost", "127.0.0.1", "0.0.0.0",
}

# Hosts that strongly indicate wallet/RPC traffic. Wildcards are matched
# via endswith on the bare hostname.
WALLET_RPC_HOST_SUFFIXES = (
    ".infura.io",
    ".alchemy.com", ".alchemyapi.io",
    ".quicknode.com", ".quicknode.pro",
    ".helius.xyz", ".helius-rpc.com",
    ".ankr.com",
    ".blastapi.io",
    ".chainstack.com",
    ".moralis.io",
    "polygon-rpc.com",
    "arb1.arbitrum.io",
    "mainnet.base.org",
    "api.mainnet-beta.solana.com",
    "mainnet.solana.com",
    "rpc.ankr.com",
)

SECRET_FILE_GLOBS = (
    re.compile(r"(?i)(^|/)\.aws/credentials$"),
    re.compile(r"(?i)(^|/)\.ssh/id_[a-z0-9_]+$"),
    re.compile(r"(?i)\.pem$"),
    re.compile(r"(?i)\.key$"),
    re.compile(r"(?i)(^|/)\.env(\.[a-z0-9_-]+)?$"),
    # Wallet/keystore exports (new)
    re.compile(r"(?i)(^|/)UTC--"),
    re.compile(r"(?i)\.keystore(\.json)?$"),
    re.compile(r"(?i)\.wallet(\.json)?$"),
)

# Substrings that, if present on the same line, suppress wallet/vendor regex
# hits. Catches obvious example/test material in docs/fixtures.
#
# We use word boundaries and avoid bare "example" because legitimate URIs
# like `db.example.com` are extremely common in real DSNs.
_PLACEHOLDER_RE = re.compile(
    r"""(?ix)
    \b(?:
        placeholder
      | sample[_-]?key | fake[_-]?key | dummy[_-]?key
      | your[_-]?(?:secret|key|token|api)
      | replace[_-]?me | todo[_-]?(?:secret|key)
      | xxxxx{2,} | 0{16,} | 1{16,}
      | deadbeef[a-f0-9]* | cafebabe
    )\b
    | <\s*your   # angle-bracketed manual fill-ins, e.g. "<your-key>"
    | <<\s*[A-Za-z]
    """
)


# ---------------------------------------------------------------------------
# Pass A — regex ruleset
# ---------------------------------------------------------------------------

# Legacy Phase 0/1 patterns. wrapper.py /redact still consumes these via the
# merged SECRET_PATTERNS dict at the bottom of this section.
SECRET_PATTERNS_LEGACY: dict[str, re.Pattern[str]] = {
    "Generic API key assignment": re.compile(
        r"""(?ix)
        \b(api[_-]?key|secret|token|passwd|password)\b
        \s*[:=]\s*
        ['"][A-Za-z0-9_\-\.]{12,}['"]
        """
    ),
    "Bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Private key block": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"
    ),
    "Debug print of credential": re.compile(
        r"(?i)\bprint\s*\(.*?(api[_-]?key|token|password|secret|bearer).*?\)"
    ),
    "Logging of credential": re.compile(
        r"(?i)\b(log|logger)\.(debug|info|warning|error)\s*\(.*?(api[_-]?key|token|password|secret).*?\)"
    ),
}

# Crypto wallet regex set. Heaviest-impact category in Step 2.
SECRET_PATTERNS_WALLET: dict[str, re.Pattern[str]] = {
    # 0x-prefixed 64-hex EVM private key. False-positive guard: the line must
    # not look like a contract/checksum address assignment (those usually pair
    # with names like `address`, `to`, `from`, `contract`).
    "EVM private key (0x hex)": re.compile(
        r"(?<![A-Fa-f0-9])0x[a-fA-F0-9]{64}(?![A-Fa-f0-9])"
    ),
    # Bare 64-hex assigned to a name that screams "secret".
    "Raw 64-hex private key assignment": re.compile(
        r"""(?ix)
        \b(priv(?:ate)?[_-]?key|secret[_-]?key|mnemonic|seed[_-]?phrase|
           sk|signing[_-]?key)\b
        \s*[:=]\s*
        ['"]?[a-fA-F0-9]{64}['"]?
        """
    ),
    # Bitcoin Wallet Import Format (compressed/uncompressed start chars).
    "Bitcoin WIF private key": re.compile(
        r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"
    ),
    # Solana exported secret key (87–88 base58 chars). Anchored to a name to
    # cut down on accidental matches in long base58 blobs.
    "Solana base58 secret key": re.compile(
        r"""(?x)
        (?:secret[_-]?key|private[_-]?key|keypair)
        \s*[:=]\s*
        ['"]([1-9A-HJ-NP-Za-km-z]{86,90})['"]
        """,
        re.IGNORECASE,
    ),
    # Geth/MEW keystore JSON shape: needs all three keys to fire.
    "Wallet keystore JSON": re.compile(
        r"""(?xs)
        \{[^{}]*?"crypto"\s*:\s*\{[^{}]*?"ciphertext"[^{}]*?"kdf"
        """
    ),
    # Standard derivation paths — informational on their own, but a strong
    # corroborating signal next to other wallet hits.
    "BIP-44 derivation path": re.compile(
        r"\bm/44'/(?:60|501|0|1)'(?:/\d+'?)*(?:/\d+)*\b"
    ),
}

# Vendor-prefixed token patterns. These are distinct from the legacy
# "Generic API key assignment" because vendor prefixes give us very high
# confidence — we can mark them at high or critical severity directly.
SECRET_PATTERNS_VENDOR: dict[str, re.Pattern[str]] = {
    "AWS secret access key value": re.compile(
        r"""(?ix)
        \baws[_-]?secret[_-]?access[_-]?key\b
        \s*[:=]\s*
        ['"][A-Za-z0-9/+=]{40}['"]
        """
    ),
    "AWS session token (ASIA)": re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    "GCP service account JSON": re.compile(
        r"""(?xs)
        "type"\s*:\s*"service_account".*?
        "private_key"\s*:\s*"-----BEGIN
        """
    ),
    "GCP API key (AIza)": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Azure storage connection string": re.compile(
        r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\s]+"
    ),
    "Postgres connection URI with password": re.compile(
        r"\bpostgres(?:ql)?://[^:\s/]+:[^@\s/]+@[^\s/]+"
    ),
    "MongoDB connection URI with password": re.compile(
        r"\bmongodb(?:\+srv)?://[^:\s/]+:[^@\s/]+@[^\s/]+"
    ),
    "MySQL connection URI with password": re.compile(
        r"\bmysql://[^:\s/]+:[^@\s/]+@[^\s/]+"
    ),
    "Redis connection URI with password": re.compile(
        r"\brediss?://[^:\s/]*:[^@\s/]+@[^\s/]+"
    ),
    "OpenSSH private key block": re.compile(
        r"-----BEGIN OPENSSH PRIVATE KEY-----"
    ),
    "SSH authorized_keys entry": re.compile(
        r"\bssh-(?:rsa|ed25519|ecdsa)\s+AAAA[0-9A-Za-z+/=]{40,}"
    ),
    "GitHub personal token": re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"
    ),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Stripe live secret key": re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
    "Stripe test secret key": re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b"),
    "Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{40,}\b"),
    "OpenAI API key": re.compile(r"\bsk-(?!ant-)[A-Za-z0-9]{20,}\b"),
    "JSON Web Token": re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    ),
}

# Public superset — wrapper.py imports this name and expects the legacy keys
# to still resolve. Order matters for redact_text() deterministic output.
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    **SECRET_PATTERNS_LEGACY,
    **SECRET_PATTERNS_WALLET,
    **SECRET_PATTERNS_VENDOR,
}

# Rule metadata: rule name -> (id, severity, category, suggested_fix)
_STATIC_RULE_META: dict[str, tuple[str, str, str, str]] = {
    # ---------- legacy ----------
    "Generic API key assignment": (
        "ES-CRED-ASSIGN-01", "warning", "credential_leak",
        "Move the literal into an environment variable or secret store.",
    ),
    "Bearer token": (
        "ES-BEARER-01", "high", "credential_leak",
        "Never embed bearer tokens in source. Load them from env at call time.",
    ),
    "AWS access key id": (
        "ES-AWS-KEY-01", "high", "cloud_credential",
        "Rotate the key immediately and load credentials from the AWS SDK chain.",
    ),
    "Private key block": (
        "ES-PRIVKEY-01", "high", "credential_leak",
        "Remove the embedded private key; use a key management system.",
    ),
    "Debug print of credential": (
        "ES-PRINT-CRED-01", "high", "credential_leak",
        "Remove the print() or redact the credential before printing.",
    ),
    "Logging of credential": (
        "ES-LOG-CRED-01", "high", "credential_leak",
        "Strip the credential from the log call or lower the log level to nothing.",
    ),
    # ---------- wallet ----------
    "EVM private key (0x hex)": (
        "ES-WALLET-EVM-PK-01", "critical", "wallet_secret",
        "Treat this wallet as compromised. Move funds, then rotate the key "
        "and load it from a hardware wallet or KMS — never source.",
    ),
    "Raw 64-hex private key assignment": (
        "ES-WALLET-RAW-PK-01", "critical", "wallet_secret",
        "Treat this wallet as compromised. Move funds and rotate the key.",
    ),
    "Bitcoin WIF private key": (
        "ES-WALLET-WIF-01", "critical", "wallet_secret",
        "Treat this BTC wallet as compromised. Sweep funds immediately.",
    ),
    "Solana base58 secret key": (
        "ES-WALLET-SOL-PK-01", "critical", "wallet_secret",
        "Treat this Solana wallet as compromised. Move SOL/SPL tokens out.",
    ),
    "Wallet keystore JSON": (
        "ES-WALLET-KEYSTORE-01", "high", "wallet_secret",
        "Encrypted keystore committed in source. Remove it and rotate; the "
        "encryption password is only as strong as it is kept separate.",
    ),
    "BIP-44 derivation path": (
        "ES-WALLET-DERIVPATH-01", "warning", "wallet_action",
        "Derivation paths in source aren't secrets, but they suggest the "
        "code derives wallets locally — confirm the seed source is safe.",
    ),
    # ---------- vendor / cloud / db / ssh ----------
    "AWS secret access key value": (
        "ES-AWS-SECRET-01", "high", "cloud_credential",
        "Rotate the AWS secret immediately and load creds from the SDK chain.",
    ),
    "AWS session token (ASIA)": (
        "ES-AWS-SESSION-01", "high", "cloud_credential",
        "Temporary AWS creds in source — rotate the source role and never "
        "persist STS tokens to disk.",
    ),
    "GCP service account JSON": (
        "ES-GCP-SA-JSON-01", "high", "cloud_credential",
        "Revoke the service account key and use Workload Identity Federation.",
    ),
    "GCP API key (AIza)": (
        "ES-GCP-API-KEY-01", "high", "cloud_credential",
        "Restrict or rotate the Google API key in the GCP console.",
    ),
    "Azure storage connection string": (
        "ES-AZURE-CONNSTR-01", "high", "cloud_credential",
        "Rotate the storage account key; prefer SAS tokens or AAD.",
    ),
    "Postgres connection URI with password": (
        "ES-DB-POSTGRES-01", "high", "db_credential",
        "Move the DSN into env; prefer per-pod IAM auth where available.",
    ),
    "MongoDB connection URI with password": (
        "ES-DB-MONGODB-01", "high", "db_credential",
        "Move the URI into env and rotate the user password.",
    ),
    "MySQL connection URI with password": (
        "ES-DB-MYSQL-01", "high", "db_credential",
        "Move the URI into env and rotate the user password.",
    ),
    "Redis connection URI with password": (
        "ES-DB-REDIS-01", "warning", "db_credential",
        "Move the URI into env and prefer ACL users over a shared password.",
    ),
    "OpenSSH private key block": (
        "ES-SSH-OPENSSH-01", "high", "ssh_key",
        "Remove the SSH private key from source and rotate the keypair.",
    ),
    "SSH authorized_keys entry": (
        "ES-SSH-AUTHORIZED-01", "warning", "ssh_key",
        "Don't ship authorized_keys lines in distributable code.",
    ),
    "GitHub personal token": (
        "ES-TOK-GH-01", "high", "high_value_token",
        "Revoke the GitHub token and load it from env at call time.",
    ),
    "Slack token": (
        "ES-TOK-SLACK-01", "high", "high_value_token",
        "Revoke the Slack token in the Slack admin console.",
    ),
    "Stripe live secret key": (
        "ES-TOK-STRIPE-LIVE-01", "critical", "high_value_token",
        "ROTATE NOW. Live Stripe key in source = direct payment access.",
    ),
    "Stripe test secret key": (
        "ES-TOK-STRIPE-TEST-01", "warning", "high_value_token",
        "Rotate the Stripe test key; even test keys can map to a real account.",
    ),
    "Anthropic API key": (
        "ES-TOK-ANTHROPIC-01", "high", "high_value_token",
        "Revoke the Anthropic key in console.anthropic.com and rotate.",
    ),
    "OpenAI API key": (
        "ES-TOK-OPENAI-01", "high", "high_value_token",
        "Revoke the OpenAI key at platform.openai.com and rotate.",
    ),
    "JSON Web Token": (
        "ES-TOK-JWT-01", "warning", "high_value_token",
        "JWTs in source usually mean a static auth shortcut — review and rotate.",
    ),
}


# ---------------------------------------------------------------------------
# Lightweight (non-Python) wallet idiom regexes
# ---------------------------------------------------------------------------

# These run on *.js / *.ts / *.jsx / *.tsx / *.mjs / *.cjs / *.sol files.
# Map: rule name -> (compiled pattern, id, severity, category, fix, suffixes)
JS_WALLET_PATTERNS: dict[str, tuple[re.Pattern[str], str, str, str, str, frozenset[str]]] = {
    "ethers.Wallet constructor": (
        re.compile(r"new\s+ethers\.Wallet\s*\("),
        "ES-WALLET-ETHERS-WALLET-01",
        "high",
        "wallet_action",
        "Wraps a private key as a signing wallet — confirm the key source is "
        "scoped (env var, hardware) and not a literal.",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    "ethers signTransaction / sendTransaction": (
        re.compile(r"\.(?:signTransaction|sendTransaction)\s*\("),
        "ES-WALLET-ETHERS-SIGN-01",
        "high",
        "wallet_action",
        "Code signs or broadcasts an EVM transaction. Make sure the user "
        "approves explicitly per-call.",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    "web3 sendSignedTransaction": (
        re.compile(r"\.sendSignedTransaction\s*\(|eth_sendRawTransaction"),
        "ES-WALLET-WEB3-SEND-01",
        "high",
        "wallet_action",
        "Broadcasts a pre-signed transaction. Verify the signing source.",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    "Solana Keypair.fromSecretKey": (
        re.compile(r"Keypair\.fromSecretKey\s*\(|sendAndConfirmTransaction\s*\("),
        "ES-WALLET-SOLANA-SIGN-01",
        "high",
        "wallet_action",
        "Loads a Solana keypair or sends a tx — confirm the secret source.",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}),
    ),
    "Hardcoded RPC provider URL": (
        re.compile(
            r"https?://[A-Za-z0-9_.\-]*"
            r"(?:infura\.io|alchemy\.com|alchemyapi\.io|quicknode\.com|"
            r"helius\.xyz|helius-rpc\.com|ankr\.com|blastapi\.io|chainstack\.com)"
            r"[A-Za-z0-9_./\-]*"
        ),
        "ES-WALLET-PROVIDER-URL-01",
        "warning",
        "wallet_action",
        "Hardcoded JSON-RPC endpoint. Move to env so the user can pin their "
        "own provider.",
        frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sol", ".py"}),
    ),
    "Solidity selfdestruct": (
        re.compile(r"\bselfdestruct\s*\("),
        "ES-SOLIDITY-SELFDESTRUCT-01",
        "high",
        "dangerous_call",
        "selfdestruct() destroys the contract — always a red flag in a "
        "third-party deliverable.",
        frozenset({".sol"}),
    ),
    "Solidity delegatecall": (
        re.compile(r"\.delegatecall\s*\("),
        "ES-SOLIDITY-DELEGATECALL-01",
        "warning",
        "dangerous_call",
        "delegatecall() runs another contract's code in this contract's "
        "context. Audit the target carefully.",
        frozenset({".sol"}),
    ),
}


# ---------------------------------------------------------------------------
# BIP-39 wordlist (English, official 2,048 words).
# Embedded inline so this module stays single-file. Loaded into a frozenset
# at import for O(1) membership checks during mnemonic detection.
# ---------------------------------------------------------------------------

_BIP39_WORDLIST_RAW = """
abandon ability able about above absent absorb abstract
absurd abuse access accident account accuse achieve acid
acoustic acquire across act action actor actress actual
adapt add addict address adjust admit adult advance
advice aerobic affair afford afraid again age agent
agree ahead aim air airport aisle alarm album
alcohol alert alien all alley allow almost alone
alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry
animal ankle announce annual another answer antenna antique
anxiety any apart apology appear apple approve april
arch arctic area arena argue arm armed armor
army around arrange arrest arrive arrow art artefact
artist artwork ask aspect assault asset assist assume
asthma athlete atom attack attend attitude attract auction
audit august aunt author auto autumn average avocado
avoid awake aware away awesome awful awkward axis
baby bachelor bacon badge bag balance balcony ball
bamboo banana banner bar barely bargain barrel base
basic basket battle beach bean beauty because become
beef before begin behave behind believe below belt
bench benefit best betray better between beyond bicycle
bid bike bind biology bird birth bitter black
blade blame blanket blast bleak bless blind blood
blossom blouse blue blur blush board boat body
boil bomb bone bonus book boost border boring
borrow boss bottom bounce box boy bracket brain
brand brass brave bread breeze brick bridge brief
bright bring brisk broccoli broken bronze broom brother
brown brush bubble buddy budget buffalo build bulb
bulk bullet bundle bunker burden burger burst bus
business busy butter buyer buzz cabbage cabin cable
cactus cage cake call calm camera camp can
canal cancel candy cannon canoe canvas canyon capable
capital captain car carbon card cargo carpet carry
cart case cash casino castle casual cat catalog
catch category cattle caught cause caution cave ceiling
celery cement census century cereal certain chair chalk
champion change chaos chapter charge chase chat cheap
check cheese chef cherry chest chicken chief child
chimney choice choose chronic chuckle chunk churn cigar
cinnamon circle citizen city civil claim clap clarify
claw clay clean clerk clever click client cliff
climb clinic clip clock clog close cloth cloud
clown club clump cluster clutch coach coast coconut
code coffee coil coin collect color column combine
come comfort comic common company concert conduct confirm
congress connect consider control convince cook cool copper
copy coral core corn correct cost cotton couch
country couple course cousin cover coyote crack cradle
craft cram crane crash crater crawl crazy cream
credit creek crew cricket crime crisp critic crop
cross crouch crowd crucial cruel cruise crumble crunch
crush cry crystal cube culture cup cupboard curious
current curtain curve cushion custom cute cycle dad
damage damp dance danger daring dash daughter dawn
day deal debate debris decade december decide decline
decorate decrease deer defense define defy degree delay
deliver demand demise denial dentist deny depart depend
deposit depth deputy derive describe desert design desk
despair destroy detail detect develop device devote diagram
dial diamond diary dice diesel diet differ digital
dignity dilemma dinner dinosaur direct dirt disagree discover
disease dish dismiss disorder display distance divert divide
divorce dizzy doctor document dog doll dolphin domain
donate donkey donor door dose double dove draft
dragon drama drastic draw dream dress drift drill
drink drip drive drop drum dry duck dumb
dune during dust dutch duty dwarf dynamic eager
eagle early earn earth easily east easy echo
ecology economy edge edit educate effort egg eight
either elbow elder electric elegant element elephant elevator
elite else embark embody embrace emerge emotion employ
empower empty enable enact end endless endorse enemy
energy enforce engage engine enhance enjoy enlist enough
enrich enroll ensure enter entire entry envelope episode
equal equip era erase erode erosion error erupt
escape essay essence estate eternal ethics evidence evil
evoke evolve exact example excess exchange excite exclude
excuse execute exercise exhaust exhibit exile exist exit
exotic expand expect expire explain expose express extend
extra eye eyebrow fabric face faculty fade faint
faith fall false fame family famous fan fancy
fantasy farm fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel female
fence festival fetch fever few fiber fiction field
figure file film filter final find fine finger
finish fire firm first fiscal fish fit fitness
fix flag flame flash flat flavor flee flight
flip float flock floor flower fluid flush fly
foam focus fog foil fold follow food foot
force forest forget fork fortune forum forward fossil
foster found fox fragile frame frequent fresh friend
fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy
gallery game gap garage garbage garden garlic garment
gas gasp gate gather gauge gaze general genius
genre gentle genuine gesture ghost giant gift giggle
ginger giraffe girl give glad glance glare glass
glide glimpse globe gloom glory glove glow glue
goat goddess gold good goose gorilla gospel gossip
govern gown grab grace grain grant grape grass
gravity great green grid grief grit grocery group
grow grunt guard guess guide guilt guitar gun
gym habit hair half hammer hamster hand happy
harbor hard harsh harvest hat have hawk hazard
head health heart heavy hedgehog height hello helmet
help hen hero hidden high hill hint hip
hire history hobby hockey hold hole holiday hollow
home honey hood hope horn horror horse hospital
host hotel hour hover hub huge human humble
humor hundred hungry hunt hurdle hurry hurt husband
hybrid ice icon idea identify idle ignore ill
illegal illness image imitate immense immune impact impose
improve impulse inch include income increase index indicate
indoor industry infant inflict inform inhale inherit initial
inject injury inmate inner innocent input inquiry insane
insect inside inspire install intact interest into invest
invite involve iron island isolate issue item ivory
jacket jaguar jar jazz jealous jeans jelly jewel
job join joke journey joy judge juice jump
jungle junior junk just kangaroo keen keep ketchup
key kick kid kidney kind kingdom kiss kit
kitchen kite kitten kiwi knee knife knock know
lab label labor ladder lady lake lamp language
laptop large later latin laugh laundry lava law
lawn lawsuit layer lazy leader leaf learn leave
lecture left leg legal legend leisure lemon lend
length lens leopard lesson letter level liar liberty
library license life lift light like limb limit
link lion liquid list little live lizard load
loan lobster local lock logic lonely long loop
lottery loud lounge love loyal lucky luggage lumber
lunar lunch luxury lyrics machine mad magic magnet
maid mail main major make mammal man manage
mandate mango mansion manual maple marble march margin
marine market marriage mask mass master match material
math matrix matter maximum maze meadow mean measure
meat mechanic medal media melody melt member memory
mention menu mercy merge merit merry mesh message
metal method middle midnight milk million mimic mind
minimum minor minute miracle mirror misery miss mistake
mix mixed mixture mobile model modify mom moment
monitor monkey monster month moon moral more morning
mosquito mother motion motor mountain mouse move movie
much muffin mule multiply muscle museum mushroom music
must mutual myself mystery myth naive name napkin
narrow nasty nation nature near neck need negative
neglect neither nephew nerve nest net network neutral
never news next nice night noble noise nominee
noodle normal north nose notable note nothing notice
novel now nuclear number nurse nut oak obey
object oblige obscure observe obtain obvious occur ocean
october odor off offer office often oil okay
old olive olympic omit once one onion online
only open opera opinion oppose option orange orbit
orchard order ordinary organ orient original orphan ostrich
other outdoor outer output outside oval oven over
own owner oxygen oyster ozone pact paddle page
pair palace palm panda panel panic panther paper
parade parent park parrot party pass patch path
patient patrol pattern pause pave payment peace peanut
pear peasant pelican pen penalty pencil people pepper
perfect permit person pet phone photo phrase physical
piano picnic picture piece pig pigeon pill pilot
pink pioneer pipe pistol pitch pizza place planet
plastic plate play please pledge pluck plug plunge
poem poet point polar pole police pond pony
pool popular portion position possible post potato pottery
poverty powder power practice praise predict prefer prepare
present pretty prevent price pride primary print priority
prison private prize problem process produce profit program
project promote proof property prosper protect proud provide
public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose purse push put puzzle
pyramid quality quantum quarter question quick quit quiz
quote rabbit raccoon race rack radar radio rail
rain raise rally ramp ranch random range rapid
rare rate rather raven raw razor ready real
reason rebel rebuild recall receive recipe record recycle
reduce reflect reform refuse region regret regular reject
relax release relief rely remain remember remind remove
render renew rent reopen repair repeat replace report
require rescue resemble resist resource response result retire
retreat return reunion reveal review reward rhythm rib
ribbon rice rich ride ridge rifle right rigid
ring riot ripple risk ritual rival river road
roast robot robust rocket romance roof rookie room
rose rotate rough round route royal rubber rude
rug rule run runway rural sad saddle sadness
safe sail salad salmon salon salt salute same
sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science
scissors scorpion scout scrap screen script scrub sea
search season seat second secret section security seed
seek segment select sell seminar senior sense sentence
series service session settle setup seven shadow shaft
shallow share shed shell sheriff shield shift shine
ship shiver shock shoe shoot shop short shoulder
shove shrimp shrug shuffle shy sibling sick side
siege sight sign silent silk silly silver similar
simple since sing siren sister situate six size
skate sketch ski skill skin skirt skull slab
slam sleep slender slice slide slight slim slogan
slot slow slush small smart smile smoke smooth
snack snake snap sniff snow soap soccer social
sock soda soft solar soldier solid solution solve
someone song soon sorry sort soul sound soup
source south space spare spatial spawn speak special
speed spell spend sphere spice spider spike spin
spirit split spoil sponsor spoon sport spot spray
spread spring spy square squeeze squirrel stable stadium
staff stage stairs stamp stand start state stay
steak steel stem step stereo stick still sting
stock stomach stone stool story stove strategy street
strike strong struggle student stuff stumble style subject
submit subway success such sudden suffer sugar suggest
suit summer sun sunny sunset super supply supreme
sure surface surge surprise surround survey suspect sustain
swallow swamp swap swarm swear sweet swift swim
swing switch sword symbol symptom syrup system table
tackle tag tail talent talk tank tape target
task taste tattoo taxi teach team tell ten
tenant tennis tent term test text thank that
theme then theory there they thing this thought
three thrive throw thumb thunder ticket tide tiger
tilt timber time tiny tip tired tissue title
toast tobacco today toddler toe together toilet token
tomato tomorrow tone tongue tonight tool tooth top
topic topple torch tornado tortoise toss total tourist
toward tower town toy track trade traffic tragic
train transfer trap trash travel tray treat tree
trend trial tribe trick trigger trim trip trophy
trouble truck true truly trumpet trust truth try
tube tuition tumble tuna tunnel turkey turn turtle
twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo
unfair unfold unhappy uniform unique unit universe unknown
unlock until unusual unveil update upgrade uphold upon
upper upset urban urge usage use used useful
useless usual utility vacant vacuum vague valid valley
valve van vanish vapor various vast vault vehicle
velvet vendor venture venue verb verify version very
vessel veteran viable vibrant vicious victory video view
village vintage violin virtual virus visa visit visual
vital vivid vocal voice void volcano volume vote
voyage wage wagon wait walk wall walnut want
warfare warm warrior wash wasp waste water wave
way wealth weapon wear weasel weather web wedding
weekend weird welcome west wet whale what wheat
wheel when where whip whisper wide width wife
wild will win window wine wing wink winner
winter wire wisdom wise wish witness wolf woman
wonder wood wool word work world worry worth
wrap wreck wrestle wrist write wrong yard year
yellow you young youth zebra zero zone zoo
"""

BIP39_WORDS: frozenset[str] = frozenset(_BIP39_WORDLIST_RAW.split())


# Tokens for splitting mnemonic candidates: lowercase ASCII letters only.
_BIP39_TOKEN_RE = re.compile(r"[a-z]+")
# Lengths of valid BIP-39 mnemonics, mapped to (rule, severity, fix).
_BIP39_LENGTHS: dict[int, tuple[str, str, str, str]] = {
    12: (
        "BIP-39 12-word mnemonic", "ES-WALLET-BIP39-12-01", "critical",
        "Treat the wallet as compromised. Move funds and generate a new seed offline.",
    ),
    24: (
        "BIP-39 24-word mnemonic", "ES-WALLET-BIP39-24-01", "critical",
        "Treat the wallet as compromised. Move funds and generate a new seed offline.",
    ),
    15: (
        "BIP-39 15-word mnemonic", "ES-WALLET-BIP39-PARTIAL-01", "high",
        "15-word seed phrase in source. Treat the wallet as compromised.",
    ),
    18: (
        "BIP-39 18-word mnemonic", "ES-WALLET-BIP39-PARTIAL-01", "high",
        "18-word seed phrase in source. Treat the wallet as compromised.",
    ),
    21: (
        "BIP-39 21-word mnemonic", "ES-WALLET-BIP39-PARTIAL-01", "high",
        "21-word seed phrase in source. Treat the wallet as compromised.",
    ),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

Severity = Literal["info", "warning", "high", "critical"]
OverallSeverity = Literal["Safe", "Warning", "High Risk", "Critical"]
FindingSource = Literal["static", "ast", "llm"]


@dataclass(slots=True)
class Finding:
    id: str
    severity: Severity
    category: str
    file: str
    line: int
    message: str
    snippet: str
    source: FindingSource
    suggested_fix: str = ""

    # Phase 0 compat: callers used `f.rule` for the human rule name. The
    # Phase 1+ stable handle is `f.id` — expose it under the old name.
    @property
    def rule(self) -> str:
        return self.id


@dataclass(slots=True)
class SkillManifest:
    name: str | None = None
    description: str | None = None
    declared_capabilities: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    source: str
    skill_root: str
    manifest: SkillManifest
    files_scanned: int
    bytes_scanned: int
    findings: list[Finding]
    risk_score: int
    severity: OverallSeverity
    suggested_fix: str
    warnings: list[str]
    llm_used: bool
    llm_provider: str  # "gemini" / "xai" / "anthropic" / "" if not used
    duration_ms: int

    # Phase 0 compat: derive the legacy 4-bucket label from risk_score.
    # Step 2 widens it to 5 buckets (adds "critical" >= 95).
    @property
    def risk_label(self) -> str:
        if self.risk_score == 0:
            return "clean"
        if self.risk_score < 25:
            return "low"
        if self.risk_score < 70:
            return "medium"
        if self.risk_score < 95:
            return "high"
        return "critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "skill_root": self.skill_root,
            "manifest": asdict(self.manifest),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "findings": [asdict(f) for f in self.findings],
            "risk_score": self.risk_score,
            "severity": self.severity,
            "risk_label": self.risk_label,
            "suggested_fix": self.suggested_fix,
            "warnings": list(self.warnings),
            "llm_used": self.llm_used,
            "llm_provider": self.llm_provider,
            "duration_ms": self.duration_ms,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Pass A — static (regex + entropy + ignore directive)
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_QUOTED_LITERAL_RE = re.compile(r"""(['"])([A-Za-z0-9_\-+/=]{20,})\1""")


def _finding_from_static_rule(
    rule: str, filename: str, lineno: int, line: str
) -> Finding:
    rule_id, severity, category, fix = _STATIC_RULE_META.get(
        rule, ("ES-STATIC-UNKNOWN", "warning", "credential_leak", "")
    )
    snippet = line.strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    return Finding(
        id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        category=category,
        file=filename,
        line=lineno,
        message=f"{rule} matched on line {lineno}.",
        snippet=snippet,
        source="static",
        suggested_fix=fix,
    )


def scan_text(text: str, filename: str = "<input>") -> list[Finding]:
    """Backwards-compat helper: regex ruleset only, no entropy, no ignore.

    Used by `wrapper.py` POST /scan. New code should call `scan_skill()`.
    Now scans the merged Step 2 ruleset (legacy + wallet + vendor).
    """
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line):
                out.append(_finding_from_static_rule(rule, filename, lineno, line))
    return out


def _detect_bip39_in_text(
    text: str, rel_path: str, fenced_safe_lines: set[int]
) -> list[Finding]:
    """Walk the token stream and flag any maximal run of BIP-39 words whose
    length matches a valid mnemonic. Suppresses matches inside Markdown code
    blocks tagged as text/example/bash so docs can reference test vectors.
    """
    out: list[Finding] = []
    # Build a flat list of (lineno, token) pairs.
    line_tokens: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if lineno in fenced_safe_lines:
            continue
        if IGNORE_DIRECTIVE_RE.search(line):
            continue
        for tok in _BIP39_TOKEN_RE.findall(line.lower()):
            line_tokens.append((lineno, tok))

    n = len(line_tokens)
    i = 0
    while i < n:
        if line_tokens[i][1] not in BIP39_WORDS:
            i += 1
            continue
        # Walk the maximal run of consecutive BIP-39 words from position i.
        j = i
        while j < n and line_tokens[j][1] in BIP39_WORDS:
            j += 1
        run_len = j - i

        # Runs much longer than a mnemonic are almost certainly the BIP-39
        # wordlist itself or a thesaurus — skip to avoid false positives.
        if run_len > 40:
            i = j
            continue

        # Fire on the longest mnemonic length that fits inside this run.
        # Anchor the snippet to the first window so the line points to the
        # actual phrase the reviewer needs to scrub. A run of 13–14 (e.g.
        # `SEED = "abandon … about"` where "seed" is itself a BIP-39 word)
        # still produces a clean 12-word fire.
        matched_len = 0
        for length in (24, 21, 18, 15, 12):
            if length <= run_len:
                matched_len = length
                break
        if matched_len:
            rule, rule_id, severity, fix = _BIP39_LENGTHS[matched_len]
            start_line = line_tokens[i][0]
            preview_words = [t for _, t in line_tokens[i:i + matched_len]]
            snippet = " ".join(preview_words)
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            out.append(
                Finding(
                    id=rule_id,
                    severity=severity,  # type: ignore[arg-type]
                    category="wallet_secret",
                    file=rel_path,
                    line=start_line,
                    message=f"{rule} detected ({matched_len} consecutive BIP-39 words).",
                    snippet=snippet,
                    source="static",
                    suggested_fix=fix,
                )
            )
        i = j  # advance past the entire run regardless
    return out


def _fenced_safe_line_set(text: str) -> set[int]:
    """Return the set of line numbers that fall inside a Markdown fenced
    code block whose info string marks it as docs/example/test material.
    """
    safe: set[int] = set()
    in_safe = False
    fence_re = re.compile(r"^```(\S*)")
    for lineno, line in enumerate(text.splitlines(), start=1):
        m = fence_re.match(line.strip())
        if m:
            tag = m.group(1).lower()
            if not in_safe:
                in_safe = tag in {"text", "txt", "example", "bash", "sh", "console"}
            else:
                in_safe = False
            continue
        if in_safe:
            safe.add(lineno)
    return safe


def _scan_static(file_path: Path, rel_path: str) -> list[Finding]:
    """Run Pass A on a single file. Honors `# estes: ignore` per line and
    placeholder/example guards on wallet & vendor patterns.
    """
    findings: list[Finding] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    suffix = file_path.suffix.lower()
    fenced_safe = _fenced_safe_line_set(text) if suffix == ".md" else set()

    # BIP-39 mnemonic walk runs once on the whole file (not per-line) because
    # phrases legitimately span multiple lines.
    findings.extend(_detect_bip39_in_text(text, rel_path, fenced_safe))

    seen_lines_with_specific_match: set[int] = set()

    for lineno, line in enumerate(text.splitlines(), start=1):
        if lineno in fenced_safe:
            continue
        if IGNORE_DIRECTIVE_RE.search(line):
            continue

        is_placeholder = bool(_PLACEHOLDER_RE.search(line))

        # Walk every rule. Wallet/vendor rules are skipped on placeholder lines.
        for rule, pattern in SECRET_PATTERNS.items():
            if not pattern.search(line):
                continue
            _, _, category, _ = _STATIC_RULE_META.get(
                rule, ("", "", "credential_leak", "")
            )
            is_high_signal = category in {
                "wallet_secret", "wallet_action", "high_value_token",
                "cloud_credential", "db_credential", "ssh_key",
            }
            if is_placeholder and is_high_signal:
                continue
            findings.append(_finding_from_static_rule(rule, rel_path, lineno, line))
            seen_lines_with_specific_match.add(lineno)

        # Entropy pass on long quoted literals, suppressed if a more specific
        # rule already fired on this line (avoid double-counting wallet keys).
        if lineno in seen_lines_with_specific_match:
            continue
        for m in _QUOTED_LITERAL_RE.finditer(line):
            literal = m.group(2)
            if _shannon_entropy(literal) >= 4.5:
                snippet = line.strip()[:200]
                findings.append(
                    Finding(
                        id="ES-ENTROPY-01",
                        severity="warning",
                        category="possible_secret",
                        file=rel_path,
                        line=lineno,
                        message="High-entropy string literal looks like a secret.",
                        snippet=snippet,
                        source="static",
                        suggested_fix=(
                            "If this is a secret, move it to env. If not, "
                            "consider shortening it."
                        ),
                    )
                )
                break  # one entropy hit per line is plenty
    return findings


def _scan_lightweight(file_path: Path, rel_path: str) -> list[Finding]:
    """Pass A* — JS/TS/Solidity wallet idiom regexes. No AST, just patterns.
    Honors `# estes: ignore` / `// estes: ignore` per line.
    """
    suffix = file_path.suffix.lower()
    findings: list[Finding] = []
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_DIRECTIVE_RE.search(line):
            continue
        for rule, (pattern, rule_id, severity, category, fix, suffixes) in (
            JS_WALLET_PATTERNS.items()
        ):
            if suffix not in suffixes:
                continue
            if not pattern.search(line):
                continue
            snippet = line.strip()
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            findings.append(
                Finding(
                    id=rule_id,
                    severity=severity,  # type: ignore[arg-type]
                    category=category,
                    file=rel_path,
                    line=lineno,
                    message=f"{rule} matched on line {lineno}.",
                    snippet=snippet,
                    source="static",
                    suggested_fix=fix,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Pass B — Python AST
# ---------------------------------------------------------------------------


def _flatten_attr(node: ast.AST) -> str | None:
    """Return dotted name for an attribute/name chain, or None."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _is_url_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if node.value.startswith(("http://", "https://")):
            return node.value
    return None


def _matches_secret_path(path: str) -> bool:
    return any(rx.search(path) for rx in SECRET_FILE_GLOBS)


def _is_wallet_rpc_host(host: str) -> bool:
    h = host.lower()
    return any(h == s.lstrip(".") or h.endswith(s) for s in WALLET_RPC_HOST_SUFFIXES)


# Names that strongly imply the value is a wallet secret.
_WALLET_ENV_NAMES = re.compile(
    r"(?i)(private[_-]?key|priv[_-]?key|mnemonic|seed[_-]?phrase|"
    r"secret[_-]?key|signing[_-]?key|wallet[_-]?key)"
)

# Functions that produce a wallet object from a secret.
_WALLET_FACTORY_FUNCS = {
    "Account.from_key", "Account.privateKeyToAccount",
    "eth_account.Account.from_key",
    "Keypair.from_seed", "Keypair.from_secret_key", "Keypair.from_bytes",
    "solders.keypair.Keypair.from_bytes",
    "solders.keypair.Keypair.from_seed",
}

# Functions that sign or broadcast EVM/Solana transactions.
_WALLET_SIGN_FUNCS = {
    "Account.sign_transaction", "Account.signTransaction",
    "w3.eth.account.sign_transaction",
    "w3.eth.send_raw_transaction", "w3.eth.sendRawTransaction",
    "web3.eth.send_raw_transaction", "web3.eth.sendRawTransaction",
    "web3.eth.sendTransaction",
    "Client.send_transaction", "AsyncClient.send_raw_transaction",
}


class _LeakVisitor(ast.NodeVisitor):
    """Pass B AST visitor. Tracks two parallel taint tables:

    * ``env_names``    — locals bound to ``os.environ[...]`` / ``os.getenv(...)``
    * ``wallet_names`` — locals bound to a wallet secret (factory call or env
                         read of a wallet-named variable)
    """

    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: list[Finding] = []
        self.env_names: set[str] = set()
        self.wallet_names: set[str] = set()
        # Per-function flag stack: did this function read any env var?
        self._function_touches_env: list[bool] = [False]

    # ---- bookkeeping ----------------------------------------------------

    def _enter_function(self) -> None:
        self._function_touches_env.append(False)

    def _exit_function(self) -> None:
        self._function_touches_env.pop()

    def _mark_env_touch(self) -> None:
        if self._function_touches_env:
            self._function_touches_env[-1] = True

    def _current_function_touches_env(self) -> bool:
        return any(self._function_touches_env)

    # ---- env detection --------------------------------------------------

    def _is_env_read(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Subscript):
            return _flatten_attr(node.value) == "os.environ"
        if isinstance(node, ast.Call):
            target = _flatten_attr(node.func)
            return target in {"os.environ.get", "os.getenv"}
        return False

    def _env_read_key(self, node: ast.AST) -> str | None:
        """If `node` is an env read with a literal key, return that key."""
        if isinstance(node, ast.Subscript) and _flatten_attr(node.value) == "os.environ":
            slc = node.slice
            if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                return slc.value
        if isinstance(node, ast.Call):
            target = _flatten_attr(node.func)
            if target in {"os.environ.get", "os.getenv"} and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    return first.value
        return None

    def _expr_touches_env(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if self._is_env_read(node):
            self._mark_env_touch()
            return True
        if isinstance(node, ast.Name) and node.id in self.env_names:
            self._mark_env_touch()
            return True
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self._expr_touches_env(v.value):
                    return True
        if isinstance(node, ast.BinOp):
            return self._expr_touches_env(node.left) or self._expr_touches_env(node.right)
        if isinstance(node, ast.Call):
            for a in node.args:
                if self._expr_touches_env(a):
                    return True
            for kw in node.keywords:
                if self._expr_touches_env(kw.value):
                    return True
        return False

    def _expr_touches_wallet(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name) and node.id in self.wallet_names:
            return True
        if isinstance(node, ast.Call):
            for a in node.args:
                if self._expr_touches_wallet(a):
                    return True
            for kw in node.keywords:
                if self._expr_touches_wallet(kw.value):
                    return True
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue) and self._expr_touches_wallet(v.value):
                    return True
        if isinstance(node, ast.BinOp):
            return self._expr_touches_wallet(node.left) or self._expr_touches_wallet(node.right)
        return False

    def _call_touches_env(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._expr_touches_env(arg):
                return True
        for kw in node.keywords:
            if self._expr_touches_env(kw.value):
                return True
        return False

    def _call_touches_wallet(self, node: ast.Call) -> bool:
        for arg in node.args:
            if self._expr_touches_wallet(arg):
                return True
        for kw in node.keywords:
            if self._expr_touches_wallet(kw.value):
                return True
        return False

    # ---- visitors -------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._enter_function()
        try:
            self.generic_visit(node)
        finally:
            self._exit_function()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._enter_function()
        try:
            self.generic_visit(node)
        finally:
            self._exit_function()

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Bind locals that are direct env reads so subsequent uses stay tainted.
        if self._is_env_read(node.value):
            self._mark_env_touch()
            key = self._env_read_key(node.value) or ""
            wallet_shaped = bool(_WALLET_ENV_NAMES.search(key))
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.env_names.add(target.id)
                    # Wallet-shaped env name OR target name is wallet-shaped
                    # → flag this binding and all downstream uses.
                    if wallet_shaped or _WALLET_ENV_NAMES.search(target.id):
                        self.wallet_names.add(target.id)
                        self._add(
                            node,
                            "ES-WALLET-PK-FROM-ENV-01",
                            "critical",
                            "wallet_secret",
                            "Code reads a wallet private key / mnemonic from "
                            "the environment. Make sure it is never logged, "
                            "printed, or sent over the network.",
                            self._snippet(node),
                            "Confirm the env var is provided by a hardware "
                            "wallet bridge or KMS, not a flat .env file.",
                        )

        # Wallet factory call → bind the result name.
        if isinstance(node.value, ast.Call):
            fname = _flatten_attr(node.value.func) or ""
            if fname in _WALLET_FACTORY_FUNCS or any(
                fname.endswith("." + suffix.split(".")[-1])
                for suffix in _WALLET_FACTORY_FUNCS
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.wallet_names.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = _flatten_attr(node.func) or ""
        snippet = self._snippet(node)

        # ------ wallet sign / send ------
        if func_name in _WALLET_SIGN_FUNCS or func_name.endswith(
            (".sign_transaction", ".signTransaction",
             ".send_raw_transaction", ".sendRawTransaction",
             ".sendTransaction", ".send_transaction")
        ):
            sev: Severity = "high"
            self._add(
                node, "ES-WALLET-SIGN-PY-01", sev, "wallet_action",
                f"{func_name}() signs or broadcasts a transaction.",
                snippet,
                "Surface a per-call confirmation prompt and never auto-sign.",
            )

        # Wallet factory → also fire as wallet_action so it's visible even
        # without an Assign target (e.g. inline `Account.from_key(pk).address`).
        if func_name in _WALLET_FACTORY_FUNCS:
            self._add(
                node, "ES-WALLET-FACTORY-PY-01", "high", "wallet_action",
                f"{func_name}() materializes a wallet from a secret.",
                snippet,
                "Make sure the secret arg is read from a vault, not a literal.",
            )

        # ------ wallet exfiltration through print / log / network ------
        if self._call_touches_wallet(node):
            if func_name == "print":
                self._add(
                    node, "ES-WALLET-PRINT-01", "critical", "wallet_secret",
                    "print() exposes a wallet secret to stdout — agent "
                    "frameworks pipe stdout straight into the LLM context.",
                    snippet,
                    "Remove the print or redact the wallet value first.",
                )
            elif "." in func_name:
                head, _, method = func_name.rpartition(".")
                head_root = head.split(".")[0]
                log_methods = {"debug", "info", "warning", "error",
                               "critical", "exception"}
                log_namespaces = {"logger", "log", "logging"}
                if head_root in log_namespaces and method in log_methods:
                    self._add(
                        node, "ES-WALLET-LOG-01", "critical", "wallet_secret",
                        f"{func_name}() logs a wallet secret.",
                        snippet,
                        "Strip the wallet value from the log call.",
                    )
                elif func_name in {
                    "requests.get", "requests.post", "requests.put",
                    "requests.patch", "requests.delete",
                    "httpx.get", "httpx.post",
                    "urllib.request.urlopen",
                }:
                    self._add(
                        node, "ES-WALLET-NET-EXFIL-01", "critical",
                        "wallet_secret",
                        f"{func_name}() sends a wallet secret over the network.",
                        snippet,
                        "Never include private keys / mnemonics in outbound "
                        "HTTP. Sign locally and ship only the signed payload.",
                    )

        # ------ legacy env leaks ------
        if func_name == "print" and self._call_touches_env(node):
            self._add(
                node, "ES-PRINT-ENV-01", "high", "credential_leak",
                "print() exposes environment variable contents to stdout, "
                "which agent frameworks inject into the LLM context.",
                snippet,
                "Remove the print or redact the env value before printing.",
            )
        elif "." in func_name:
            head, _, method = func_name.rpartition(".")
            log_methods = {"debug", "info", "warning", "error",
                           "critical", "exception"}
            log_namespaces = {"logger", "log", "logging"}
            head_root = head.split(".")[0]
            if (
                head_root in log_namespaces
                and method in log_methods
                and self._call_touches_env(node)
            ):
                self._add(
                    node, "ES-LOG-ENV-01", "high", "credential_leak",
                    f"{func_name}() logs environment variable contents.",
                    snippet,
                    "Strip the env value from the log call.",
                )

        # ------ exec / eval ------
        if func_name in {"eval", "exec", "__import__"} and node.args:
            first = node.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                self._add(
                    node, "ES-EXEC-01", "high", "dangerous_call",
                    f"{func_name}() called with a non-literal argument.",
                    snippet,
                    "Replace dynamic code execution with an explicit dispatch table.",
                )

        # ------ subprocess / os.system ------
        if func_name.startswith("subprocess."):
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self._add(
                        node, "ES-SUBPROC-SHELL-01", "warning", "dangerous_call",
                        f"{func_name}(..., shell=True) enables shell injection.",
                        snippet,
                        "Pass an argv list and drop shell=True.",
                    )
        if func_name == "os.system":
            self._add(
                node, "ES-OS-SYSTEM-01", "warning", "dangerous_call",
                "os.system() invokes a shell with the given string.",
                snippet,
                "Use subprocess.run([...]) without shell=True instead.",
            )

        # ------ secret file reads ------
        if func_name == "open" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                if _matches_secret_path(first.value):
                    self._add(
                        node, "ES-FILE-SECRET-READ-01", "high", "credential_leak",
                        f"open() reads a known credential path: {first.value!r}.",
                        snippet,
                        "Remove this read or move credentials into a vault.",
                    )

        # ------ phone-home (legacy) + wallet-RPC detection ------
        if func_name in {
            "requests.get", "requests.post", "requests.put",
            "requests.patch", "urllib.request.urlopen",
            "httpx.get", "httpx.post",
        }:
            url = _is_url_literal(node.args[0]) if node.args else None
            if url:
                host = (urlparse(url).hostname or "").lower()
                if host:
                    if _is_wallet_rpc_host(host):
                        self._add(
                            node, "ES-WALLET-RPC-PY-01", "warning", "wallet_action",
                            f"Outbound RPC call to wallet/blockchain host: {host}.",
                            snippet,
                            "Confirm the manifest discloses on-chain interaction "
                            "and that the user controls the signing flow.",
                        )
                    elif (
                        host not in NETWORK_ALLOWLIST
                        and self._current_function_touches_env()
                    ):
                        self._add(
                            node, "ES-NET-PHONEHOME-01", "warning",
                            "exfiltration_risk",
                            f"Outbound HTTP to {host} from a function that "
                            "touches env vars.",
                            snippet,
                            "Remove the network call or document and allowlist "
                            "the destination.",
                        )

        # ------ database connection with tainted secret ------
        if func_name in {
            "psycopg2.connect", "pymysql.connect", "pymongo.MongoClient",
            "redis.Redis", "redis.StrictRedis", "sqlalchemy.create_engine",
            "asyncpg.connect", "aiomysql.connect",
        } and self._call_touches_env(node):
            self._add(
                node, "ES-DB-CONN-PY-01", "warning", "db_credential",
                f"{func_name}() builds a DB connection from env vars — "
                "ensure the DSN is not logged or echoed.",
                snippet,
                "Wrap the connect call so the DSN never reaches stdout/logs.",
            )

        self.generic_visit(node)

    # ---- helpers --------------------------------------------------------

    def _snippet(self, node: ast.AST) -> str:
        try:
            text = ast.unparse(node)
        except Exception:
            text = ""
        text = text.strip().replace("\n", " ")
        return text[:200]

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        severity: Severity,
        category: str,
        message: str,
        snippet: str,
        suggested_fix: str,
    ) -> None:
        self.findings.append(
            Finding(
                id=rule_id,
                severity=severity,
                category=category,
                file=self.file,
                line=getattr(node, "lineno", 0),
                message=message,
                snippet=snippet,
                source="ast",
                suggested_fix=suggested_fix,
            )
        )


def _scan_ast(file_path: Path, rel_path: str) -> list[Finding]:
    if file_path.suffix.lower() != ".py":
        return []
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            Finding(
                id="ES-PARSE-ERR-01",
                severity="info",
                category="parse_error",
                file=rel_path,
                line=exc.lineno or 0,
                message=f"Could not parse Python source: {exc.msg}.",
                snippet="",
                source="ast",
                suggested_fix="",
            )
        ]
    visitor = _LeakVisitor(rel_path)
    visitor.visit(tree)
    return visitor.findings


# ---------------------------------------------------------------------------
# Pass C — LLM semantic check (Gemini → xAI → Anthropic)
# ---------------------------------------------------------------------------

LLM_SYSTEM_PROMPT = (
    "You are a security auditor reviewing a third-party AI agent skill. "
    "You are looking at a skill that may be invoked from a chat session "
    "where the user is connected to a crypto wallet or holds production "
    "credentials. You will be given the skill's manifest and a "
    "concatenated dump of its source files.\n\n"
    "Look for, in priority order:\n"
    "  1. Crypto wallet leaks — strings/code that look like private keys "
    "(0x hex, base58), seed phrases, BIP-39 mnemonics, keystore JSON, or "
    "env reads named PRIVATE_KEY / MNEMONIC / SEED_PHRASE.\n"
    "  2. Wallet actions — code that signs or broadcasts a transaction, "
    "instantiates a wallet from a secret, or contacts a JSON-RPC node "
    "provider (Infura, Alchemy, QuickNode, Helius, etc.).\n"
    "  3. Manifest mismatches — the skill says X but the code does Y "
    "(silent network calls, unrelated file reads, undeclared capabilities).\n"
    "  4. High-impact non-crypto secrets — SSH keys, DB connection strings, "
    "cloud provider keys, vendor-prefixed tokens (ghp_, sk_live_, xoxb-, ...)\n"
    "  5. Capability creep — code exercises capabilities the manifest does "
    "not declare.\n\n"
    "Severity rules:\n"
    "  - Anything the user CANNOT rotate (private keys, seed phrases) → "
    "'critical'.\n"
    "  - Unannounced transaction signing or RPC calls → 'high'.\n"
    "  - Manifest mismatch or undeclared network → 'warning'.\n\n"
    "Respond with a single JSON object and nothing else. Schema:\n"
    "{\n"
    '  "findings": [\n'
    '    {"id": "ES-SEM-...", "severity": "critical|high|warning|info", '
    '"category": "wallet_secret|wallet_action|credential_leak|cloud_credential|'
    'db_credential|ssh_key|high_value_token|semantic_mismatch", '
    '"file": "<relative path or empty>", "line": 0, '
    '"message": "<one sentence>", "snippet": "<<=200 chars>", '
    '"suggested_fix": "<one sentence>"}\n'
    "  ],\n"
    '  "summary": "<one sentence overall remediation, may be empty>"\n'
    "}\n"
    'If nothing is suspicious, return {"findings": [], "summary": ""}.'
)

# Allow-list for LLM-supplied categories. Anything else is downgraded.
_VALID_LLM_CATEGORIES = {
    "wallet_secret", "wallet_action",
    "credential_leak", "cloud_credential", "db_credential",
    "ssh_key", "high_value_token",
    "semantic_mismatch", "manifest", "exfiltration_risk",
    "dangerous_call", "possible_secret",
}


def _build_user_prompt(manifest: SkillManifest, code_dump: str, tree: str) -> str:
    manifest_text = manifest.description or "(no manifest description provided)"
    if len(manifest_text) > 4096:
        manifest_text = manifest_text[:4093] + "..."
    return (
        "SKILL MANIFEST:\n---\n"
        f"name: {manifest.name or '(unknown)'}\n"
        f"declared_capabilities: {manifest.declared_capabilities}\n"
        f"description: {manifest_text}\n"
        "---\n\n"
        "FILE TREE:\n"
        f"{tree}\n\n"
        "CODE (concatenated, truncated):\n"
        f"{code_dump}\n"
    )


def _build_code_dump(files: list[tuple[str, Path]], limit: int = 32_000) -> str:
    chunks: list[str] = []
    used = 0
    for rel, path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        header = f"\n# === {rel} ===\n"
        if used + len(header) >= limit:
            break
        remaining = limit - used - len(header)
        if remaining <= 0:
            break
        chunks.append(header + text[:remaining])
        used += len(header) + min(len(text), remaining)
        if used >= limit:
            break
    return "".join(chunks)


def _build_tree(files: list[tuple[str, Path]]) -> str:
    return "\n".join(rel for rel, _ in files[:200])


# ---- Provider HTTP shims -------------------------------------------------

def _call_gemini(model: str, api_key: str, system: str, user: str,
                 timeout_s: float) -> str:
    """Google Gemini generateContent. Asks for strict JSON via responseMimeType."""
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )
    resp = requests.post(
        url,
        headers={"Content-Type": "application/json"},
        json={
            "systemInstruction": {"role": "system", "parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": 1024,
                "responseMimeType": "application/json",
            },
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    data = resp.json()
    candidates = data.get("candidates") or []
    if not candidates:
        return ""
    parts = (candidates[0].get("content") or {}).get("parts") or []
    for part in parts:
        if isinstance(part, dict) and "text" in part:
            return part["text"]
    return ""


def _call_xai(model: str, api_key: str, system: str, user: str,
              timeout_s: float) -> str:
    resp = requests.post(
        "https://api.x.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices") or []
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message") or {}
        return msg.get("content", "") or ""
    return ""


def _call_anthropic(model: str, api_key: str, system: str, user: str,
                    timeout_s: float) -> str:
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=timeout_s,
    )
    resp.raise_for_status()
    data = resp.json()
    parts = data.get("content") or []
    for part in parts:
        if isinstance(part, dict) and part.get("type") == "text":
            return part.get("text", "")
    return ""


# ---- JSON parsing & coercion --------------------------------------------

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_llm_json(raw: str) -> dict[str, Any] | None:
    """Tolerate code fences and chatter around the JSON object."""
    if not raw:
        return None
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = _JSON_BLOCK_RE.search(text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


def _coerce_llm_findings(blob: dict[str, Any]) -> tuple[list[Finding], str]:
    raw_findings = blob.get("findings")
    out: list[Finding] = []
    if isinstance(raw_findings, list):
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            sev = item.get("severity", "warning")
            if sev not in {"info", "warning", "high", "critical"}:
                sev = "warning"
            cat = item.get("category", "semantic_mismatch")
            if cat not in _VALID_LLM_CATEGORIES:
                cat = "semantic_mismatch"
            out.append(
                Finding(
                    id=str(item.get("id", "ES-SEM-LLM-01"))[:64],
                    severity=sev,  # type: ignore[arg-type]
                    category=str(cat)[:64],
                    file=str(item.get("file", ""))[:200],
                    line=int(item.get("line", 0) or 0),
                    message=str(item.get("message", ""))[:500],
                    snippet=str(item.get("snippet", ""))[:200],
                    source="llm",
                    suggested_fix=str(item.get("suggested_fix", ""))[:500],
                )
            )
    summary = str(blob.get("summary", ""))[:500]
    return out, summary


# ---- Provider chooser ----------------------------------------------------

def _resolve_provider() -> tuple[str, str | None, str | None]:
    """Pick (provider, api_key, default_model) based on env config.

    Returns ("none", None, None) when no LLM should run. Honors:
      * ESTES_LLM_PROVIDER = "gemini"|"xai"|"anthropic"|"off"|"auto" (default)
      * GEMINI_API_KEY / XAI_API_KEY / ANTHROPIC_API_KEY
    """
    pinned = os.environ.get("ESTES_LLM_PROVIDER", "auto").strip().lower()

    if pinned == "off":
        return "off", None, None

    chain: list[tuple[str, str, str]] = [
        ("gemini", "GEMINI_API_KEY", "gemini-2.5-flash"),
        ("xai", "XAI_API_KEY", "grok-4-mini"),
        ("anthropic", "ANTHROPIC_API_KEY", "claude-haiku-4-5"),
    ]

    if pinned in {"gemini", "xai", "anthropic"}:
        for name, env_key, default_model in chain:
            if name == pinned:
                key = os.environ.get(env_key)
                return name, key, default_model
        return "none", None, None

    # auto: walk the chain and pick the first provider whose key is set.
    for name, env_key, default_model in chain:
        key = os.environ.get(env_key)
        if key:
            return name, key, default_model
    return "none", None, None


def _llm_semantic_check(
    manifest: SkillManifest,
    files: list[tuple[str, Path]],
    timeout_s: float,
) -> tuple[list[Finding], str, list[str], bool, str]:
    """Run Pass C. Returns (findings, summary, warnings, llm_used, provider)."""
    provider, api_key, default_model = _resolve_provider()
    if provider == "off":
        return [], "", ["LLM check disabled (ESTES_LLM_PROVIDER=off)."], False, ""
    if provider == "none" or not api_key:
        return (
            [], "",
            ["LLM check skipped: no provider API key found "
             "(set GEMINI_API_KEY, XAI_API_KEY, or ANTHROPIC_API_KEY)."],
            False, "",
        )

    model = os.environ.get("ESTES_LLM_MODEL") or (default_model or "")

    if provider == "gemini":
        caller = lambda u: _call_gemini(model, api_key, LLM_SYSTEM_PROMPT, u, timeout_s)  # noqa: E731
    elif provider == "xai":
        caller = lambda u: _call_xai(model, api_key, LLM_SYSTEM_PROMPT, u, timeout_s)  # noqa: E731
    elif provider == "anthropic":
        caller = lambda u: _call_anthropic(model, api_key, LLM_SYSTEM_PROMPT, u, timeout_s)  # noqa: E731
    else:
        return [], "", [f"LLM check skipped: unknown provider {provider!r}."], False, ""

    user_prompt = _build_user_prompt(
        manifest, _build_code_dump(files), _build_tree(files)
    )

    try:
        raw = caller(user_prompt)
    except requests.RequestException as exc:
        return [], "", [f"LLM check skipped ({provider}): HTTP error: {exc}"], False, provider
    except Exception as exc:  # noqa: BLE001
        return (
            [], "",
            [f"LLM check skipped ({provider}): {exc.__class__.__name__}: {exc}"],
            False, provider,
        )

    blob = _parse_llm_json(raw)
    if not isinstance(blob, dict):
        return (
            [], "",
            [f"LLM check skipped ({provider}): response was not valid JSON."],
            True, provider,
        )

    findings, summary = _coerce_llm_findings(blob)
    return findings, summary, [], True, provider


# ---------------------------------------------------------------------------
# Source resolution & extraction
# ---------------------------------------------------------------------------

_GITHUB_HOST_RE = re.compile(r"^https?://github\.com/", re.IGNORECASE)


def _is_github_url(s: str) -> bool:
    return bool(_GITHUB_HOST_RE.match(s))


def _parse_github_url(url: str) -> tuple[str, str, str | None, str | None] | None:
    """Returns (owner, repo, branch_or_None, subpath_or_None) or None."""
    m = re.match(
        r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(.+?))?/?$",
        url,
    )
    if not m:
        return None
    owner, repo, rest = m.group(1), m.group(2), m.group(3)
    branch: str | None = None
    subpath: str | None = None
    if rest:
        parts = rest.split("/", 1)
        if parts[0] == "tree" and len(parts) == 2:
            tail = parts[1].split("/", 1)
            branch = tail[0]
            if len(tail) == 2 and tail[1]:
                subpath = tail[1]
        elif parts[0] in {"blob", "raw"}:
            tail = parts[1].split("/", 1) if len(parts) == 2 else []
            if tail:
                branch = tail[0]
                if len(tail) == 2:
                    subpath = tail[1]
    return owner, repo, branch, subpath


def _github_default_branch(owner: str, repo: str, timeout_s: float) -> str:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}",
        headers=headers,
        timeout=timeout_s,
    )
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


def _fetch_github_zip(
    owner: str,
    repo: str,
    branch: str,
    dest_zip: Path,
    timeout_s: float,
    max_bytes: int,
) -> None:
    """Stream a codeload zip to disk; abort and unlink if total > max_bytes."""
    headers: dict[str, str] = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    resp = requests.get(url, headers=headers, timeout=timeout_s, stream=True)
    resp.raise_for_status()

    total = 0
    f = dest_zip.open("wb")
    try:
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                f.close()
                dest_zip.unlink(missing_ok=True)
                raise requests.RequestException(
                    f"GitHub archive exceeded max_bytes={max_bytes}; "
                    f"aborted at {total} bytes."
                )
            f.write(chunk)
    finally:
        if not f.closed:
            f.close()


def _safe_extract(
    zip_path: Path, dest_dir: Path, max_bytes: int
) -> tuple[int, list[str]]:
    """Extract zip_path into dest_dir, defending against traversal & bombs."""
    warnings_out: list[str] = []
    total = 0
    per_file_cap = max_bytes // 4
    dest_resolved = dest_dir.resolve()

    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        return 0, [f"Not a valid zip: {zip_path.name}"]

    with zf:
        for info in zf.infolist():
            name = info.filename
            if not name or name.endswith("/"):
                continue
            if Path(name).is_absolute() or ".." in Path(name).parts:
                warnings_out.append(f"Skipped traversal entry: {name}")
                continue
            if (info.external_attr >> 28) == 0o12:
                warnings_out.append(f"Skipped symlink entry: {name}")
                continue
            if info.file_size > per_file_cap:
                warnings_out.append(
                    f"Skipped oversized entry ({info.file_size} bytes): {name}"
                )
                continue
            if total + info.file_size > max_bytes:
                warnings_out.append(
                    f"Aborted extract at max_bytes={max_bytes}; "
                    "remaining entries skipped."
                )
                break

            target = (dest_dir / name).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                warnings_out.append(f"Skipped escape entry: {name}")
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target.open("wb") as dst:
                data = src.read(per_file_cap + 1)
                if len(data) > per_file_cap:
                    warnings_out.append(f"Skipped runtime-oversized entry: {name}")
                    target.unlink(missing_ok=True)
                    continue
                dst.write(data)
                total += len(data)

    return total, warnings_out


def _resolve_source(
    source: str | Path,
    workspace: Path,
    *,
    timeout_s: float,
    max_bytes: int,
) -> tuple[Path | None, list[str]]:
    """Materialize the skill into workspace/skill/. Returns (root, warnings)."""
    warnings_out: list[str] = []
    skill_dir = workspace / "skill"
    skill_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = workspace / "source"
    raw_dir.mkdir(parents=True, exist_ok=True)

    src_str = str(source)

    if _is_github_url(src_str):
        parsed = _parse_github_url(src_str)
        if parsed is None:
            warnings_out.append(f"Could not parse GitHub URL: {src_str}")
            return None, warnings_out
        owner, repo, branch, subpath = parsed
        try:
            if branch is None:
                branch = _github_default_branch(owner, repo, timeout_s)
            archive_path = raw_dir / f"{repo}-{branch.replace('/', '_')}.zip"
            _fetch_github_zip(owner, repo, branch, archive_path, timeout_s, max_bytes)
        except requests.RequestException as exc:
            warnings_out.append(f"GitHub fetch failed: {exc}")
            return None, warnings_out
        _, extract_warnings = _safe_extract(archive_path, skill_dir, max_bytes)
        warnings_out.extend(extract_warnings)
        children = [p for p in skill_dir.iterdir() if p.is_dir()]
        root = children[0] if len(children) == 1 else skill_dir
        if subpath:
            candidate = (root / subpath).resolve()
            try:
                candidate.relative_to(root.resolve())
            except ValueError:
                warnings_out.append(f"Subpath escapes archive root: {subpath}")
                return None, warnings_out
            if not candidate.exists():
                warnings_out.append(f"Subpath not found in archive: {subpath}")
                return None, warnings_out
            root = candidate
        return root, warnings_out

    if src_str.startswith(("git@", "ssh://")):
        warnings_out.append("SSH git URLs are not supported.")
        return None, warnings_out

    p = Path(src_str).expanduser()
    if not p.exists():
        warnings_out.append(f"Source not found: {p}")
        return None, warnings_out

    if p.is_file() and p.suffix.lower() == ".zip":
        _, extract_warnings = _safe_extract(p, skill_dir, max_bytes)
        warnings_out.extend(extract_warnings)
        children = [c for c in skill_dir.iterdir() if c.is_dir()]
        root = children[0] if len(children) == 1 else skill_dir
        return root, warnings_out

    if p.is_file():
        target = skill_dir / p.name
        target.write_bytes(p.read_bytes())
        return skill_dir, warnings_out

    if p.is_dir():
        shutil.copytree(p, skill_dir, dirs_exist_ok=True, symlinks=False)
        return skill_dir, warnings_out

    warnings_out.append(f"Unsupported source shape: {p}")
    return None, warnings_out


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _discover_manifest(skill_root: Path) -> SkillManifest:
    for name in MANIFEST_NAMES:
        path = skill_root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]

                data = yaml.safe_load(text) or {}
            except Exception:
                data = {}
            if isinstance(data, dict):
                return SkillManifest(
                    name=str(data.get("name")) if data.get("name") else None,
                    description=str(data.get("description") or text[:4096]),
                    declared_capabilities=list(data.get("capabilities") or []),
                )

        if path.suffix.lower() == ".json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                return SkillManifest(
                    name=str(data.get("name")) if data.get("name") else None,
                    description=str(data.get("description") or text[:4096]),
                    declared_capabilities=list(data.get("capabilities") or []),
                )

        # Markdown: pull first H1 as name, body as description.
        name_match = re.search(r"^#\s+(.+)$", text, re.MULTILINE)
        return SkillManifest(
            name=name_match.group(1).strip() if name_match else None,
            description=text[:4096],
            declared_capabilities=[],
        )

    return SkillManifest()


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SCANNABLE_SUFFIXES:
            yield path


def _discover_files(
    skill_root: Path, max_bytes: int
) -> tuple[list[tuple[str, Path]], int, list[Finding]]:
    files: list[tuple[str, Path]] = []
    bytes_used = 0
    oversize: list[Finding] = []
    for path in _iter_files(skill_root):
        rel = path.relative_to(skill_root).as_posix()
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > DEFAULT_PER_FILE_BYTES:
            oversize.append(
                Finding(
                    id="ES-FILE-OVERSIZE-01",
                    severity="info",
                    category="scan_skipped",
                    file=rel,
                    line=0,
                    message=(
                        f"File skipped: {size} bytes exceeds per-file cap "
                        f"({DEFAULT_PER_FILE_BYTES})."
                    ),
                    snippet="",
                    source="static",
                    suggested_fix="",
                )
            )
            continue
        if bytes_used + size > max_bytes:
            break
        files.append((rel, path))
        bytes_used += size
    return files, bytes_used, oversize


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

# Per-severity base weight.
_SEVERITY_WEIGHT: dict[str, int] = {
    "critical": 80,
    "high": 30,
    "warning": 10,
    "info": 2,
}

# Per-category multiplier — wallet leaks dominate the score.
_CATEGORY_MULTIPLIER: dict[str, float] = {
    "wallet_secret": 2.0,
    "wallet_action": 1.5,
    "ssh_key": 1.5,
    "cloud_credential": 1.3,
    "db_credential": 1.2,
    "high_value_token": 1.2,
}


def _compute_score(findings: list[Finding]) -> int:
    total = 0.0
    for f in findings:
        base = _SEVERITY_WEIGHT.get(f.severity, 0)
        mult = _CATEGORY_MULTIPLIER.get(f.category, 1.0)
        total += base * mult
    return min(100, int(round(total)))


def _compute_severity(findings: list[Finding], score: int) -> OverallSeverity:
    n_crit = sum(1 for f in findings if f.severity == "critical")
    n_high = sum(1 for f in findings if f.severity == "high")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    if n_crit >= 1 or score >= 95:
        return "Critical"
    if n_high >= 1 or score >= 70:
        return "High Risk"
    if n_warn >= 1 or score >= 25:
        return "Warning"
    return "Safe"


def _rollup_suggested_fix(findings: list[Finding], llm_summary: str) -> str:
    n_crit = sum(1 for f in findings if f.severity == "critical")
    n_high = sum(1 for f in findings if f.severity == "high")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    if n_crit:
        base = (
            f"DO NOT INSTALL. {n_crit} critical leak(s) detected — likely an "
            "unrotatable wallet secret or live payment key. Treat any "
            "associated wallet/account as compromised and rotate or migrate "
            "funds immediately."
        )
    elif n_high:
        base = (
            f"Remove credential leaks before installing this skill. "
            f"See the {n_high} high-severity finding(s)."
        )
    elif n_warn:
        base = (
            f"Review the {n_warn} warning(s); this skill may exceed its "
            "declared capabilities."
        )
    else:
        base = "No actionable issues detected."
    if llm_summary:
        base = f"{base}\n{llm_summary}"
    return base


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates by (file, line, id) and collapse wallet/entropy overlap."""
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.file, f.line, f.id)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)

    # If a wallet_secret finding sits on the same (file, line) as an entropy
    # warning, drop the entropy one — the more specific rule wins.
    wallet_lines = {(f.file, f.line) for f in out if f.category == "wallet_secret"}
    out = [
        f for f in out
        if not (f.id == "ES-ENTROPY-01" and (f.file, f.line) in wallet_lines)
    ]
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_skill(
    source: str | Path,
    *,
    llm: bool = True,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ScanReport:
    """Scan a skill from a local path, archive, or public GitHub URL.

    Parameters
    ----------
    source
        Local file, local dir, local `.zip`, or `https://github.com/...` URL.
    llm
        Run the LLM semantic pass when an API key is configured. Falls back
        to static + AST only on any error.
    timeout_s
        Per-network-call timeout (GitHub fetch, LLM request).
    max_bytes
        Total bytes read into memory across all scanned files.

    Returns
    -------
    ScanReport
        Always returns. Errors land in `report.warnings`; never raises on a
        bad skill.
    """
    started = time.monotonic()
    src_str = str(source)
    warnings_out: list[str] = []
    log.debug("scan_skill start: source=%s llm=%s", src_str, llm)

    with tempfile.TemporaryDirectory(prefix="estes_") as tmp:
        workspace = Path(tmp)
        skill_root, resolve_warnings = _resolve_source(
            source, workspace, timeout_s=timeout_s, max_bytes=max_bytes
        )
        warnings_out.extend(resolve_warnings)

        if skill_root is None:
            return ScanReport(
                source=src_str,
                skill_root="",
                manifest=SkillManifest(),
                files_scanned=0,
                bytes_scanned=0,
                findings=[],
                risk_score=0,
                severity="Safe",
                suggested_fix="No actionable issues detected.",
                warnings=warnings_out,
                llm_used=False,
                llm_provider="",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        manifest = _discover_manifest(skill_root)
        files, bytes_used, oversize = _discover_files(skill_root, max_bytes)

        findings: list[Finding] = list(oversize)
        for rel, path in files:
            findings.extend(_scan_static(path, rel))
            findings.extend(_scan_lightweight(path, rel))
            findings.extend(_scan_ast(path, rel))

        if not manifest.description:
            findings.append(
                Finding(
                    id="ES-MANIFEST-MISSING-01",
                    severity="warning",
                    category="manifest",
                    file="",
                    line=0,
                    message="No SKILL.md / manifest found at the skill root.",
                    snippet="",
                    source="static",
                    suggested_fix=(
                        "Add a SKILL.md describing what the skill does and "
                        "the data it touches."
                    ),
                )
            )

        llm_used = False
        llm_summary = ""
        provider_used = ""
        if llm:
            llm_findings, llm_summary, llm_warnings, llm_used, provider_used = (
                _llm_semantic_check(manifest, files, timeout_s)
            )
            findings.extend(llm_findings)
            warnings_out.extend(llm_warnings)

        findings = _dedupe(findings)
        score = _compute_score(findings)
        severity = _compute_severity(findings, score)
        suggested = _rollup_suggested_fix(findings, llm_summary)
        log.debug(
            "scan_skill done: severity=%s score=%d findings=%d files=%d",
            severity, score, len(findings), len(files),
        )

        return ScanReport(
            source=src_str,
            skill_root=str(skill_root.relative_to(workspace)),
            manifest=manifest,
            files_scanned=len(files),
            bytes_scanned=bytes_used,
            findings=findings,
            risk_score=score,
            severity=severity,
            suggested_fix=suggested,
            warnings=warnings_out,
            llm_used=llm_used,
            llm_provider=provider_used,
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def scan_path(root: str | Path) -> ScanReport:
    """Compatibility shim for Phase 0 callers (Streamlit + FastAPI)."""
    return scan_skill(root, llm=False)


def redact_text(text: str, marker: str = "[REDACTED by Estes]") -> tuple[str, int]:
    """Apply every Pass A regex (legacy + wallet + vendor) to text.

    Returns (redacted_text, count). Used by `wrapper.py /redact`.
    """
    count = 0
    for pattern in SECRET_PATTERNS.values():
        text, n = pattern.subn(marker, text)
        count += n
    return text, count


__all__ = [
    "Finding",
    "ScanReport",
    "SkillManifest",
    "SECRET_PATTERNS",
    "SECRET_PATTERNS_LEGACY",
    "SECRET_PATTERNS_WALLET",
    "SECRET_PATTERNS_VENDOR",
    "JS_WALLET_PATTERNS",
    "BIP39_WORDS",
    "redact_text",
    "scan_path",
    "scan_skill",
    "scan_text",
]
