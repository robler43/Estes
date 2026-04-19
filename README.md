# Estes

**The AI-powered bouncer for third-party AI agent skills**

**Runtime supply-chain security for agentic AI**
Protecting OpenClaw, Antigravity, Claude Code, and watsonx Orchestrate-style agents from silent credential leaks and tool-output poisoning.

---

## 🎯 Problem This Project Solves

Recent research (April 2026) audited **17,022 publicly available third-party AI agent skills** and discovered:

- **3.1%** are actively leaking real API keys, OAuth tokens, and passwords **during normal execution**.
- **73.5%** of leaks come from simple leftover `print()` / `console.log()` debug statements.
- Agent frameworks (Claude Code, OpenClaw, Antigravity, LangGraph, etc.) automatically capture stdout and **inject it straight into the LLM context window**.
- Once the secret is in the context, **anyone continuing the chat or receiving a shared/exported history** can retrieve the key with a normal follow-up question.

This is a **silent, no-hack-required supply-chain vulnerability** that affects every developer and enterprise using agent skills.

IBM has explicitly called out this class of risk in their April 2026 agentic security announcements, emphasizing the need for runtime guardrails and governance in platforms like **watsonx Orchestrate** (which ships with 500+ third-party skills).

## 🛡️ What Estes Does

Estes is a **two-layer defense** built specifically for this problem:

### 1. Pre-Install Auditor (Skill Checkup)

- User uploads any third-party skill (`.zip` or GitHub URL).
- AI + static analysis scans for:
  - Debug prints dumping environment variables
  - Semantic mismatches between `SKILL.md` description and actual code
  - Credential file reads or secret handling
- Returns a clear **Risk Score (0–100)** + detailed findings + suggested fixes.

### 2. Runtime Wrapper / Bouncer (Middleware)

- Runs as a lightweight local FastAPI proxy (`estes start`).
- Intercepts **every tool output** before it reaches the LLM context.
- Automatically detects and **redacts secrets** in real time.
- Adds a warning log and optional human approval gate.
- Keeps chat histories safe even if shared or exported.

### 3. Bonus IBM-Aligned Features

- Governance Recommendations section (maps directly to watsonx.governance).
- Simple compliance report export (JSON) for enterprise audit trails.

## 🎯 Why This Matters (Hook 'Em Hacks + IBM Track)

This project directly addresses the **"Security in an AI-First World"** track sponsored by IBM.

It solves the exact supply-chain and runtime leakage problems IBM is highlighting with watsonx Orchestrate and Guardium AI Security. By adding observability and policy enforcement to open agent ecosystems, Estes helps enterprises adopt agentic AI safely and at scale.

## 🏗️ Architecture

```
User → Antigravity / OpenClaw / Claude Code
            ↓
   Third-party Skill runs
            ↓
   Tool Output (stdout + result)
            ↓
   Estes Wrapper (localhost:8000)
            ↓
   Secret Detection + Redaction
            ↓
   Clean Output → LLM Context Window
```

- **Auditor**: Standalone Streamlit web app
- **Wrapper**: FastAPI server (middleware)
- **Integration**: Local proxy (easy to point Antigravity tool output through)

## 🚀 Quick Start

```bash
cd /Users/robinhoesli/Desktop/projects/Estes

# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the Auditor (frontend + scanner)
streamlit run app.py

# 3. (Optional) Run the Runtime Wrapper
uvicorn wrapper:app --reload
# or, once the CLI is added:
estes start
```

## 📁 Project Structure

```
Estes/
├── app.py                    # Streamlit frontend + Auditor UI
├── auditor.py                # Core skill scanning logic
├── wrapper.py                # FastAPI runtime bouncer
├── requirements.txt
├── README.md
├── demo/
│   └── weather_tool/         # Example leaky skill for demos
├── handoff/                  # Three-Man-Team handoff files
└── tests/                    # (future)
```

## 🧪 Demo Flow (for Hook 'Em Hacks judges)

1. Upload the `weather_tool` from the `demo/` folder.
2. See **High Risk** score + exact findings.
3. Run Live Demo → **Before** (key leaks) vs **After** (Estes redacts it).
4. Show that the chat remains safe even if shared or exported.

## 🛠 Tech Stack

- **Frontend**: Streamlit (dark theme, neon green accents)
- **Backend**: FastAPI + Uvicorn
- **AI Analysis**: Grok / Claude Haiku (via API)
- **Parsing**: Python AST + regex for debug prints
- **Target Platforms**: Antigravity (Claude), OpenClaw, Claude Code, watsonx Orchestrate

## 🔮 Future Roadmap (IBM Alignment)

- Native watsonx.governance API integration for centralized policy & audit logging
- Auto-patch generation (fix the skill and return a clean version)
- Chat Shield warning before sharing/exporting conversations
- CLI tool (`estes scan` and `estes start`)

## 📌 Built For

- **Hook 'Em Hacks 2026** — *Security in an AI-First World* track (IBM Sponsored)
- Real developers using Antigravity, OpenClaw, and agent marketplaces
- Enterprises deploying agentic AI securely

---

*Project created by Robin Ho (for Hook 'Em Hacks 2026)*
*Last updated: April 18, 2026*
