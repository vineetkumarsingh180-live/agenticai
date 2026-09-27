# 🔐 Secure Coding Assistant — LangGraph + Gemini

An autonomous AI agent that identifies software vulnerabilities and automatically applies secure fixes, powered by **LangGraph** and **Google Gemini 2.5 Flash**.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     LangGraph Agent                     │
│                                                         │
│  ┌──────────────────┐     ┌──────────────────────────┐  │
│  │  analyze_        │────▶│  generate_patch          │  │
│  │  vulnerabilities │     │  (Gemini structured LLM) │  │
│  │  (Gemini)        │     └────────────┬─────────────┘  │
│  └──────────────────┘                  │                 │
│                                        ▼                 │
│                               ┌─────────────────┐       │
│                               │  verify_patch   │       │
│                               │  (AST / static) │       │
│                               └────────┬────────┘       │
│                            pass        │     fail (<3x)  │
│                      ┌─────────────────┘                 │
│                      ▼          ▲ retry                  │
│             ┌─────────────────┐ └──────────────┐         │
│             │ generate_report │                │         │
│             │ (.md + .pdf)    │                │         │
│             └────────┬────────┘                │         │
│                      ▼                         │         │
│                    END                         │         │
└─────────────────────────────────────────────────────────┘
```

---

## Setup

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Add your Gemini API key
Edit `.env`:
```
GOOGLE_API_KEY=your_gemini_api_key_here
```
Get a free key at: https://aistudio.google.com/app/apikey

---

## Usage

### Scan a single file
```bash
python main.py --file test_sample.py
```

### Scan multiple files in parallel
```bash
python main.py --file app.py utils.py login.php --workers 4
```

### Custom output directory
```bash
python main.py --file vulnerable.py --out my_reports
```

---

## Output

For each scanned file, the agent produces inside `output/`:

| File | Description |
|------|-------------|
| `patched_<name>.py` | Secure, fixed version of the source code |
| `report_<name>.md` | Markdown audit report |
| `report_<name>.pdf` | Professional PDF report with severity badges |

---

## Supported Languages

| Extension | Language   |
|-----------|------------|
| `.py`     | Python     |
| `.js`     | JavaScript |
| `.ts`     | TypeScript |
| `.php`    | PHP        |
| `.java`   | Java       |
| `.c`      | C          |
| `.cpp`    | C++        |
| `.rb`     | Ruby       |
| `.go`     | Go         |

---

## What the Report Contains

1. **Vulnerability Findings**
   - CWE ID and title
   - Severity (CRITICAL / HIGH / MEDIUM / LOW)
   - Exact vulnerable line numbers
   - Risk & Impact description
   - Technical breakdown

2. **Remediations & Patches Applied**
   - Human-readable change summary
   - Complete patched source code

3. **Syntax Validation Status** — automatically retries up to 3× if Python syntax check fails

---

## Project Structure

```
internships/
├── main.py          # Entry point (single + parallel scan)
├── graph.py         # LangGraph agent graph (4 nodes)
├── schemas.py       # Pydantic models for structured LLM output
├── report.py        # PDF report generator (ReportLab)
├── requirements.txt
├── .env             # Your GOOGLE_API_KEY goes here
└── test_sample.py   # Example vulnerable file (SQL Injection)
```
