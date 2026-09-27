import ast
import os
import time
from pathlib import Path
from typing import TypedDict, Optional, List

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END

from schemas import VulnerabilityAnalysis, PatchResult, ValidationResult
from report import generate_pdf_report

# ── LLM ──────────────────────────────────────────────────────────────────────
# Lazy-initialized so the module can be imported without a key present.
_llm = None

def get_llm():
    global _llm
    if _llm is None:
        api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "No Gemini API key found. "
                "Set GOOGLE_API_KEY in your .env file or environment."
            )
        _llm = ChatGoogleGenerativeAI(
            model="gemini-3.8-flash",
            temperature=0.1,
            google_api_key=api_key,
        )
    return _llm


def invoke_with_retry(chain, inputs: dict, max_retries: int = 5):
    """Invoke a LangChain chain with automatic retry on 429 rate-limit errors."""
    import re
    for attempt in range(max_retries):
        try:
            return chain.invoke(inputs)
        except Exception as e:
            err_str = str(e)
            # Check for rate limit (429 RESOURCE_EXHAUSTED)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                # Try to parse retry delay from API error message
                match = re.search(r"retry in (\d+(?:\.\d+)?)s", err_str)
                wait = float(match.group(1)) if match else min(30 * (2 ** attempt), 120)
                print(f"  [Rate limit] Waiting {wait:.0f}s before retry {attempt + 1}/{max_retries}...")
                time.sleep(wait)
            else:
                raise  # non-rate-limit errors bubble up immediately
    raise RuntimeError(f"LLM call failed after {max_retries} retries (rate limit).")

# ── State ─────────────────────────────────────────────────────────────────────
class AgentState(TypedDict):
    file_path: str
    original_code: str
    language: str
    analysis: Optional[VulnerabilityAnalysis]
    patch: Optional[PatchResult]
    validation: Optional[ValidationResult]
    retry_count: int
    final_report_md: Optional[str]
    final_report_pdf: Optional[str]


# ── Node 1 : Vulnerability Detection ─────────────────────────────────────────
def analyze_vulnerabilities_node(state: AgentState) -> dict:
    code_with_lines = "\n".join(
        f"{idx + 1:4d} | {line}"
        for idx, line in enumerate(state["original_code"].splitlines())
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", (
            "You are a Senior Application Security Auditor. "
            "Examine the source code line by line. Identify all security weaknesses, "
            "the exact vulnerable line numbers, CWE categories, severity, risk and impact. "
            "You MUST always return a valid structured response. "
            "If no vulnerabilities are found, return has_vulnerabilities=false and an empty list."
        )),
        ("user", "Language: {language}\n\nCode with line numbers:\n{code}")
    ])

    analyzer = prompt | get_llm().with_structured_output(VulnerabilityAnalysis)
    result = invoke_with_retry(analyzer, {
        "language": state["language"],
        "code": code_with_lines,
    })
    return {"analysis": result}


# ── Node 2 : Patch Generation ─────────────────────────────────────────────────
def generate_patch_node(state: AgentState) -> dict:
    feedback = ""
    if state.get("validation") and not state["validation"].is_valid_syntax:
        feedback = (
            f"\nPrevious attempt failed syntax check: "
            f"{state['validation'].error_message}. Fix this syntax error."
        )

    prompt = ChatPromptTemplate.from_messages([
        ("system", (
            "You are an expert secure systems engineer. "
            "Given the original code and the identified vulnerabilities, produce a complete, "
            "secure replacement that resolves every security flaw while preserving all existing "
            "business logic, naming conventions, and runtime interfaces. "
            "You MUST always return a valid structured response with patched_code and changes_made."
        )),
        ("user", (
            "Language: {language}\n"
            "Original Code:\n{original_code}\n\n"
            "Identified Vulnerabilities:\n{analysis}\n"
            "{feedback}"
        ))
    ])

    patcher = prompt | get_llm().with_structured_output(PatchResult)
    result = invoke_with_retry(patcher, {
        "language": state["language"],
        "original_code": state["original_code"],
        "analysis": state["analysis"].model_dump_json(indent=2) if state["analysis"] else "None",
        "feedback": feedback,
    })
    return {
        "patch": result,
        "retry_count": state.get("retry_count", 0) + 1,
    }


# ── Node 3 : Automated Verification ──────────────────────────────────────────
def verify_patch_node(state: AgentState) -> dict:
    patched_code = state["patch"].patched_code
    lang = state["language"].lower()

    if lang == "python":
        try:
            ast.parse(patched_code)
            syntax_ok = True
            err = None
        except SyntaxError as e:
            syntax_ok = False
            err = f"SyntaxError on line {e.lineno}: {e.msg}"
    else:
        # Non-Python: trust the model; flag obvious emptiness
        syntax_ok = bool(patched_code.strip())
        err = None if syntax_ok else "Empty patch returned."

    return {
        "validation": ValidationResult(
            is_valid_syntax=syntax_ok,
            error_message=err,
            vulnerabilities_resolved=syntax_ok,
        )
    }


# ── Conditional routing ───────────────────────────────────────────────────────
def should_retry_patch(state: AgentState) -> str:
    val = state.get("validation")
    if val and not val.is_valid_syntax and state.get("retry_count", 0) < 3:
        return "generate_patch"
    return "generate_report"


# ── Node 4 : Report Generation ────────────────────────────────────────────────
def generate_report_node(state: AgentState) -> dict:
    analysis = state["analysis"]
    patch    = state["patch"]
    val      = state["validation"]

    md = [
        "# Secure Code Audit & Remediation Report",
        f"**Target File:** `{state['file_path']}`  ",
        f"**Language:** `{state['language']}`  ",
        f"**Syntax Validation:** `{'PASSED' if val and val.is_valid_syntax else 'FAILED'}`\n",
        "---",
        "## 1. Vulnerability Findings\n",
    ]

    if not analysis or not analysis.vulnerabilities:
        md.append("No security vulnerabilities detected.")
    else:
        for idx, v in enumerate(analysis.vulnerabilities, 1):
            md.extend([
                f"### Finding {idx}: {v.title} ({v.cwe_id})",
                f"- **Severity:** {v.severity}",
                f"- **Vulnerable Lines:** `{v.vulnerable_lines}`",
                f"- **Risk & Impact:** {v.risk_impact}",
                f"- **Technical Breakdown:** {v.explanation}\n",
            ])

    md.extend([
        "---",
        "## 2. Remediations & Patches Applied\n",
        "### Key Changes Made:",
    ])
    if patch:
        for ch in patch.changes_made:
            md.append(f"- {ch}")
        md.extend([
            "\n### Patched Source Code:",
            f"```{state['language']}",
            patch.patched_code,
            "```",
        ])

    md_content = "\n".join(md)

    # PDF generation — stored next to other outputs
    out_dir = Path("output")
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(state["file_path"]).stem
    pdf_path = str(out_dir / f"report_{stem}.pdf")
    try:
        generate_pdf_report(state, pdf_path)
    except Exception:
        pdf_path = None

    return {
        "final_report_md": md_content,
        "final_report_pdf": pdf_path,
    }


# ── Build Graph ───────────────────────────────────────────────────────────────
def build_secure_agent_graph():
    workflow = StateGraph(AgentState)

    workflow.add_node("analyze_vulnerabilities", analyze_vulnerabilities_node)
    workflow.add_node("generate_patch",          generate_patch_node)
    workflow.add_node("verify_patch",            verify_patch_node)
    workflow.add_node("generate_report",         generate_report_node)

    workflow.set_entry_point("analyze_vulnerabilities")
    workflow.add_edge("analyze_vulnerabilities", "generate_patch")
    workflow.add_edge("generate_patch",          "verify_patch")

    workflow.add_conditional_edges(
        "verify_patch",
        should_retry_patch,
        {
            "generate_patch":  "generate_patch",
            "generate_report": "generate_report",
        },
    )
    workflow.add_edge("generate_report", END)

    return workflow.compile()