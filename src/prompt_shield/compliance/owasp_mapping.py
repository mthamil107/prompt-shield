"""OWASP LLM Top 10 compliance mapping for prompt-shield detectors."""

from __future__ import annotations

from pydantic import BaseModel


class OwaspCategory(BaseModel):
    """An OWASP LLM Top 10 category."""

    id: str
    name: str
    description: str
    url: str


class CategoryCoverage(BaseModel):
    """Coverage details for a single OWASP category."""

    category_id: str
    name: str
    covered: bool
    detector_ids: list[str]
    detector_names: list[str]


class ComplianceReport(BaseModel):
    """Full OWASP compliance report."""

    owasp_version: str
    total_detectors: int
    categories_covered: int
    categories_not_covered: int
    coverage_percentage: float
    category_details: list[CategoryCoverage]


# OWASP Top 10 for LLM Applications (2025)
OWASP_LLM_TOP_10: list[OwaspCategory] = [
    OwaspCategory(
        id="LLM01",
        name="Prompt Injection",
        description="Manipulating LLMs via crafted inputs to cause unintended actions.",
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    OwaspCategory(
        id="LLM02",
        name="Sensitive Information Disclosure",
        description="Unintentional exposure of confidential data through LLM responses.",
        url="https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    ),
    OwaspCategory(
        id="LLM03",
        name="Supply Chain Vulnerabilities",
        description="Risks from third-party components, data, and pre-trained models.",
        url="https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
    ),
    OwaspCategory(
        id="LLM04",
        name="Data and Model Poisoning",
        description="Manipulation of training data or fine-tuning to introduce vulnerabilities.",
        url="https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    ),
    OwaspCategory(
        id="LLM05",
        name="Improper Output Handling",
        description="Insufficient validation of LLM outputs leading to downstream exploits.",
        url="https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    ),
    OwaspCategory(
        id="LLM06",
        name="Excessive Agency",
        description="Granting LLMs excessive autonomy, permissions, or functionality.",
        url="https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    ),
    OwaspCategory(
        id="LLM07",
        name="System Prompt Leakage",
        description="Risk of exposing system prompts containing sensitive information.",
        url="https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    ),
    OwaspCategory(
        id="LLM08",
        name="Vector and Embedding Weaknesses",
        description="Vulnerabilities in RAG vector and embedding mechanisms.",
        url="https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    ),
    OwaspCategory(
        id="LLM09",
        name="Misinformation",
        description="LLMs generating false or misleading information (hallucinations).",
        url="https://genai.owasp.org/llmrisk/llm09-misinformation/",
    ),
    OwaspCategory(
        id="LLM10",
        name="Unbounded Consumption",
        description="Denial of service through resource-exhausting LLM interactions.",
        url="https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    ),
]

# Maps each detector_id to the OWASP LLM Top 10 categories it addresses.
DETECTOR_OWASP_MAP: dict[str, list[str]] = {
    "d001_system_prompt_extraction": ["LLM01", "LLM06"],
    "d002_role_hijack": ["LLM01"],
    "d003_instruction_override": ["LLM01"],
    "d004_recursive_prompt_attack": ["LLM01", "LLM06", "LLM10"],
    "d005_payload_delimiter_smuggling": ["LLM01"],
    "d006_context_window_abuse": ["LLM01"],
    "d007_few_shot_injection": ["LLM01"],
    "d008_encoding_evasion": ["LLM01"],
    "d009_invisible_unicode": ["LLM01"],
    "d010_multilingual_injection": ["LLM01"],
    "d011_markdown_html_abuse": ["LLM01"],
    "d012_data_exfiltration": ["LLM01", "LLM02"],
    "d013_tool_misuse": ["LLM06", "LLM08"],
    "d014_indirect_injection": ["LLM07", "LLM08"],
    "d015_chain_of_thought_exploit": ["LLM01", "LLM03"],
    "d016_rag_poisoning": ["LLM02", "LLM08"],
    "d017_persona_switching": ["LLM01"],
    "d018_output_format_manipulation": ["LLM01"],
    "d019_hypothetical_framing": ["LLM01"],
    "d020_nested_instruction": ["LLM01"],
    "d021_vault_similarity": ["LLM01"],
    "d022_semantic_classifier": ["LLM01"],
}

# All valid OWASP category IDs for validation
_VALID_OWASP_IDS: set[str] = {cat.id for cat in OWASP_LLM_TOP_10}


def generate_compliance_report(
    registered_detector_ids: list[str],
    detector_metadata: list[dict[str, object]],
) -> ComplianceReport:
    """Generate an OWASP compliance report for the given set of detectors.

    Args:
        registered_detector_ids: List of active detector IDs.
        detector_metadata: List of metadata dicts with at least 'detector_id' and 'name'.

    Returns:
        A ComplianceReport with per-category coverage details.
    """
    # Build a quick lookup: detector_id -> name
    id_to_name: dict[str, str] = {
        str(m["detector_id"]): str(m.get("name", m["detector_id"]))
        for m in detector_metadata
    }

    # Build reverse map: category_id -> list of detector_ids that cover it
    category_detectors: dict[str, list[str]] = {cat.id: [] for cat in OWASP_LLM_TOP_10}
    for det_id in registered_detector_ids:
        for cat_id in DETECTOR_OWASP_MAP.get(det_id, []):
            if cat_id in category_detectors:
                category_detectors[cat_id].append(det_id)

    category_details: list[CategoryCoverage] = []
    for cat in OWASP_LLM_TOP_10:
        det_ids = category_detectors[cat.id]
        category_details.append(
            CategoryCoverage(
                category_id=cat.id,
                name=cat.name,
                covered=len(det_ids) > 0,
                detector_ids=det_ids,
                detector_names=[id_to_name.get(d, d) for d in det_ids],
            )
        )

    covered = sum(1 for c in category_details if c.covered)
    total = len(OWASP_LLM_TOP_10)

    return ComplianceReport(
        owasp_version="2025",
        total_detectors=len(registered_detector_ids),
        categories_covered=covered,
        categories_not_covered=total - covered,
        coverage_percentage=round(covered / total * 100, 1) if total else 0.0,
        category_details=category_details,
    )
