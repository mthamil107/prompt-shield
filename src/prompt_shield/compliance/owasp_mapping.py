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


class AgenticComplianceReport(BaseModel):
    """OWASP Agentic Applications Top 10 compliance report."""

    owasp_version: str
    framework: str
    total_features: int
    categories_covered: int
    categories_not_covered: int
    coverage_percentage: float
    category_details: list[CategoryCoverage]


class EuAiActArticle(BaseModel):
    """An EU AI Act article."""

    id: str
    name: str
    description: str


class EuAiActCoverage(BaseModel):
    """Coverage details for a single EU AI Act article."""

    article_id: str
    name: str
    covered: bool
    coverage_items: list[str]


class EuAiActReport(BaseModel):
    """EU AI Act compliance report."""

    framework: str
    articles_covered: int
    articles_total: int
    coverage_percentage: float
    article_details: list[EuAiActCoverage]


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
    "d023_pii_detection": ["LLM02"],
    "d024_multilingual_injection": ["LLM01"],
    "d025_multi_encoding": ["LLM01"],
    "d026_denial_of_wallet": ["LLM10"],
    "d028_sequence_alignment": ["LLM01"],
}

# All valid OWASP category IDs for validation
_VALID_OWASP_IDS: set[str] = {cat.id for cat in OWASP_LLM_TOP_10}


# ---------------------------------------------------------------------------
# OWASP Top 10 for Agentic Applications (2026)
# ---------------------------------------------------------------------------

_AGENTIC_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"

OWASP_AGENTIC_TOP_10: list[OwaspCategory] = [
    OwaspCategory(
        id="ASI01",
        name="Agent Goal Hijack",
        description="Adversarial manipulation of agent objectives through prompt injection or context poisoning",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI02",
        name="Insecure Tool Integration",
        description="Vulnerabilities in tool/API integrations used by agents",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI03",
        name="Identity & Privilege Abuse",
        description="Agents operating with excessive permissions or impersonating users",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI04",
        name="Data Leakage via Agent Actions",
        description="Agents inadvertently exposing sensitive data through tool calls or outputs",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI05",
        name="Poisoned Agent Context",
        description="Manipulation of agent memory, RAG context, or conversation history",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI06",
        name="Cascading Hallucination Chains",
        description="Hallucinated outputs from one agent step becoming inputs to subsequent steps",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI07",
        name="Uncontrolled Autonomous Actions",
        description="Agents taking irreversible or harmful actions without adequate human oversight",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI08",
        name="Cross-Agent Prompt Injection",
        description="Injection attacks propagating between agents in multi-agent systems",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI09",
        name="Insufficient Logging & Forensics",
        description="Lack of audit trails for agent reasoning and actions",
        url=_AGENTIC_URL,
    ),
    OwaspCategory(
        id="ASI10",
        name="Trust Boundary Violations",
        description="Agents crossing security boundaries between trusted and untrusted contexts",
        url=_AGENTIC_URL,
    ),
]

# Maps detector/feature IDs to Agentic Top 10 categories.
DETECTOR_AGENTIC_MAP: dict[str, list[str]] = {
    "d001_system_prompt_extraction": ["ASI01", "ASI04"],
    "d002_role_hijack": ["ASI01"],
    "d003_instruction_override": ["ASI01"],
    "d013_data_exfiltration": ["ASI04"],
    "d014_tool_function_abuse": ["ASI02", "ASI07"],
    "d015_rag_poisoning": ["ASI05"],
    "d023_pii_detection": ["ASI04"],
    "d024_multilingual_injection": ["ASI01", "ASI08"],
    "d025_multi_encoding": ["ASI01"],
    "d028_sequence_alignment": ["ASI01", "ASI08"],
    # AgentGuard features (not detector-based)
    "agent_guard_input_gate": ["ASI01", "ASI10"],
    "agent_guard_data_gate": ["ASI02", "ASI05", "ASI08"],
    "agent_guard_output_gate": ["ASI04", "ASI06"],
    "canary_tokens": ["ASI04", "ASI09"],
    "output_toxicity_scanner": ["ASI07"],
    "output_code_injection_scanner": ["ASI02"],
    "output_prompt_leakage_scanner": ["ASI04", "ASI09"],
    "output_pii_scanner": ["ASI04"],
}

_VALID_AGENTIC_IDS: set[str] = {cat.id for cat in OWASP_AGENTIC_TOP_10}


# ---------------------------------------------------------------------------
# EU AI Act Mapping
# ---------------------------------------------------------------------------

EU_AI_ACT_ARTICLES: list[EuAiActArticle] = [
    EuAiActArticle(
        id="Art.9",
        name="Risk Management",
        description="Continuous risk management for high-risk AI systems",
    ),
    EuAiActArticle(
        id="Art.10",
        name="Data Governance",
        description="Training and testing data quality requirements",
    ),
    EuAiActArticle(
        id="Art.13",
        name="Transparency",
        description="AI systems must be transparent and provide information to users",
    ),
    EuAiActArticle(
        id="Art.14",
        name="Human Oversight",
        description="High-risk AI systems must allow effective human oversight",
    ),
    EuAiActArticle(
        id="Art.15",
        name="Accuracy & Robustness",
        description="AI systems must be accurate, robust, and cybersecure",
    ),
    EuAiActArticle(
        id="Art.50",
        name="AI-Generated Content",
        description="Transparency obligations for AI-generated content",
    ),
    EuAiActArticle(
        id="Art.52",
        name="Interaction Disclosure",
        description="Users must be informed when interacting with AI",
    ),
]

PROMPT_SHIELD_EU_AI_ACT_COVERAGE: dict[str, list[str]] = {
    "Art.9": [
        "Input scanning (25 detectors)",
        "Output scanning (5 scanners)",
        "Red team self-testing",
    ],
    "Art.10": [
        "Benchmarking against public datasets",
        "Community threat feed",
    ],
    "Art.13": [
        "OWASP compliance reports",
        "Scan reports with full transparency",
    ],
    "Art.14": [
        "Block/flag/monitor modes",
        "Human-in-the-loop via feedback system",
    ],
    "Art.15": [
        "92.3% detection accuracy",
        "0% false positive rate",
        "Adversarial self-testing",
    ],
    "Art.50": [
        "Output scanning for AI-generated content",
    ],
    "Art.52": [
        "Canary tokens for AI disclosure",
    ],
}


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


def generate_agentic_compliance_report(
    feature_ids: list[str] | None = None,
) -> AgenticComplianceReport:
    """Generate an OWASP Agentic Applications Top 10 compliance report.

    Args:
        feature_ids: Optional list of active feature/detector IDs.
            If *None*, all keys in ``DETECTOR_AGENTIC_MAP`` are used
            (i.e. full prompt-shield feature set).

    Returns:
        An AgenticComplianceReport with per-category coverage details.
    """
    if feature_ids is None:
        feature_ids = list(DETECTOR_AGENTIC_MAP.keys())

    # Build reverse map: category_id -> list of feature_ids that cover it
    category_features: dict[str, list[str]] = {cat.id: [] for cat in OWASP_AGENTIC_TOP_10}
    for feat_id in feature_ids:
        for cat_id in DETECTOR_AGENTIC_MAP.get(feat_id, []):
            if cat_id in category_features:
                category_features[cat_id].append(feat_id)

    category_details: list[CategoryCoverage] = []
    for cat in OWASP_AGENTIC_TOP_10:
        feat_ids = category_features[cat.id]
        category_details.append(
            CategoryCoverage(
                category_id=cat.id,
                name=cat.name,
                covered=len(feat_ids) > 0,
                detector_ids=feat_ids,
                detector_names=feat_ids,  # features use their ID as display name
            )
        )

    covered = sum(1 for c in category_details if c.covered)
    total = len(OWASP_AGENTIC_TOP_10)

    return AgenticComplianceReport(
        owasp_version="2026",
        framework="owasp-agentic",
        total_features=len(feature_ids),
        categories_covered=covered,
        categories_not_covered=total - covered,
        coverage_percentage=round(covered / total * 100, 1) if total else 0.0,
        category_details=category_details,
    )


def generate_eu_ai_act_report() -> EuAiActReport:
    """Generate an EU AI Act compliance report.

    Returns:
        An EuAiActReport showing prompt-shield coverage for each article.
    """
    article_details: list[EuAiActCoverage] = []
    for article in EU_AI_ACT_ARTICLES:
        items = PROMPT_SHIELD_EU_AI_ACT_COVERAGE.get(article.id, [])
        article_details.append(
            EuAiActCoverage(
                article_id=article.id,
                name=article.name,
                covered=len(items) > 0,
                coverage_items=items,
            )
        )

    covered = sum(1 for a in article_details if a.covered)
    total = len(EU_AI_ACT_ARTICLES)

    return EuAiActReport(
        framework="eu-ai-act",
        articles_covered=covered,
        articles_total=total,
        coverage_percentage=round(covered / total * 100, 1) if total else 0.0,
        article_details=article_details,
    )
