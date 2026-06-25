"""MITRE ATLAS framework mapping for prompt-shield detectors.

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
is the AI/ML extension of the MITRE ATT&CK framework. It catalogs adversary
tactics and techniques targeting machine-learning systems — including LLM
prompt injection, model theft, evasion, and supply-chain attacks.

This module maps each prompt-shield detector to the ATLAS techniques it
helps mitigate, in the same shape as the existing OWASP and EU AI Act
mappings (``DETECTOR_OWASP_MAP`` etc.).

Source:
    https://atlas.mitre.org/matrices/ATLAS

Last refreshed: 2026-06-25 (against the current public ATLAS matrix).

Note: ATLAS describes *attacker* techniques. A defender's mitigation is
inherent. The mappings below indicate detectors that *make a given ATLAS
technique observably harder*, not detectors that prove the attack failed.
"""

from __future__ import annotations

from pydantic import BaseModel


class AtlasTechnique(BaseModel):
    """A single MITRE ATLAS technique entry."""

    id: str
    name: str
    tactic: str  # parent tactic (e.g. "TA0043 Reconnaissance")
    description: str
    url: str


_ATLAS_BASE = "https://atlas.mitre.org/techniques"


ATLAS_TECHNIQUES: list[AtlasTechnique] = [
    AtlasTechnique(
        id="AML.T0051",
        name="LLM Prompt Injection",
        tactic="ML Attack Staging",
        description=(
            "Adversary crafts inputs that override or supplement system prompts, "
            "altering LLM behaviour. Covers direct, indirect, and obfuscated injection."
        ),
        url=f"{_ATLAS_BASE}/AML.T0051/",
    ),
    AtlasTechnique(
        id="AML.T0054",
        name="LLM Jailbreak",
        tactic="Initial Access",
        description=(
            "Bypassing the safety guardrails of an LLM via roleplay framings, "
            "hypothetical scenarios, persona-switching, or compound jailbreak templates."
        ),
        url=f"{_ATLAS_BASE}/AML.T0054/",
    ),
    AtlasTechnique(
        id="AML.T0048",
        name="External Harms — Financial Harm",
        tactic="Impact",
        description=(
            "Denial-of-wallet attacks: forcing the victim to absorb high token / "
            "compute cost through prompts designed to exhaust the LLM's resources."
        ),
        url=f"{_ATLAS_BASE}/AML.T0048/",
    ),
    AtlasTechnique(
        id="AML.T0052",
        name="Publish Poisoned Datasets",
        tactic="Resource Development",
        description=(
            "Attacker plants malicious content in publicly scraped / retrieved sources "
            "(documentation sites, GitHub, web search results) that the LLM later "
            "ingests via RAG, agent tools, or training pipelines."
        ),
        url=f"{_ATLAS_BASE}/AML.T0052/",
    ),
    AtlasTechnique(
        id="AML.T0057",
        name="LLM Data Leakage",
        tactic="Exfiltration",
        description=(
            "Eliciting PII, internal system prompts, training-data fragments, or other "
            "confidential information from the LLM via probing prompts."
        ),
        url=f"{_ATLAS_BASE}/AML.T0057/",
    ),
    AtlasTechnique(
        id="AML.T0053",
        name="LLM Plugin Compromise",
        tactic="Persistence / Lateral Movement",
        description=(
            "Abuse of tool / function-call interfaces to invoke unauthorized actions, "
            "exfiltrate data via tool outputs, or pivot into connected systems."
        ),
        url=f"{_ATLAS_BASE}/AML.T0053/",
    ),
    AtlasTechnique(
        id="AML.T0042",
        name="Verify Attack",
        tactic="ML Attack Staging",
        description=(
            "Iterative probing campaigns to confirm an attack works against the target. "
            "Often appears as repeated near-miss attempts from the same source — the "
            "adversarial-fatigue tracker is designed against this."
        ),
        url=f"{_ATLAS_BASE}/AML.T0042/",
    ),
    AtlasTechnique(
        id="AML.T0044",
        name="Full ML Model Access",
        tactic="ML Model Access",
        description=(
            "Probing the LLM to reconstruct its training data, weights, or system "
            "configuration — typically via watermark-elicitation or stylometric attacks."
        ),
        url=f"{_ATLAS_BASE}/AML.T0044/",
    ),
    AtlasTechnique(
        id="AML.T0049",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        description=(
            "Targeting LLM-enabled web applications, customer-support bots, or "
            "agentic interfaces with crafted user inputs."
        ),
        url=f"{_ATLAS_BASE}/AML.T0049/",
    ),
]


# Map each detector_id (or output-scanner / engine feature) to the ATLAS
# techniques it makes observably harder. Multiple techniques per detector
# are encouraged where relevant — coverage is per-technique, not exclusive.
DETECTOR_ATLAS_MAP: dict[str, list[str]] = {
    # Direct injection family — primary mitigation for T0051 + T0054
    "d001_system_prompt_extraction": ["AML.T0051", "AML.T0057"],
    "d002_role_hijack": ["AML.T0051", "AML.T0054"],
    "d003_instruction_override": ["AML.T0051"],
    "d004_prompt_leaking": ["AML.T0051", "AML.T0057"],
    "d005_context_manipulation": ["AML.T0051"],
    "d006_multi_turn_escalation": ["AML.T0051", "AML.T0054"],
    "d007_task_deflection": ["AML.T0051"],
    # Obfuscation family
    "d008_base64_payload": ["AML.T0051"],
    "d009_rot13_substitution": ["AML.T0051"],
    "d010_unicode_homoglyph": ["AML.T0051"],
    "d011_whitespace_injection": ["AML.T0051"],
    "d012_markdown_html_injection": ["AML.T0051"],
    # Indirect / tool-mediated injection
    "d013_data_exfiltration": ["AML.T0057", "AML.T0053"],
    "d014_tool_function_abuse": ["AML.T0053"],
    "d015_rag_poisoning": ["AML.T0052", "AML.T0051"],
    "d016_url_injection": ["AML.T0053", "AML.T0049"],
    # Jailbreak framings — primary T0054
    "d017_hypothetical_framing": ["AML.T0054"],
    "d018_academic_pretext": ["AML.T0054"],
    "d019_dual_persona": ["AML.T0054"],
    "d020_token_smuggling": ["AML.T0051", "AML.T0054"],
    # ML + self-learning + breadth
    "d021_vault_similarity": ["AML.T0051", "AML.T0042"],
    "d022_semantic_classifier": ["AML.T0051", "AML.T0054"],
    "d023_pii_detection": ["AML.T0057"],
    "d024_multilingual_injection": ["AML.T0051"],
    "d025_multi_encoding": ["AML.T0051"],
    "d026_denial_of_wallet": ["AML.T0048"],
    # v0.4.0 cross-domain
    "d027_stylometric_discontinuity": ["AML.T0052", "AML.T0044"],
    "d028_sequence_alignment": ["AML.T0051", "AML.T0054"],
    "d029_many_shot_structural": ["AML.T0054"],
    # v0.5.0 operator-policy + multi-turn
    "d030_custom_rules": ["AML.T0051"],
    "d031_language_enforcement": ["AML.T0051", "AML.T0049"],
    "d032_topic_enforcement": ["AML.T0049"],
    "d033_topic_drift": ["AML.T0054", "AML.T0042"],
    # Engine features
    "adversarial_fatigue_tracker": ["AML.T0042"],
    "canary_tokens": ["AML.T0057", "AML.T0044"],
    "federated_threat_intel": ["AML.T0042", "AML.T0051"],
    # Output scanners
    "output_toxicity_scanner": ["AML.T0054"],
    "output_code_injection_scanner": ["AML.T0053", "AML.T0049"],
    "output_prompt_leakage_scanner": ["AML.T0057"],
    "output_pii_scanner": ["AML.T0057"],
}


_VALID_ATLAS_IDS: set[str] = {tech.id for tech in ATLAS_TECHNIQUES}


class AtlasCoverage(BaseModel):
    """Coverage report row for one ATLAS technique."""

    technique_id: str
    technique_name: str
    tactic: str
    is_covered: bool
    detector_ids: list[str]


class AtlasReport(BaseModel):
    """Report of prompt-shield coverage against MITRE ATLAS."""

    framework: str = "MITRE ATLAS"
    framework_url: str = "https://atlas.mitre.org/"
    coverage: list[AtlasCoverage]
    coverage_percentage: float
    total_techniques: int
    techniques_covered: int


def generate_atlas_report(registered_detector_ids: list[str]) -> AtlasReport:
    """Generate a coverage report against MITRE ATLAS.

    Args:
        registered_detector_ids: List of currently-registered detector IDs
            (plus any non-detector feature keys present in DETECTOR_ATLAS_MAP,
            such as ``canary_tokens`` or ``adversarial_fatigue_tracker``).
    """
    by_technique: dict[str, list[str]] = {t.id: [] for t in ATLAS_TECHNIQUES}
    for det_id in registered_detector_ids:
        for tech_id in DETECTOR_ATLAS_MAP.get(det_id, []):
            if tech_id in by_technique:
                by_technique[tech_id].append(det_id)

    rows: list[AtlasCoverage] = []
    covered = 0
    for tech in ATLAS_TECHNIQUES:
        dets = by_technique[tech.id]
        is_covered = len(dets) > 0
        if is_covered:
            covered += 1
        rows.append(
            AtlasCoverage(
                technique_id=tech.id,
                technique_name=tech.name,
                tactic=tech.tactic,
                is_covered=is_covered,
                detector_ids=dets,
            )
        )

    return AtlasReport(
        coverage=rows,
        coverage_percentage=(covered / len(ATLAS_TECHNIQUES) * 100.0) if ATLAS_TECHNIQUES else 0.0,
        total_techniques=len(ATLAS_TECHNIQUES),
        techniques_covered=covered,
    )
