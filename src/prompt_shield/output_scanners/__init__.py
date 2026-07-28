"""Output scanners — analyse LLM-generated text for harmful content.

Nine scanners ship in the box: :class:`ToxicityScanner`,
:class:`CodeInjectionScanner`, :class:`PromptLeakageScanner`,
:class:`OutputPIIScanner`, :class:`SchemaValidationScanner`,
:class:`BiasFairnessOutputScanner`, :class:`SentimentOutputScanner`,
:class:`HallucinationOutputScanner`, and :class:`RelevanceScanner`.

Use :class:`OutputScanEngine` to run all of them (or a named subset) in
one call and get back an aggregated :class:`OutputScanReport`.
"""

from prompt_shield.output_scanners.base import BaseOutputScanner
from prompt_shield.output_scanners.bias_fairness import BiasFairnessOutputScanner
from prompt_shield.output_scanners.code_injection import CodeInjectionScanner
from prompt_shield.output_scanners.engine import OutputScanEngine, available_scanners
from prompt_shield.output_scanners.hallucination import HallucinationOutputScanner
from prompt_shield.output_scanners.models import OutputScanReport, OutputScanResult
from prompt_shield.output_scanners.output_pii import OutputPIIScanner
from prompt_shield.output_scanners.prompt_leakage import PromptLeakageScanner
from prompt_shield.output_scanners.relevance import RelevanceScanner
from prompt_shield.output_scanners.schema_validation import SchemaValidationScanner
from prompt_shield.output_scanners.sentiment import SentimentOutputScanner
from prompt_shield.output_scanners.toxicity import ToxicityScanner

__all__ = [
    "BaseOutputScanner",
    "BiasFairnessOutputScanner",
    "CodeInjectionScanner",
    "HallucinationOutputScanner",
    "OutputPIIScanner",
    "OutputScanEngine",
    "OutputScanReport",
    "OutputScanResult",
    "PromptLeakageScanner",
    "RelevanceScanner",
    "SchemaValidationScanner",
    "SentimentOutputScanner",
    "ToxicityScanner",
    "available_scanners",
]
