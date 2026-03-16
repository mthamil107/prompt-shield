"""Data models for red team reports."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttackResult(BaseModel):
    """Result of a single attack attempt against prompt-shield."""

    category: str
    prompt: str
    bypassed: bool
    risk_score: float = Field(ge=0.0, le=1.0)
    action: str
    detections: list[str] = Field(default_factory=list)


class RedTeamReport(BaseModel):
    """Aggregated report from a red team run."""

    total_attacks: int = 0
    total_bypasses: int = 0
    bypass_rate: float = 0.0
    duration_seconds: float = 0.0
    categories_tested: list[str] = Field(default_factory=list)
    results: list[AttackResult] = Field(default_factory=list)
    bypasses_by_category: dict[str, int] = Field(default_factory=dict)
    tokens_used: int = 0

    def summary(self) -> str:
        """Return a human-readable summary of the red team run."""
        lines: list[str] = []
        lines.append("")
        lines.append("=" * 60)
        lines.append("  RED TEAM REPORT")
        lines.append("=" * 60)
        lines.append(f"  Duration:          {self.duration_seconds:.1f}s")
        lines.append(f"  Total attacks:     {self.total_attacks}")
        lines.append(f"  Total bypasses:    {self.total_bypasses}")
        lines.append(f"  Bypass rate:       {self.bypass_rate:.1%}")
        lines.append(f"  Tokens used:       {self.tokens_used}")
        lines.append(f"  Categories tested: {len(self.categories_tested)}")
        lines.append("")

        if self.bypasses_by_category:
            lines.append("  Bypasses by category:")
            for cat, count in sorted(
                self.bypasses_by_category.items(), key=lambda x: x[1], reverse=True
            ):
                lines.append(f"    {cat:40s} {count}")
            lines.append("")

        if self.total_bypasses > 0:
            lines.append("  Top bypass prompts:")
            bypass_results = [r for r in self.results if r.bypassed]
            for result in bypass_results[:10]:
                prompt_preview = result.prompt[:80].replace("\n", " ")
                if len(result.prompt) > 80:
                    prompt_preview += "..."
                lines.append(
                    f"    [{result.category}] (score={result.risk_score:.2f}, "
                    f"action={result.action})"
                )
                lines.append(f"      {prompt_preview}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)
