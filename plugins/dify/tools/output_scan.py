"""Output scanning tool for Dify."""

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage


class OutputScanTool(Tool):
    """Scans LLM output text for harmful content."""

    def _invoke(
        self, tool_parameters: dict[str, Any]
    ) -> Generator[ToolInvokeMessage]:
        output_text = tool_parameters.get("output_text", "")
        if not output_text:
            yield self.create_text_message("Error: output_text is required.")
            return

        try:
            from prompt_shield.output_scanners.engine import OutputScanEngine

            engine = OutputScanEngine()
            report = engine.scan(output_text)

            flags = []
            for flag in report.flags:
                flags.append({
                    "scanner_id": flag.scanner_id,
                    "categories": flag.categories,
                    "confidence": flag.confidence,
                    "explanation": flag.explanation,
                })

            result = {
                "flagged": report.flagged,
                "total_scanners_run": report.total_scanners_run,
                "total_flags": len(flags),
                "scan_duration_ms": report.scan_duration_ms,
                "flags": flags,
            }

            yield self.create_json_message(result)

        except ImportError:
            yield self.create_text_message(
                "Error: prompt-shield is not installed. "
                "Install it with: pip install prompt-shield-ai"
            )
        except Exception as e:
            yield self.create_text_message(f"Error scanning output: {e}")
