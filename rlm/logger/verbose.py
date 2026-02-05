"""
Verbose printing for RLM using rich.

Provides console output for debugging and understanding RLM execution.
This version uses ASCII-safe characters to avoid Windows console encoding errors.
"""

from typing import Any

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

from rlm.core.types import CodeBlock, RLMIteration, RLMMetadata

# ============================================================================
# Color Theme
# ============================================================================
COLORS = {
    "primary": "#7AA2F7",
    "secondary": "#BB9AF7",
    "success": "#9ECE6A",
    "warning": "#E0AF68",
    "error": "#F7768E",
    "text": "#A9B1D6",
    "muted": "#565F89",
    "accent": "#7DCFFF",
    "border": "#3B4261",
}

STYLE_PRIMARY = Style(color=COLORS["primary"], bold=True)
STYLE_SECONDARY = Style(color=COLORS["secondary"])
STYLE_SUCCESS = Style(color=COLORS["success"])
STYLE_WARNING = Style(color=COLORS["warning"])
STYLE_ERROR = Style(color=COLORS["error"])
STYLE_TEXT = Style(color=COLORS["text"])
STYLE_MUTED = Style(color=COLORS["muted"])
STYLE_ACCENT = Style(color=COLORS["accent"], bold=True)


def _to_str(value: Any) -> str:
    """Convert any value to string safely."""
    if isinstance(value, str):
        return value
    return str(value)


class VerbosePrinter:
    """
    Rich console printer for RLM verbose output.

    Displays structured output showing:
    - Initial configuration panel
    - Each iteration with response summaries
    - Code execution with results
    - Sub-calls to other models
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.console = (
            Console(force_terminal=True, color_system="standard", safe_box=True)
            if enabled
            else None
        )
        self._iteration_count = 0

    def print_header(
        self,
        backend: str,
        model: str,
        environment: str,
        max_iterations: int,
        max_depth: int,
        other_backends: list[str] | None = None,
    ) -> None:
        if not self.enabled:
            return

        title = Text()
        title.append("* ", style=STYLE_ACCENT)
        title.append("RLM", style=Style(color=COLORS["primary"], bold=True))
        title.append(" - Recursive Language Model", style=STYLE_MUTED)

        config_table = Table(
            show_header=False,
            show_edge=False,
            box=box.ASCII,
            padding=(0, 2),
            expand=True,
        )
        config_table.add_column("key", style=STYLE_MUTED, width=16)
        config_table.add_column("value", style=STYLE_TEXT)
        config_table.add_column("key2", style=STYLE_MUTED, width=16)
        config_table.add_column("value2", style=STYLE_TEXT)

        config_table.add_row(
            "Backend",
            Text(backend, style=STYLE_SECONDARY),
            "Environment",
            Text(environment, style=STYLE_SECONDARY),
        )
        config_table.add_row(
            "Model",
            Text(model, style=STYLE_ACCENT),
            "Max Iterations",
            Text(str(max_iterations), style=STYLE_WARNING),
        )

        if other_backends:
            backends_text = Text(", ".join(other_backends), style=STYLE_SECONDARY)
            config_table.add_row(
                "Sub-models",
                backends_text,
                "Max Depth",
                Text(str(max_depth), style=STYLE_WARNING),
            )
        else:
            config_table.add_row(
                "Max Depth",
                Text(str(max_depth), style=STYLE_WARNING),
                "",
                "",
            )

        panel = Panel(
            config_table,
            title=title,
            title_align="left",
            border_style=COLORS["border"],
            padding=(1, 2),
            box=box.ASCII,
        )

        self.console.print()
        self.console.print(panel)
        self.console.print()

    def print_metadata(self, metadata: RLMMetadata) -> None:
        if not self.enabled:
            return

        model = metadata.backend_kwargs.get("model_name", "unknown")
        other = list(metadata.other_backends) if metadata.other_backends else None

        self.print_header(
            backend=metadata.backend,
            model=model,
            environment=metadata.environment_type,
            max_iterations=metadata.max_iterations,
            max_depth=metadata.max_depth,
            other_backends=other,
        )

    def print_iteration_start(self, iteration: int) -> None:
        if not self.enabled:
            return

        self._iteration_count = iteration
        rule = Rule(Text(f" Iteration {iteration} ", style=STYLE_PRIMARY), style=COLORS["border"])
        self.console.print(rule)

    def print_completion(self, response: Any, iteration_time: float | None = None) -> None:
        if not self.enabled:
            return

        header = Text()
        header.append("> ", style=STYLE_ACCENT)
        header.append("LLM Response", style=STYLE_PRIMARY)
        if iteration_time:
            header.append(f"  ({iteration_time:.2f}s)", style=STYLE_MUTED)

        response_str = _to_str(response)
        response_text = Text(response_str, style=STYLE_TEXT)
        word_count = len(response_str.split())
        footer = Text(f"~{word_count} words", style=STYLE_MUTED)

        panel = Panel(
            Group(response_text, Text(), footer),
            title=header,
            title_align="left",
            border_style=COLORS["muted"],
            padding=(0, 1),
            box=box.ASCII,
        )
        self.console.print(panel)

    def print_code_execution(self, code_block: CodeBlock) -> None:
        if not self.enabled:
            return

        result = code_block.result
        header = Text()
        header.append(">> ", style=STYLE_SUCCESS)
        header.append("Code Execution", style=Style(color=COLORS["success"], bold=True))
        if result.execution_time:
            header.append(f"  ({result.execution_time:.3f}s)", style=STYLE_MUTED)

        content_parts = []

        code_text = Text()
        code_text.append("Code:\n", style=STYLE_MUTED)
        code_text.append(_to_str(code_block.code), style=STYLE_TEXT)
        content_parts.append(code_text)

        stdout_str = _to_str(result.stdout) if result.stdout else ""
        if stdout_str.strip():
            stdout_text = Text()
            stdout_text.append("\nOutput:\n", style=STYLE_MUTED)
            stdout_text.append(stdout_str, style=STYLE_SUCCESS)
            content_parts.append(stdout_text)

        stderr_str = _to_str(result.stderr) if result.stderr else ""
        if stderr_str.strip():
            stderr_text = Text()
            stderr_text.append("\nError:\n", style=STYLE_MUTED)
            stderr_text.append(stderr_str, style=STYLE_ERROR)
            content_parts.append(stderr_text)

        if result.rlm_calls:
            calls_text = Text()
            calls_text.append(f"\n-> {len(result.rlm_calls)} sub-call(s)", style=STYLE_SECONDARY)
            content_parts.append(calls_text)

        panel = Panel(
            Group(*content_parts),
            title=header,
            title_align="left",
            border_style=COLORS["success"],
            padding=(0, 1),
            box=box.ASCII,
        )
        self.console.print(panel)

    def print_subcall(
        self,
        model: str,
        prompt_preview: str,
        response_preview: str,
        execution_time: float | None = None,
    ) -> None:
        if not self.enabled:
            return

        header = Text()
        header.append("  -> ", style=STYLE_SECONDARY)
        header.append("Sub-call: ", style=STYLE_SECONDARY)
        header.append(_to_str(model), style=STYLE_ACCENT)
        if execution_time:
            header.append(f"  ({execution_time:.2f}s)", style=STYLE_MUTED)

        content = Text()
        content.append("Prompt: ", style=STYLE_MUTED)
        content.append(_to_str(prompt_preview), style=STYLE_TEXT)
        content.append("\nResponse: ", style=STYLE_MUTED)
        content.append(_to_str(response_preview), style=STYLE_TEXT)

        panel = Panel(
            content,
            title=header,
            title_align="left",
            border_style=COLORS["secondary"],
            padding=(0, 1),
            box=box.ASCII,
        )
        self.console.print(panel)

    def print_iteration(self, iteration: RLMIteration, iteration_num: int) -> None:
        if not self.enabled:
            return

        self.print_iteration_start(iteration_num)
        self.print_completion(iteration.response, iteration.iteration_time)

        for code_block in iteration.code_blocks:
            self.print_code_execution(code_block)
            for call in code_block.result.rlm_calls:
                self.print_subcall(
                    model=call.root_model,
                    prompt_preview=_to_str(call.prompt) if call.prompt else "",
                    response_preview=_to_str(call.response) if call.response else "",
                    execution_time=call.execution_time,
                )

    def print_final_answer(self, answer: Any) -> None:
        if not self.enabled:
            return

        title = Text()
        title.append("* ", style=STYLE_WARNING)
        title.append("Final Answer", style=Style(color=COLORS["warning"], bold=True))

        answer_text = Text(_to_str(answer), style=STYLE_TEXT)

        panel = Panel(
            answer_text,
            title=title,
            title_align="left",
            border_style=COLORS["warning"],
            padding=(1, 2),
            box=box.ASCII,
        )

        self.console.print()
        self.console.print(panel)
        self.console.print()

    def print_summary(
        self,
        total_iterations: int,
        total_time: float,
        usage_summary: dict[str, Any] | None = None,
    ) -> None:
        if not self.enabled:
            return

        summary_table = Table(
            show_header=False,
            show_edge=False,
            box=box.ASCII,
            padding=(0, 2),
        )
        summary_table.add_column("metric", style=STYLE_MUTED)
        summary_table.add_column("value", style=STYLE_ACCENT)

        summary_table.add_row("Iterations", str(total_iterations))
        summary_table.add_row("Total Time", f"{total_time:.2f}s")

        if usage_summary:
            total_input = sum(
                m.get("total_input_tokens", 0)
                for m in usage_summary.get("model_usage_summaries", {}).values()
            )
            total_output = sum(
                m.get("total_output_tokens", 0)
                for m in usage_summary.get("model_usage_summaries", {}).values()
            )
            if total_input or total_output:
                summary_table.add_row("Input Tokens", f"{total_input:,}")
                summary_table.add_row("Output Tokens", f"{total_output:,}")

        self.console.print()
        self.console.print(Rule(style=COLORS["border"], characters="="))
        self.console.print(summary_table, justify="center")
        self.console.print(Rule(style=COLORS["border"], characters="="))
        self.console.print()
