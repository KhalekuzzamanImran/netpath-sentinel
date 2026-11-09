import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from netpath_sentinel.domain.enums import StepStatus
from netpath_sentinel.domain.models import DiagnosticStep


@dataclass
class WorkflowContext:
    session_id: str
    values: dict[str, object] = field(default_factory=dict)
    steps: list[DiagnosticStep] = field(default_factory=list)


StepFunction = Callable[[WorkflowContext], Awaitable[StepStatus]]


class DiagnosticWorkflow:
    def __init__(self, steps: list[tuple[str, str, StepFunction]]) -> None:
        self.steps = steps

    async def run(self, context: WorkflowContext) -> WorkflowContext:
        for step_id, name, function in self.steps:
            step = DiagnosticStep(
                session_id=context.session_id,
                step_id=step_id,
                name=name,
                status=StepStatus.RUNNING,
                started_at=datetime.now(UTC),
            )
            context.steps.append(step)
            try:
                step.status = await function(context)
            except asyncio.CancelledError:
                step.status = StepStatus.SKIPPED
                step.error = "workflow cancelled"
                raise
            except PermissionError as exc:
                step.status = StepStatus.PERMISSION_DENIED
                step.error = str(exc)
            except NotImplementedError as exc:
                step.status = StepStatus.UNSUPPORTED
                step.error = str(exc)
            except Exception as exc:  # workflow boundary records errors, UI remains alive
                step.status = StepStatus.FAILED
                step.error = str(exc)
            finally:
                step.ended_at = datetime.now(UTC)
        return context
