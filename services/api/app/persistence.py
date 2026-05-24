from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .contracts import (
    AgentImportRecord,
    AgentSpec,
    AuditLogRecord,
    DiffResult,
    ProviderCallRecord,
    RepositoryRecord,
    Report,
    RequestPrResponse,
    Run,
    RunEvent,
    RunEventRecord,
    RunStatus,
    utc_now,
)
from .database import session_scope
from .db_models import (
    AgentImportRow,
    AgentRow,
    ApprovalRow,
    AuditLogRow,
    DiffRow,
    ProviderCallRow,
    RepositoryRow,
    ReportRow,
    RunEventRow,
    RunPrRow,
    RunRow,
)


class PersistentStore:
    def save_agent(self, agent: AgentSpec) -> AgentSpec:
        with session_scope() as session:
            session.merge(agent_to_row(agent))
        return agent

    def get_agent(self, agent_id: str) -> AgentSpec | None:
        with session_scope() as session:
            row = session.get(AgentRow, agent_id)
            return row_to_agent(row) if row else None

    def list_agents(self) -> list[AgentSpec]:
        with session_scope() as session:
            rows = session.scalars(select(AgentRow).order_by(AgentRow.created_at.desc())).all()
            return [row_to_agent(row) for row in rows]

    def save_repository(
        self,
        *,
        installation_id: int | None,
        owner: str,
        repo: str,
        default_branch: str | None,
        selected_ref: str | None,
        html_url: str | None,
    ) -> RepositoryRecord:
        record = RepositoryRecord(
            id=f"repo_{uuid.uuid4().hex[:10]}",
            installation_id=installation_id,
            owner=owner,
            repo=repo,
            full_name=f"{owner}/{repo}",
            default_branch=default_branch,
            selected_ref=selected_ref,
            html_url=html_url,
        )
        with session_scope() as session:
            session.add(repository_to_row(record))
        return record

    def list_repositories(self) -> list[RepositoryRecord]:
        with session_scope() as session:
            rows = session.scalars(select(RepositoryRow).order_by(RepositoryRow.created_at.desc())).all()
            return [row_to_repository(row) for row in rows]

    def save_agent_import(
        self,
        *,
        source: dict[str, Any],
        repository: RepositoryRecord,
        agent: AgentSpec,
        warnings: list[str],
        recommended_scenario_ids: list[str],
        commit_sha: str | None,
    ) -> AgentImportRecord:
        record = AgentImportRecord(
            id=f"import_{uuid.uuid4().hex[:10]}",
            source=source,
            repository=repository,
            agent=agent,
            warnings=warnings,
            recommended_scenario_ids=recommended_scenario_ids,
            commit_sha=commit_sha,
        )
        with session_scope() as session:
            session.add(
                AgentImportRow(
                    id=record.id,
                    source=source,
                    repository_id=repository.id,
                    agent_id=agent.id or "",
                    warnings=warnings,
                    recommended_scenario_ids=recommended_scenario_ids,
                    commit_sha=commit_sha,
                    created_at=record.created_at,
                )
            )
        return record

    def get_agent_import_for_agent(self, agent_id: str) -> AgentImportRecord | None:
        with session_scope() as session:
            row = session.scalars(
                select(AgentImportRow)
                .where(AgentImportRow.agent_id == agent_id)
                .order_by(AgentImportRow.created_at.desc())
            ).first()
            if row is None:
                return None
            repository = session.get(RepositoryRow, row.repository_id)
            agent = session.get(AgentRow, row.agent_id)
            if repository is None or agent is None:
                return None
            return row_to_agent_import(row, row_to_repository(repository), row_to_agent(agent))

    def save_run(self, run: Run) -> Run:
        with session_scope() as session:
            session.merge(run_to_row(run))
        return run

    def get_run(self, run_id: str) -> Run | None:
        with session_scope() as session:
            row = session.get(RunRow, run_id)
            return row_to_run(row) if row else None

    def update_run_status(
        self,
        run_id: str,
        *,
        status: RunStatus,
        completed_at: datetime | None = None,
        score: int | None = None,
    ) -> Run | None:
        with session_scope() as session:
            row = session.get(RunRow, run_id)
            if row is None:
                return None
            row.status = str(status)
            row.completed_at = completed_at
            row.score = score
            session.add(row)
            session.flush()
            return row_to_run(row)

    def add_event(self, run_id: str, event: RunEvent) -> RunEventRecord:
        with session_scope() as session:
            row = RunEventRow(
                run_id=run_id,
                sequence=event.sequence,
                timestamp=event.timestamp,
                actor=enum_value(event.actor),
                message=event.message,
                scenario_id=event.scenario_id,
                tool_call=event.tool_call,
                policy_decision=enum_value(event.policy_decision) if event.policy_decision else None,
                risk_signal=event.risk_signal,
            )
            session.add(row)
            session.flush()
            return row_to_event_record(row)

    def list_events(self, run_id: str, *, after_sequence: int = 0) -> list[RunEventRecord]:
        with session_scope() as session:
            rows = session.scalars(
                select(RunEventRow)
                .where(RunEventRow.run_id == run_id, RunEventRow.sequence > after_sequence)
                .order_by(RunEventRow.sequence.asc())
            ).all()
            return [row_to_event_record(row) for row in rows]

    def next_event_sequence(self, run_id: str) -> int:
        with session_scope() as session:
            row = session.scalars(
                select(RunEventRow).where(RunEventRow.run_id == run_id).order_by(RunEventRow.sequence.desc())
            ).first()
            return (row.sequence if row else 0) + 1

    def save_report(self, report: Report) -> Report:
        payload = report.model_dump(mode="json", by_alias=False)
        with session_scope() as session:
            session.merge(ReportRow(run_id=report.run_id, payload=payload, created_at=report_timestamp(report)))
        return report

    def get_report(self, run_id: str) -> Report | None:
        with session_scope() as session:
            row = session.get(ReportRow, run_id)
            return Report.model_validate(row.payload) if row else None

    def save_approval(self, run_id: str, diff_ids: Iterable[str], *, apply_to_agent: bool) -> None:
        with session_scope() as session:
            for diff_id in diff_ids:
                session.add(ApprovalRow(run_id=run_id, diff_id=diff_id, apply_to_agent=apply_to_agent))

    def approved_diff_ids(self, run_id: str) -> set[str]:
        with session_scope() as session:
            rows = session.scalars(select(ApprovalRow).where(ApprovalRow.run_id == run_id)).all()
            return {row.diff_id for row in rows}

    def save_run_pr(self, response: RequestPrResponse) -> RequestPrResponse:
        if not response.interaction_id:
            return response
        with session_scope() as session:
            session.merge(
                RunPrRow(
                    run_id=response.interaction_id,
                    payload=response.model_dump(mode="json", by_alias=False),
                )
            )
        return response

    def get_run_pr(self, run_id: str) -> RequestPrResponse | None:
        with session_scope() as session:
            row = session.get(RunPrRow, run_id)
            return RequestPrResponse.model_validate(row.payload) if row else None

    def save_diff(self, diff: DiffResult) -> DiffResult:
        with session_scope() as session:
            session.merge(DiffRow(id=diff.id, payload=diff.model_dump(mode="json", by_alias=False)))
        return diff

    def get_diff(self, diff_id: str) -> DiffResult | None:
        with session_scope() as session:
            row = session.get(DiffRow, diff_id)
            return DiffResult.model_validate(row.payload) if row else None

    def save_provider_call(self, record: ProviderCallRecord) -> ProviderCallRecord:
        with session_scope() as session:
            session.add(
                ProviderCallRow(
                    id=record.id,
                    run_id=record.run_id,
                    provider=enum_value(record.provider),
                    model_id=record.model_id,
                    status=record.status,
                    request_summary=record.request_summary,
                    response_summary=record.response_summary,
                    error=record.error,
                    redacted=record.redacted,
                    created_at=record.created_at,
                )
            )
        return record

    def list_provider_calls(self, run_id: str | None = None) -> list[ProviderCallRecord]:
        with session_scope() as session:
            statement = select(ProviderCallRow).order_by(ProviderCallRow.created_at.asc())
            if run_id is not None:
                statement = statement.where(ProviderCallRow.run_id == run_id)
            rows = session.scalars(statement).all()
            return [row_to_provider_call(row) for row in rows]

    def audit(
        self,
        action: str,
        *,
        actor: str = "system",
        target_id: str | None = None,
        detail: dict[str, str | int | bool | None] | None = None,
    ) -> AuditLogRecord:
        record = AuditLogRecord(
            id=f"audit_{uuid.uuid4().hex[:12]}",
            action=action,
            actor=actor,
            target_id=target_id,
            detail=detail or {},
        )
        with session_scope() as session:
            session.add(
                AuditLogRow(
                    id=record.id,
                    action=record.action,
                    actor=record.actor,
                    target_id=record.target_id,
                    detail=record.detail,
                    created_at=record.created_at,
                )
            )
        return record

    def clear_all(self) -> None:
        with session_scope() as session:
            for table in [
                AuditLogRow,
                ProviderCallRow,
                DiffRow,
                RunPrRow,
                ApprovalRow,
                ReportRow,
                RunEventRow,
                RunRow,
                AgentImportRow,
                RepositoryRow,
                AgentRow,
            ]:
                session.execute(delete(table))


def agent_to_row(agent: AgentSpec) -> AgentRow:
    return AgentRow(
        id=agent.id or "",
        name=agent.name,
        system_prompt=agent.system_prompt,
        prompt_path=agent.prompt_path,
        tools=agent.tools,
        sandbox_policy=agent.sandbox_policy.model_dump(mode="json", by_alias=False),
        managed=agent.managed,
        runtime=agent.runtime.model_dump(mode="json", by_alias=False) if agent.runtime else None,
    )


def row_to_agent(row: AgentRow) -> AgentSpec:
    return AgentSpec(
        id=row.id,
        name=row.name,
        system_prompt=row.system_prompt,
        prompt_path=row.prompt_path,
        tools=list(row.tools or []),
        sandbox_policy=row.sandbox_policy,
        managed=row.managed,
        runtime=row.runtime,
    )


def repository_to_row(record: RepositoryRecord) -> RepositoryRow:
    return RepositoryRow(
        id=record.id,
        installation_id=record.installation_id,
        owner=record.owner,
        repo=record.repo,
        full_name=record.full_name,
        default_branch=record.default_branch,
        selected_ref=record.selected_ref,
        html_url=record.html_url,
        created_at=record.created_at,
    )


def row_to_repository(row: RepositoryRow) -> RepositoryRecord:
    return RepositoryRecord(
        id=row.id,
        installation_id=row.installation_id,
        owner=row.owner,
        repo=row.repo,
        full_name=row.full_name,
        default_branch=row.default_branch,
        selected_ref=row.selected_ref,
        html_url=row.html_url,
        created_at=row.created_at,
    )


def row_to_agent_import(row: AgentImportRow, repository: RepositoryRecord, agent: AgentSpec) -> AgentImportRecord:
    return AgentImportRecord(
        id=row.id,
        source=row.source,
        repository=repository,
        agent=agent,
        warnings=list(row.warnings or []),
        recommended_scenario_ids=list(row.recommended_scenario_ids or []),
        commit_sha=row.commit_sha,
        created_at=row.created_at,
    )


def run_to_row(run: Run) -> RunRow:
    return RunRow(
        id=run.id,
        agent_id=run.agent_id,
        model_id=run.model_id,
        scenario_ids=run.scenario_ids,
        allow_cloud_analysis=run.allow_cloud_analysis,
        status=enum_value(run.status),
        created_at=run.created_at,
        completed_at=run.completed_at,
        score=run.score,
    )


def row_to_run(row: RunRow) -> Run:
    return Run(
        id=row.id,
        agent_id=row.agent_id,
        model_id=row.model_id,
        scenario_ids=list(row.scenario_ids or []),
        allow_cloud_analysis=row.allow_cloud_analysis,
        status=row.status,
        created_at=row.created_at,
        completed_at=row.completed_at,
        score=row.score,
    )


def row_to_event_record(row: RunEventRow) -> RunEventRecord:
    return RunEventRecord(
        run_id=row.run_id,
        sequence=row.sequence,
        timestamp=row.timestamp,
        actor=row.actor,
        message=row.message,
        scenario_id=row.scenario_id,
        tool_call=row.tool_call,
        policy_decision=row.policy_decision,
        risk_signal=row.risk_signal,
    )


def row_to_provider_call(row: ProviderCallRow) -> ProviderCallRecord:
    return ProviderCallRecord(
        id=row.id,
        run_id=row.run_id,
        provider=row.provider,
        model_id=row.model_id,
        status=row.status,
        request_summary=row.request_summary,
        response_summary=row.response_summary,
        error=row.error,
        redacted=row.redacted,
        created_at=row.created_at,
    )


def report_timestamp(report: Report) -> datetime:
    return utc_now()


def enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))
