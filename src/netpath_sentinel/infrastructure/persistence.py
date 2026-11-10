import json
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from netpath_sentinel.domain.models import (
    DiagnosticConfig,
    DiagnosticStep,
    Evidence,
    Finding,
    PacketEvent,
    TCPSession,
    utc_now,
)


class Base(DeclarativeBase):
    pass


class StoredSession(Base):
    __tablename__ = "diagnostic_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(30), default="running")
    config: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True))


class StoredEvidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_type: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(30))
    observation: Mapped[dict[str, Any]] = mapped_column(JSON)
    raw_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[str] = mapped_column(DateTime(timezone=True))


class StoredFinding(Base):
    __tablename__ = "rca_findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    code: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    conclusion: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class StoredStep(Base):
    __tablename__ = "diagnostic_steps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    step_id: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(30))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class StoredPacket(Base):
    __tablename__ = "packet_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    tcp_session_id: Mapped[str] = mapped_column(String(36), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class StoredTCPSession(Base):
    __tablename__ = "tcp_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class StoredReport(Base):
    __tablename__ = "reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    html_path: Mapped[str] = mapped_column(Text)
    json_path: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True))


class Repository:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{database_path}", future=True)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)
        Base.metadata.create_all(self.engine)
        if os.name != "nt" and database_path.exists():
            database_path.chmod(0o600)

    def save_session(
        self, session_id: str, config: DiagnosticConfig, status: str = "created"
    ) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredSession(
                    id=session_id,
                    name=config.name,
                    status=status,
                    config=config.model_dump(mode="json"),
                    created_at=utc_now(),
                )
            )

    def list_sessions(self) -> list[StoredSession]:
        with self.sessions() as db:
            return list(db.query(StoredSession).order_by(StoredSession.created_at.desc()).all())

    def update_session_status(self, session_id: str, status: str) -> None:
        with self.sessions.begin() as db:
            session = db.get(StoredSession, session_id)
            if session:
                session.status = status

    def save_step(self, step: DiagnosticStep) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredStep(
                    id=step.id,
                    session_id=step.session_id,
                    step_id=step.step_id,
                    name=step.name,
                    status=step.status.value,
                    payload=json.loads(step.model_dump_json()),
                )
            )

    def save_packet(self, packet: PacketEvent, tcp_session_id: str, session_id: str) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredPacket(
                    id=str(uuid4()),
                    session_id=session_id,
                    tcp_session_id=tcp_session_id,
                    payload=json.loads(packet.model_dump_json()),
                )
            )

    def save_tcp_session(self, session: TCPSession, session_id: str) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredTCPSession(
                    id=session.id,
                    session_id=session_id,
                    payload=json.loads(session.model_dump_json(exclude={"packets"})),
                )
            )

    def save_report(self, session_id: str, html_path: str, json_path: str) -> None:
        with self.sessions.begin() as db:
            db.add(
                StoredReport(
                    id=str(uuid4()),
                    session_id=session_id,
                    html_path=html_path,
                    json_path=json_path,
                    created_at=utc_now(),
                )
            )

    def session_bundle(self, session_id: str) -> dict[str, list[dict[str, Any]]]:
        with self.sessions() as db:
            return {
                "steps": [
                    item.payload
                    for item in db.query(StoredStep).filter_by(session_id=session_id).all()
                ],
                "packets": [
                    {**item.payload, "tcp_session_id": item.tcp_session_id}
                    for item in db.query(StoredPacket).filter_by(session_id=session_id).all()
                ],
                "tcp_sessions": [
                    item.payload
                    for item in db.query(StoredTCPSession).filter_by(session_id=session_id).all()
                ],
                "findings": [
                    item.payload
                    for item in db.query(StoredFinding).filter_by(session_id=session_id).all()
                ],
                "reports": [
                    {
                        "html_path": item.html_path,
                        "json_path": item.json_path,
                        "created_at": str(item.created_at),
                    }
                    for item in db.query(StoredReport).filter_by(session_id=session_id).all()
                ],
            }

    def save_evidence(self, evidence: Evidence) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredEvidence(
                    id=evidence.id,
                    session_id=evidence.session_id,
                    evidence_type=evidence.evidence_type,
                    status=evidence.status.value,
                    observation=evidence.observation,
                    raw_reference=evidence.raw_reference,
                    collected_at=evidence.collected_at,
                )
            )

    def save_finding(self, finding: Finding) -> None:
        with self.sessions.begin() as db:
            db.merge(
                StoredFinding(
                    id=finding.id,
                    session_id=finding.session_id,
                    code=finding.code,
                    severity=finding.severity.value,
                    confidence=finding.confidence.value,
                    conclusion=finding.conclusion,
                    payload=json.loads(finding.model_dump_json()),
                )
            )
