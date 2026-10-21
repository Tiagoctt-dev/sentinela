# Persistência do histórico de scans (PostgreSQL via SQLAlchemy).

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TargetModel(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String, unique=True)
    # "file"   — seedado de targets/*.json (exemplo, somente leitura via API, editável no arquivo)
    # "custom" — cadastrado pelo usuário via API/UI (editável e excluível livremente)
    source: Mapped[str] = mapped_column(String, default="custom")
    config: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    runs: Mapped[list["ScanRun"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    credentials: Mapped[list["CredentialModel"]] = relationship(cascade="all, delete-orphan")


class CredentialModel(Base):
    """Usuário de teste de um alvo (ex.: um usuário comum e um admin). A senha
    fica criptografada e nunca é devolvida pela API."""

    __tablename__ = "target_credentials"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="user")
    username: Mapped[str] = mapped_column(String)
    password_enc: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    target_name: Mapped[str] = mapped_column(String)
    mode: Mapped[str] = mapped_column(String)
    overall_score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String)
    categories: Mapped[dict] = mapped_column(JSON)
    totals: Mapped[dict] = mapped_column(JSON)
    ai: Mapped[dict] = mapped_column(JSON, nullable=True)
    policy: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String, nullable=True)
    origin: Mapped[str] = mapped_column(String, nullable=True)  # "manual" | "agendado"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    target: Mapped["TargetModel"] = relationship(back_populates="runs")
    findings: Mapped[list["FindingModel"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(ForeignKey("scan_runs.id"))
    finding_id: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    detail: Mapped[str] = mapped_column(String, nullable=True)
    recommendation: Mapped[str] = mapped_column(String, nullable=True)
    evidence: Mapped[str] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String)
    owasp: Mapped[str] = mapped_column(String, nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=True)
    ai_rec: Mapped[dict] = mapped_column(JSON, nullable=True)
    # Workflow de triagem: "open" | "resolved" | "risk_accepted" — separado do
    # status técnico (PASS/FAIL/WARN/SKIP), que é o resultado do scan em si.
    resolution: Mapped[str] = mapped_column(String, default="open")
    resolution_note: Mapped[str] = mapped_column(String, nullable=True)

    run: Mapped["ScanRun"] = relationship(back_populates="findings")


class WebhookModel(Base):
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    url: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str] = mapped_column(String, nullable=True)
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GithubIntegrationModel(Base):
    __tablename__ = "github_integrations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    repo: Mapped[str] = mapped_column(String)
    token: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str] = mapped_column(String, nullable=True)
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class SlackIntegrationModel(Base):
    __tablename__ = "slack_integrations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String)
    webhook_url: Mapped[str] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status: Mapped[str] = mapped_column(String, nullable=True)
    last_triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True)
    name: Mapped[str] = mapped_column(String)
    password_hash: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="analyst")  # admin | analyst | viewer
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLogModel(Base):
    """Quem fez o quê. Guarda método, rota e resultado — nunca o corpo da requisição."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_email: Mapped[str] = mapped_column(String, nullable=True)
    method: Mapped[str] = mapped_column(String)
    path: Mapped[str] = mapped_column(String)
    status_code: Mapped[int] = mapped_column(Integer)
    ip: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class ScheduleModel(Base):
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), unique=True)
    interval_hours: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String, nullable=True)
    created_by: Mapped[str] = mapped_column(String, nullable=True)
