import sqlalchemy as sa
from alembic import op

revision = "0002_workflow_data"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "diagnostic_steps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("step_id", sa.String(80), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_diagnostic_steps_session_id", "diagnostic_steps", ["session_id"])
    op.create_table(
        "packet_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("tcp_session_id", sa.String(36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_packet_events_session_id", "packet_events", ["session_id"])
    op.create_index("ix_packet_events_tcp_session_id", "packet_events", ["tcp_session_id"])
    op.create_table(
        "tcp_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_tcp_sessions_session_id", "tcp_sessions", ["session_id"])
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("html_path", sa.Text(), nullable=False),
        sa.Column("json_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_reports_session_id", "reports", ["session_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_index("ix_tcp_sessions_session_id", table_name="tcp_sessions")
    op.drop_table("tcp_sessions")
    op.drop_index("ix_packet_events_tcp_session_id", table_name="packet_events")
    op.drop_index("ix_packet_events_session_id", table_name="packet_events")
    op.drop_table("packet_events")
    op.drop_index("ix_diagnostic_steps_session_id", table_name="diagnostic_steps")
    op.drop_table("diagnostic_steps")
