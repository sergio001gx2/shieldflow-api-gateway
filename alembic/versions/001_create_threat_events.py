"""Initial migration — Create threat_events table."""

from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone


revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client_ip", sa.String(length=64), nullable=False),
        sa.Column("request_path", sa.String(length=1024), nullable=False),
        sa.Column("request_method", sa.String(length=10), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("matched_pattern", sa.String(length=256), nullable=False),
        sa.Column("payload_location", sa.String(length=64), nullable=False),
        sa.Column("payload_snippet", sa.Text(), nullable=False),
        sa.Column("all_threats_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # Create indexes for dashboard queries
    op.create_index("ix_threat_events_client_ip", "threat_events", ["client_ip"])
    op.create_index("ix_threat_events_attack_type", "threat_events", ["attack_type"])
    op.create_index("ix_threat_events_detected_at", "threat_events", ["detected_at"])
    op.create_index(
        "ix_threat_events_ip_time",
        "threat_events",
        ["client_ip", "detected_at"],
    )
    op.create_index(
        "ix_threat_events_type_time",
        "threat_events",
        ["attack_type", "detected_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_events_type_time", table_name="threat_events")
    op.drop_index("ix_threat_events_ip_time", table_name="threat_events")
    op.drop_index("ix_threat_events_detected_at", table_name="threat_events")
    op.drop_index("ix_threat_events_attack_type", table_name="threat_events")
    op.drop_index("ix_threat_events_client_ip", table_name="threat_events")
    op.drop_table("threat_events")
