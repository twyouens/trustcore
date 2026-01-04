"""
Alembic migration - Allow null requested_by_id for SCEP certificates
Filename: 003_allow_null_requested_by.py
Location: alembic/versions/

Revision ID: 003_allow_null_requested_by
Revises: 002_add_api_tokens_and_scep
Create Date: 2026-01-03
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '003_allow_null_requested_by'
down_revision = '002_api_and_scep'
branch_labels = None
depends_on = None


def upgrade():
    # Make requested_by_id nullable for SCEP certificates
    op.alter_column('certificates', 'requested_by_id',
                    existing_type=sa.Integer(),
                    nullable=True)


def downgrade():
    # Revert to non-nullable (only if no NULL values exist)
    op.alter_column('certificates', 'requested_by_id',
                    existing_type=sa.Integer(),
                    nullable=False)