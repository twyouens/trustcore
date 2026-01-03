"""
Alembic migration - Add API tokens and SCEP clients
Filename: 002_api_and_scep.py
Location: alembic/versions/

Revision ID: 002_api_and_scep
Revises: 001_initial_migration
Create Date: 2026-01-03

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

# revision identifiers, used by Alembic.
revision = '002_api_and_scep'
down_revision = '001'  # Update to match your first migration
branch_labels = None
depends_on = None


def upgrade():
    # Create api_tokens table
    op.create_table(
        'api_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('scopes', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_by_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_api_tokens_user_id'),
        sa.ForeignKeyConstraint(['revoked_by_id'], ['users.id'], name='fk_api_tokens_revoked_by_id'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash', name='uq_api_tokens_token_hash')
    )
    op.create_index('ix_api_tokens_id', 'api_tokens', ['id'])
    op.create_index('ix_api_tokens_token_hash', 'api_tokens', ['token_hash'])
    
    # Create scep_clients table
    op.create_table(
        'scep_clients',
        sa.Column('id', UUID(as_uuid=True), nullable=False, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('allowed_certificate_types', ARRAY(sa.String()), nullable=False),
        sa.Column('user_validation_url', sa.String(length=500), nullable=True),
        sa.Column('machine_validation_url', sa.String(length=500), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('total_requests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('successful_requests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_requests', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], name='fk_scep_clients_created_by_id'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scep_clients_id', 'scep_clients', ['id'])
    op.create_index('ix_scep_clients_enabled', 'scep_clients', ['enabled'])


def downgrade():
    # Drop scep_clients table
    op.drop_index('ix_scep_clients_enabled', table_name='scep_clients')
    op.drop_index('ix_scep_clients_id', table_name='scep_clients')
    op.drop_table('scep_clients')
    
    # Drop api_tokens table
    op.drop_index('ix_api_tokens_token_hash', table_name='api_tokens')
    op.drop_index('ix_api_tokens_id', table_name='api_tokens')
    op.drop_table('api_tokens')