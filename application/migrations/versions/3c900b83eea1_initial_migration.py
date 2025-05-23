"""Initial migration

Revision ID: 3c900b83eea1
Revises: 
Create Date: 2025-03-13 01:56:23.530293

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3c900b83eea1'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('document',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('doc_id', sa.String(length=36), nullable=True),
    sa.Column('doc_name', sa.String(length=255), nullable=False),
    sa.Column('doc_type', sa.String(length=100), nullable=False),
    sa.Column('doc_format', sa.Enum('pdf', 'word', name='doc_format_enum'), nullable=False),
    sa.Column('file_path', sa.Text(), nullable=False),
    sa.Column('insert_date', sa.DateTime(), nullable=True),
    sa.Column('updated_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('doc_id')
    )
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=100), nullable=False),
    sa.Column('email', sa.String(length=150), nullable=False),
    sa.Column('password', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('role', sa.Enum('admin', 'user', name='role'), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('users')
    op.drop_table('document')
    # ### end Alembic commands ###
