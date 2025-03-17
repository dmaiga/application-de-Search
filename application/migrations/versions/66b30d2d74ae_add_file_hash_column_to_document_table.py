"""Add file_hash column to Document table

Revision ID: 66b30d2d74ae
Revises: 969cad55d411
Create Date: 2025-03-13 16:58:39.408123

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '66b30d2d74ae'
down_revision = '969cad55d411'
branch_labels = None
depends_on = None


def upgrade():
    # Ajouter la colonne file_hash avec une contrainte d'unicité nommée
    with op.batch_alter_table('document') as batch_op:
        batch_op.add_column(sa.Column('file_hash', sa.String(length=64), nullable=False))
        batch_op.create_unique_constraint('uq_document_file_hash', ['file_hash'])  # Ajout du nom de la contrainte

def downgrade():
    # Supprimer la contrainte d'unicité et la colonne file_hash
    with op.batch_alter_table('document') as batch_op:
        batch_op.drop_constraint('uq_document_file_hash', type_='unique')
        batch_op.drop_column('file_hash')