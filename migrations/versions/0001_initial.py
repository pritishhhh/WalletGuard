from pathlib import Path
from alembic import op

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Checked-in schema is the authoritative initial migration, including PostgreSQL constraints.
    sql = (Path(__file__).parents[1] / 'schema.sql').read_text(encoding='utf-8')
    op.get_bind().connection.driver_connection.execute(sql)


def downgrade():
    raise RuntimeError('Ledger destruction is forbidden; restore a backup instead of downgrading')
