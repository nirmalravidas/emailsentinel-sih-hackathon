"""Alembic environment configured from EmailSentinel settings."""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app import config
from app.database.base import Base
from app.database import models  # noqa: F401 - registers all model metadata

if context.config.config_file_name is not None:
    fileConfig(context.config.config_file_name)

context.config.set_main_option("sqlalchemy.url", config.DATABASE_URL.replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        context.config.get_section(context.config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
