
import asyncio

from app.db.base import Base
from app.db.session import engine

# Import the models package so its registered models are loaded.
import app.models  # noqa: F401

# These models exist in the project but aren't currently imported
# by app/models/__init__.py.
import app.models.case_activity  # noqa: F401
import app.models.report  # noqa: F401


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


if __name__ == "__main__":
    asyncio.run(init_db())
