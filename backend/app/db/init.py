import asyncio

from app.db.base import Base
from app.db.session import engine
from app.models.case import Case  # noqa: F401
from app.models.evidence import Evidence


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


if __name__ == "__main__":
    asyncio.run(init_db())
