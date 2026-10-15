import asyncio

from app.db.base import Base
from app.db.session import engine

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.pcap_analysis import PcapAnalysis
from app.models.network_flow import NetworkFlow
from app.models.network_host import NetworkHost
from app.models.dns_record import DNSRecord
from app.models.http_transaction import HTTPTransaction
from app.models.tls_session import TLSSession


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all
        )


if __name__ == "__main__":
    asyncio.run(init_db())