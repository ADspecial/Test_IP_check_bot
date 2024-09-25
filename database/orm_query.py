
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import Address, Vt_ip

async def orm_add_vt_ipv4(session: AsyncSession, data: dict):
    obj1 = Address(
        ipv4 = data['ip'],
    )
    session.add(obj1)
    await session.commit()
    obj2 = Vt_ip(
        verdict = data['verdict'],
        network = data['network'],
        owner = data['owner'],
        country = data['country'],
        vote_malicious = data['stats']['vote_malicious'],
        vote_harmless = data['stats']['vote_harmless'],
        stat_malicious = data['stats']['stat_malicious'],
        stat_suspicious = data['stats']['stat_suspicious'],
        stat_harmless = data['stats']['stat_harmless'],
        stat_undetected = data['stats']['stat_undetected'],
        last_analysis_date = data['stats']['last_analysis_date'],
        address_id = obj1.id
    )
    session.add(obj2)
    await session.commit()
