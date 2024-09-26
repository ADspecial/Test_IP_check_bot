
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.dialects.postgresql import INET
from datetime import datetime, timedelta
from database.models import Address, Vt_ip

async def orm_check_ip_in_db(session: AsyncSession, ip_address: str):
    result = await session.execute(select(Address).where(Address.ipv4 == ip_address))
    existing_address = result.scalars().first()
    retrun = True if existing_address else False


async def orm_add_vt_ipv4(session: AsyncSession, data: dict):
    ip_address = data['ip']
    result = await session.execute(select(Address).where(Address.ipv4 == ip_address))
    existing_address = result.scalars().first()

    if existing_address:
        if existing_address.updated and (datetime.utcnow() - existing_address.updated) > timedelta(hours=48):
            existing_address.block = False
            obj2 = Vt_ip(
                verdict=data['verdict'],
                network=data['network'],
                owner=data['owner'],
                country=data['country'],
                vote_malicious=data['stats']['malicious'],
                vote_harmless=data['stats']['harmless'],
                stat_malicious=data['stats']['malicious'],
                stat_suspicious=data['stats']['suspicious'],
                stat_harmless=data['stats']['harmless'],
                stat_undetected=data['stats']['undetected'],
                last_analysis_date=datetime.strptime(data['last_analysis_date'], '%Y-%m-%d %H:%M:%S'),
                address=existing_address.id
            )
            session.add(obj2)
        else:
            return
    else:
        obj1 = Address(
            ipv4 = data['ip'],
            block = False
        )
        session.add(obj1)
        await session.commit()
        obj2 = Vt_ip(
            verdict = data['verdict'],
            network = data['network'],
            owner = data['owner'],
            country = data['country'],
            vote_malicious = data['stats']['malicious'],
            vote_harmless = data['stats']['harmless'],
            stat_malicious = data['stats']['malicious'],
            stat_suspicious = data['stats']['suspicious'],
            stat_harmless = data['stats']['harmless'],
            stat_undetected = data['stats']['undetected'],
            last_analysis_date = datetime.strptime(data['last_analysis_date'], '%Y-%m-%d %H:%M:%S'),
            address = obj1.id
        )
    session.add(obj2)
    await session.commit()
