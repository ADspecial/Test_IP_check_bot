
from sqlalchemy import Column, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound, IntegrityError

from datetime import datetime, timedelta
from database.models import Address, History, Vt_ip

from typing import Callable, List, Dict, Union, Tuple

async def orm_check_ip_in_db(session: AsyncSession, ip_address: str) -> bool:
    """
    Проверяет, существует ли указанный IP-адрес в базе данных.

    :param session: Асинхронная сессия для работы с базой данных.
    :param ip_address: IP-адрес для проверки.
    :return: True, если IP-адрес существует, иначе False.
    """
    try:
        # Выполняем запрос к базе данных
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        return result.scalars().first() is not None
        existing_address = result.scalars().first()

        # Возвращаем результат проверки
        return existing_address is not None

    except Exception as e:
        # Логируем ошибку (можно использовать logging)
        print(f"Ошибка при проверке IP-адреса {ip_address}: {e}")
        return False

async def orm_check_ip_in_vt(session: AsyncSession, ip_address: str) -> bool:
    """
    Проверяет, существует ли указанный IP-адрес в таблице Vt_ip.

    :param session: Асинхронная сессия для работы с базой данных.
    :param ip_address: IP-адрес для проверки.
    :return: True, если IP-адрес существует в таблице Vt_ip, иначе False.
    """
    try:
        # Выполняем запрос к таблице Address для получения ID адреса
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        existing_address = result.scalars().first()

        # Если адрес не найден, возвращаем False
        if not existing_address:
            return False

        # Выполняем запрос к таблице Vt_ip по ID адреса
        result = await session.execute(select(Vt_ip).where(Vt_ip.address == existing_address.id))
        existing_vt_record = result.scalars().first()

        # Возвращаем результат проверки
        return existing_vt_record is not None

    except Exception as e:
        # Логируем ошибку (можно использовать logging)
        print(f"Ошибка при проверке IP-адреса {ip_address} в Vt_ip: {e}")
        return False

async def orm_check_ip_in_vt_updated(session: AsyncSession, ip_address: str) -> bool:
    try:
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        existing_address = result.scalars().first()

        if not existing_address:
            return False

        result = await session.execute(select(Vt_ip).where(Vt_ip.address == existing_address.id))
        existing_vt_record = result.scalars().first()

        if not existing_vt_record:
            return False

        if existing_vt_record.updated:
            current_time = datetime.utcnow()
            if (current_time - existing_vt_record.updated) <= timedelta(days=7):
                return True

        return False

    except Exception as e:
        print(f"Ошибка при проверке IP-адреса {ip_address} в Vt_ip: {e}")
        return False

async def orm_get_vt_ip(session: AsyncSession, ip_address: str) -> Dict[str, any]:
    """
    Ищет запись в таблице Vt_ip по IP-адресу.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, any]: Словарь, содержащий данные из таблицы Vt_ip, или словарь с одним ключом 'error' содержащий сообщение об ошибке, если запись не найдена.
    """
    try:
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().first()
        result = await session.execute(select(Vt_ip).where(Vt_ip.address == address.id))
        vt_ip_data = result.scalars().first()
        response = {
            'ip': address.ip,
            'verdict': vt_ip_data.verdict,
            'network': vt_ip_data.network,
            'owner': vt_ip_data.owner,
            'country': vt_ip_data.country,
            'rep_score': vt_ip_data.rep_score,
            'users_votes': {
                'malicious': vt_ip_data.vote_malicious,
                'harmless': vt_ip_data.vote_harmless
            },
            'stats': {
                'total engines': vt_ip_data.stat_malicious + vt_ip_data.stat_suspicious + vt_ip_data.stat_harmless + vt_ip_data.stat_undetected,
                'malicious': vt_ip_data.stat_malicious,
                'suspicious': vt_ip_data.stat_suspicious,
                'harmless': vt_ip_data.stat_harmless,
                'undetected': vt_ip_data.stat_undetected
            },
            'last_analysis_date': vt_ip_data.last_analysis_date
        }
        return response
    except NoResultFound:
        return {'error': 'IP not found in database'}

async def orm_add_vt_ip(session: AsyncSession, data: dict) -> bool:
    """
    Добавляет или обновляет IP-адрес и связанные данные в базе данных.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Проверяем, существует ли адрес
        result = await session.execute(select(Address).where(Address.ip == data['ip']))
        existing_address = result.scalars().first()

        if existing_address:
            # Если адрес существует, обновляем данные Vt_ip
            vt_ip_result = await session.execute(select(Vt_ip).where(Vt_ip.address == existing_address.id))
            existing_vt_ip = vt_ip_result.scalars().first()

            if existing_vt_ip:
                # Обновляем существующую запись
                existing_vt_ip.verdict = data['verdict']
                existing_vt_ip.network = data['network']
                existing_vt_ip.owner = data['owner']
                existing_vt_ip.country = data['country']
                existing_vt_ip.vote_malicious = data['stats']['malicious']
                existing_vt_ip.vote_harmless = data['stats']['harmless']
                existing_vt_ip.stat_malicious = data['stats']['malicious']
                existing_vt_ip.stat_suspicious = data['stats']['suspicious']
                existing_vt_ip.stat_harmless = data['stats']['harmless']
                existing_vt_ip.stat_undetected = data['stats']['undetected']
                existing_vt_ip.last_analysis_date = datetime.strptime(data['last_analysis_date'], '%Y-%m-%d %H:%M:%S')
                existing_vt_ip.updated = func.current_timestamp()
                #update(session, Vt_ip, existing_vt_ip)
            else:
                # Если записи Vt_ip не существует, создаем новую
                new_vt_ip = Vt_ip(
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
                )
                session.add(new_vt_ip)

        else:
            # Если адрес не существует, создаем новый адрес и новую запись Vt_ip
            new_address = Address(ip=data['ip'])
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            new_vt_ip = Vt_ip(
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
                address=new_address.id
            )
            session.add(new_vt_ip)

        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении IP-адреса {data['ip']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных: {e}")
        await session.rollback()
        return False

async def orm_delete_vt_ip(session: AsyncSession, ip_address: str) -> bool:
    """
    Удаляет IP-адрес и связанные данные из базы данных.

    :param session: Асинхронная сессия для работы с базой данных.
    :param ip_address: IP-адрес для удаления.
    :return: True в случае успешного удаления, иначе False.
    """
    try:
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().one_or_none()

        if not address:
            print(f"IP-адрес {ip_address} не найден.")
            return False

        if address.vt_ip:
            await session.delete(address.vt_ip)

        await session.delete(address)
        await session.commit()

        return True

    except IntegrityError as e:
        print(f"Ошибка при удалении IP-адреса {ip_address}: {e}")
        await session.rollback()
        return False

    except Exception as e:
        print(f"Ошибка при удалении данных: {e}")
        await session.rollback()
        return False

async def orm_add_file_history(session: AsyncSession, message_id: int, file_path: str) -> bool:
    """
    Сохранение пути к файлу в таблицу history.

    Аргументы:
        session: Асинхронная сессия для работы с базой данных.
        user_id: ID пользователя.
        chat_id: ID чата.
        message_id: ID сообщения.
        file_path: Путь к файлу, который нужно сохранить.
    """
    try:
        result = await session.execute(select(History).where(History.message_id == message_id))
        existing_history = result.scalars().first()
        if existing_history:
            existing_history.message = '__data file__'
            existing_history.file_path = file_path
            await session.commit()
            return True
        else:
            return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных: {e}")
        await session.rollback()
        return False
