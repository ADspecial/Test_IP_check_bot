
from sqlalchemy import Column, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import NoResultFound, IntegrityError
from sqlalchemy.orm import InstrumentedAttribute

from datetime import datetime, timedelta
from database.models import Address, History, Virustotal, Ipinfo, Abuseipdb, Kaspersky, CriminalIP, Alienvault

from typing import Callable, List, Dict, Union, Tuple, Any, Type

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

async def orm_add_vt_ip(session: AsyncSession, data: dict) -> bool:
    """
    Добавляет или обновляет IP-адрес и связанные данные в базе данных.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Проверяем, существует ли адрес
        result = await session.execute(select(Address).where(Address.ip == data['ip_address']))
        existing_address = result.scalars().first()

        if existing_address:
            # Если адрес существует, обновляем данные Vt_ip
            vt_ip_result = await session.execute(select(Virustotal).where(Virustotal.address == existing_address.id))
            existing_vt_ip = vt_ip_result.scalars().first()

            if existing_vt_ip:
                # Обновляем существующую запись
                existing_vt_ip.verdict = data['verdict']
                existing_vt_ip.network = data['network']
                existing_vt_ip.owner = data['owner']
                existing_vt_ip.country = data['country']
                existing_vt_ip.rep_score = data['rep_score']
                existing_vt_ip.votes = data['votes']
                existing_vt_ip.stats = data['stats']
                existing_vt_ip.updated = func.current_timestamp()
            else:
                # Если записи Vt_ip не существует, создаем новую
                new_vt_ip = Virustotal(
                    address=existing_address.id,
                    verdict=data['verdict'],
                    network=data['network'],
                    owner=data['owner'],
                    country=data['country'],
                    rep_score=data['rep_score'],
                    votes=data['votes'],
                    stats=data['stats'],
                )
                session.add(new_vt_ip)

        else:
            # Если адрес не существует, создаем новый адрес и новую запись Vt_ip
            new_address = Address(ip=data['ip_address'])
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            new_vt_ip = Virustotal(
                verdict=data['verdict'],
                network=data['network'],
                owner=data['owner'],
                country=data['country'],
                rep_score=data['rep_score'],
                votes=data['votes'],
                stats=data['stats'],
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

async def orm_add_ipi_ip(session: AsyncSession, data: dict) -> bool:
    """
    Добавляет или обновляет IP-адрес и связанные данные в таблице Ipi_ip.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Проверяем, существует ли адрес
        result = await session.execute(select(Address).where(Address.ip == data['ip']))
        existing_address = result.scalars().first()

        if existing_address:
            # Если адрес существует, проверяем, существует ли запись Ipi_ip
            ipi_ip_result = await session.execute(select(Ipinfo).where(Ipinfo.address == existing_address.id))
            existing_ipi_ip = ipi_ip_result.scalars().first()

            if existing_ipi_ip:
                # Обновляем существующую запись
                existing_ipi_ip.country = data.get('country')
                existing_ipi_ip.region = data.get('region')
                existing_ipi_ip.city = data.get('city')
                existing_ipi_ip.org = data.get('org')
                existing_ipi_ip.loc = data.get('loc')
                existing_ipi_ip.updated = func.current_timestamp()
            else:
                # Если записи Ipi_ip не существует, создаем новую
                new_ipi_ip = Ipinfo(
                    address=existing_address.id,
                    country=data.get('country'),
                    region=data.get('region'),
                    city=data.get('city'),
                    org=data.get('org'),
                    loc=data.get('loc')
                )
                session.add(new_ipi_ip)

        else:
            # Если адрес не найден, создаем новый адрес
            new_address = Address(ip=data['ip'])  # Предполагается, что ID передается в data
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            # Создаем новую запись Ipi_ip
            new_ipi_ip = Ipinfo(
                address=new_address.id,
                country=data.get('country'),
                region=data.get('region'),
                city=data.get('city'),
                org=data.get('org'),
                loc=data.get('loc')
            )
            session.add(new_ipi_ip)

        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении IP-адреса {data['address_id']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных: {e}")
        await session.rollback()
        return False

async def orm_check_ip_in_table(session: AsyncSession, ip_address: str, table_model) -> bool:
    """
    Проверяет, существует ли указанный IP-адрес в заданной таблице.

    :param session: Асинхронная сессия для работы с базой данных.
    :param ip_address: IP-адрес для проверки.
    :param table_model: Модель таблицы для проверки (например, Vt_ip или Ipi_ip).
    :return: True, если IP-адрес существует в указанной таблице, иначе False.
    """
    try:
        # Выполняем запрос к таблице Address для получения ID адреса
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        existing_address = result.scalars().first()

        # Если адрес не найден, возвращаем False
        if not existing_address:
            return False

        # Выполняем запрос к указанной таблице по ID адреса
        result = await session.execute(select(table_model).where(table_model.address == existing_address.id))
        existing_record = result.scalars().first()

        # Возвращаем результат проверки
        return existing_record is not None

    except Exception as e:
        # Логируем ошибку (можно использовать logging)
        print(f"Ошибка при проверке IP-адреса {ip_address} в {table_model.__tablename__}: {e}")
        return False

async def orm_check_ip_in_table_updated(session: AsyncSession, ip_address: str, table_model) -> bool:
    """
    Проверяет, существует ли указанный IP-адрес в заданной таблице и обновлён ли он в течение последней недели.

    :param session: Асинхронная сессия для работы с базой данных.
    :param ip_address: IP-адрес для проверки.
    :param table_model: Модель таблицы для проверки (например, Vt_ip или Ipi_ip).
    :return: True, если IP-адрес существует в указанной таблице и был обновлён за последнюю неделю, иначе False.
    """
    try:
        # Выполняем запрос к таблице Address для получения ID адреса
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        existing_address = result.scalars().first()

        # Если адрес не найден, возвращаем False
        if not existing_address:
            return False

        # Выполняем запрос к указанной таблице по ID адреса
        result = await session.execute(select(table_model).where(table_model.address == existing_address.id))
        existing_record = result.scalars().first()

        # Если запись не найдена, возвращаем False
        if not existing_record:
            return False

        # Проверяем дату обновления записи
        if existing_record.updated:
            current_time = datetime.utcnow()
            if (current_time - existing_record.updated) <= timedelta(days=7):
                return True

        return False

    except Exception as e:
        print(f"Ошибка при проверке IP-адреса {ip_address} в {table_model.__tablename__}: {e}")
        return False

async def orm_add_abuseipdb(session: AsyncSession, data: dict) -> bool:
    """
    Добавляет или обновляет данные о злоупотреблении IP-адресом в таблице Abuseipdb.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        result = await session.execute(select(Address).where(Address.ip == data['ip_address']))
        existing_address = result.scalars().first()

        if existing_address:
            abuseipdb_result = await session.execute(select(Abuseipdb).where(Abuseipdb.address == existing_address.id))
            existing_abuse_record = abuseipdb_result.scalars().first()

            if existing_abuse_record:
                # Обновляем существующую запись
                existing_abuse_record.is_public = data.get('is_public')
                existing_abuse_record.ip_version = data.get('ip_version')
                existing_abuse_record.is_whitelisted = data.get('is_whitelisted')
                existing_abuse_record.abuse_confidence_score = data.get('abuse_confidence_score')
                existing_abuse_record.country = data.get('country')
                existing_abuse_record.usage_type = data.get('usage_type')
                existing_abuse_record.isp = data.get('isp')
                existing_abuse_record.domain = data.get('domain')
                existing_abuse_record.total_reports = data.get('total_reports')
                existing_abuse_record.num_distinct_users = data.get('num_distinct_users')
                existing_abuse_record.updated = func.current_timestamp()
            else:
                new_abuse_record = Abuseipdb(
                    address=existing_address.id,
                    is_public=data.get('is_public', True),
                    ip_version=data['ip_version'],
                    is_whitelisted=data.get('is_whitelisted'),
                    abuse_confidence_score=data.get('abuse_confidence_score'),
                    country=data.get('country'),
                    usage_type=data.get('usage_type'),
                    isp=data.get('isp'),
                    domain=data.get('domain'),
                    total_reports=data.get('total_reports'),
                    num_distinct_users=data.get('num_distinct_users'),
                    #last_reported_at=data.get('last_reported_at')
                )
                session.add(new_abuse_record)

        else:
            new_address = Address(ip=data['ip_address'])
            session.add(new_address)
            await session.commit()

            new_abuse_record = Abuseipdb(
                address=new_address.id,
                is_public=data.get('is_public', True),
                ip_version=data['ip_version'],
                is_whitelisted=data.get('is_whitelisted'),
                abuse_confidence_score=data.get('abuse_confidence_score'),
                country=data.get('country'),
                usage_type=data.get('usage_type'),
                isp=data.get('isp'),
                domain=data.get('domain'),
                total_reports=data.get('total_reports'),
                num_distinct_users=data.get('num_distinct_users'),
                #last_reported_at=data.get('last_reported_at')
            )
            session.add(new_abuse_record)


        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении записи Abuseipdb для адреса {data['ip_address']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных Abuseipdb: {e}")
        await session.rollback()
        return False

async def orm_get_abuseipdb_data(session: AsyncSession, ip_address: str) -> Dict[str, any]:
    """
    Ищет запись в таблице Abuseipdb по IP-адресу и возвращает данные в виде словаря.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, any]: Словарь, содержащий данные из таблицы Abuseipdb, или словарь с одним ключом 'error',
                        содержащий сообщение об ошибке, если запись не найдена.
    """
    try:
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().first()

        if not address:
            return {'error': 'IP not found in database'}

        result = await session.execute(select(Abuseipdb).where(Abuseipdb.address == address.id))
        abuse_data = result.scalars().first()

        if not abuse_data:
            return {'error': 'IP not found in Abuseipdb table'}

        response = {
            'ip_address': ip_address,
            'is_public': abuse_data.is_public,
            'ip_version': abuse_data.ip_version,
            'is_whitelisted': abuse_data.is_whitelisted,
            'abuse_confidence_score': abuse_data.abuse_confidence_score,
            'country': abuse_data.country,
            'usage_type': abuse_data.usage_type,
            'isp': abuse_data.isp,
            'domain': abuse_data.domain,
            'total_reports': abuse_data.total_reports,
            'num_distinct_users': abuse_data.num_distinct_users,
            #'last_reported_at': abuse_data.last_reported_at
        }

        return response

    except Exception as e:
        print(f"Ошибка при поиске IP-адреса {ip_address} в Abuseipdb: {e}")
        return {'error': str(e)}

async def orm_get_kaspersky_data(session: AsyncSession, ip_address: str) -> Dict[str, Any]:
    """
    Ищет запись в таблице Kaspersky по IP-адресу и возвращает данные в виде словаря.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, Any]: Словарь, содержащий данные из таблицы Kaspersky, или словарь с одним ключом 'error',
                        содержащий сообщение об ошибке, если запись не найдена.
    """
    try:
        # Получаем адрес по IP
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().first()

        if not address:
            return {'error': 'IP not found in database'}

        # Получаем данные из таблицы Kaspersky по адресу
        result = await session.execute(select(Kaspersky).where(Kaspersky.address == address.id))
        kaspersky_data = result.scalars().first()

        if not kaspersky_data:
            return {'error': 'IP not found in Kaspersky table'}

        response = {
            'ip_address': ip_address,
            'status': kaspersky_data.status,
            'country': kaspersky_data.country,
            'net_name': kaspersky_data.net_name,
            'verdict': kaspersky_data.verdict,
        }

        return response

    except Exception as e:
        print(f"Ошибка при поиске IP-адреса {ip_address} в Kaspersky: {e}")
        return {'error': str(e)}

async def orm_add_kaspersky_data(session: AsyncSession, data: Dict[str, any]) -> bool:
    """
    Добавляет или обновляет данные о IP-адресе в таблице Kaspersky.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Поиск существующего адреса по IP
        result = await session.execute(select(Address).where(Address.ip == data['ip_address']))
        existing_address = result.scalars().first()

        if existing_address:
            # Поиск существующей записи в Kaspersky
            kaspersky_result = await session.execute(select(Kaspersky).where(Kaspersky.address == existing_address.id))
            existing_kaspersky_record = kaspersky_result.scalars().first()

            if existing_kaspersky_record:
                # Обновляем существующую запись
                existing_kaspersky_record.status = data.get('status')
                existing_kaspersky_record.country = data.get('country')
                existing_kaspersky_record.net_name = data.get('net_name')
                existing_kaspersky_record.verdict = data.get('verdict')
                existing_kaspersky_record.updated = func.current_timestamp()
            else:
                # Создаем новую запись в Kaspersky
                new_kaspersky_record = Kaspersky(
                    address=existing_address.id,
                    status=data.get('status'),
                    country=data.get('country'),
                    net_name=data.get('net_name'),
                    verdict=data.get('verdict'),
                )
                session.add(new_kaspersky_record)

        else:
            # Если адрес не найден, создаем новый адрес и новую запись в Kaspersky
            new_address = Address(ip=data['ip_address'])
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            new_kaspersky_record = Kaspersky(
                address=new_address.id,
                status=data.get('status'),
                country=data.get('country'),
                net_name=data.get('net_name'),
                verdict=data.get('verdict'),
            )
            session.add(new_kaspersky_record)

        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении записи Kaspersky для адреса {data['ip_address']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных Kaspersky: {e}")
        await session.rollback()
        return False

async def orm_add_criminalip_data(session: AsyncSession, data: Dict[str, any]) -> bool:
    """
    Добавляет или обновляет данные о IP-адресе в таблице CriminalIP.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Поиск существующего адреса по IP
        result = await session.execute(select(Address).where(Address.ip == data['ip_address']))
        existing_address = result.scalars().first()

        if existing_address:
            # Поиск существующей записи в CriminalIP
            criminal_ip_result = await session.execute(select(CriminalIP).where(CriminalIP.address == existing_address.id))
            existing_criminal_record = criminal_ip_result.scalars().first()

            if existing_criminal_record:
                # Обновляем существующую запись
                existing_criminal_record.verdict = data.get('verdict')
                existing_criminal_record.open_ports = data.get('open_ports')
                existing_criminal_record.hostname = data.get('hostname')
                existing_criminal_record.country = data.get('country')
                existing_criminal_record.updated = func.current_timestamp()
            else:
                # Создаем новую запись в CriminalIP
                new_criminal_record = CriminalIP(
                    address=existing_address.id,
                    verdict=data.get('verdict'),
                    open_ports=data.get('open_ports'),
                    hostname=data.get('hostname'),
                    country=data.get('country'),
                )
                session.add(new_criminal_record)

        else:
            # Если адрес не найден, создаем новый адрес и новую запись в CriminalIP
            new_address = Address(ip=data['ip_address'])
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            new_criminal_record = CriminalIP(
                address=new_address.id,
                verdict=data.get('verdict'),
                open_ports=data.get('open_ports'),
                hostname=data.get('hostname'),
                country=data.get('country'),
            )
            session.add(new_criminal_record)

        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении записи CriminalIP для адреса {data['ip_address']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных CriminalIP: {e}")
        await session.rollback()
        return False

async def orm_get_criminalip_data(session: AsyncSession, ip_address: str) -> Dict[str, Any]:
    """
    Ищет запись в таблице CriminalIP по IP-адресу и возвращает данные в виде словаря.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, Any]: Словарь, содержащий данные из таблицы CriminalIP, или словарь с одним ключом 'error',
                        содержащий сообщение об ошибке, если запись не найдена.
    """
    try:
        # Получаем адрес по IP
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().first()

        if not address:
            return {'error': 'IP not found in database'}

        # Получаем данные из таблицы CriminalIP по адресу
        result = await session.execute(select(CriminalIP).where(CriminalIP.address == address.id))
        criminal_ip_data = result.scalars().first()

        if not criminal_ip_data:
            return {'error': 'IP not found in CriminalIP table'}

        response = {
            'ip_address': ip_address,
            'verdict': criminal_ip_data.verdict,
            'open_ports': criminal_ip_data.open_ports,
            'hostname': criminal_ip_data.hostname,
            'country': criminal_ip_data.country,
        }

        return response

    except Exception as e:
        print(f"Ошибка при поиске IP-адреса {ip_address} в CriminalIP: {e}")
        return {'error': str(e)}

async def orm_get_alienvault_data(session: AsyncSession, ip_address: str) -> Dict[str, Any]:
    """
    Ищет запись в таблице Alienvault по IP-адресу и возвращает данные в виде словаря.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, Any]: Словарь, содержащий данные из таблицы Alienvault, или словарь с одним ключом 'error',
                        содержащий сообщение об ошибке, если запись не найдена.
    """
    try:
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        address = result.scalars().first()

        if not address:
            return {'error': 'IP not found in database'}

        result = await session.execute(select(Alienvault).where(Alienvault.address == address.id))
        alienvault_data = result.scalars().first()

        if not alienvault_data:
            return {'error': 'IP not found in Alienvault table'}

        response = {
            'ip_address': ip_address,
            'verdict': alienvault_data.verdict,
            'country': alienvault_data.country,
            'asn': alienvault_data.asn,
        }

        return response

    except Exception as e:
        print(f"Ошибка при поиске IP-адреса {ip_address} в Alienvault: {e}")
        return {'error': str(e)}

async def orm_add_alienvault_data(session: AsyncSession, data: Dict[str, Any]) -> bool:
    """
    Добавляет или обновляет данные о IP-адресе в таблице Alienvault.

    :param session: Асинхронная сессия для работы с базой данных.
    :param data: Словарь с данными для добавления или обновления.
    :return: True в случае успешного добавления или обновления, иначе False.
    """
    try:
        # Поиск существующего адреса по IP
        result = await session.execute(select(Address).where(Address.ip == data['ip_address']))
        existing_address = result.scalars().first()

        if existing_address:
            # Поиск существующей записи в Alienvault
            alienvault_result = await session.execute(select(Alienvault).where(Alienvault.address == existing_address.id))
            existing_alienvault_record = alienvault_result.scalars().first()

            if existing_alienvault_record:
                # Обновляем существующую запись
                existing_alienvault_record.verdict = data.get('verdict')
                existing_alienvault_record.country = data.get('country')
                existing_alienvault_record.asn = data.get('asn')
                existing_alienvault_record.updated = func.current_timestamp()
            else:
                # Создаем новую запись в Alienvault
                new_alienvault_record = Alienvault(
                    address=existing_address.id,
                    verdict=data.get('verdict'),
                    country=data.get('country'),
                    asn=data.get('asn'),
                )
                session.add(new_alienvault_record)

        else:
            # Если адрес не найден, создаем новый адрес и новую запись в Alienvault
            new_address = Address(ip=data['ip_address'])
            session.add(new_address)
            await session.commit()  # Сохраняем новый адрес

            new_alienvault_record = Alienvault(
                address=new_address.id,
                verdict=data.get('verdict'),
                country=data.get('country'),
                asn=data.get('asn'),
            )
            session.add(new_alienvault_record)

        await session.commit()  # Сохраняем изменения
        return True

    except IntegrityError as e:
        print(f"Ошибка при добавлении/обновлении записи Alienvault для адреса {data['ip_address']}: {e}")
        await session.rollback()
        return False
    except Exception as e:
        print(f"Ошибка при добавлении/обновлении данных Alienvault: {e}")
        await session.rollback()
        return False

async def orm_get_data_ip(
    session: AsyncSession,
    table_name: Type,
    ip_address: str,
) -> Dict[str, Any]:
    """
    Универсальная функция для получения информации из любой таблицы по IP-адресу.

    Аргументы:
        session (AsyncSession): Асинхронная сессия для работы с базой данных.
        table_model (Type): Модель таблицы базы данных.
        ip_address (str): IP-адрес для поиска.

    Возвращает:
        Dict[str, Any]: Словарь с данными из таблицы или ошибкой, если запись не найдена.
    """
    try:
        # Ищем запись в таблице по IP-адресу
        result = await session.execute(select(Address).where(Address.ip == ip_address))
        adress = result.scalars().first()

        if not adress:
            return {'error': f'IP {ip_address} not found in {Address.__name__} table'}

        result = await session.execute(select(table_name).where(table_name.address == adress.id))
        record = result.scalars().first()

        # Преобразуем объект записи в словарь
        response = {column.name: getattr(record, column.name) for column in table_name.__table__.columns}
        response['ip_address'] = ip_address

        return response

    except Exception as e:
        print(f"Ошибка при поиске IP-адреса {ip_address} в таблице {table_name.__name__}: {e}")
        return {'error': str(e)}
