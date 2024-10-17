import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    BigInteger,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.types import JSON
from sqlalchemy import Table, Column, Integer, ForeignKey

class Base(DeclarativeBase):
    created = Column(DateTime, default=datetime.datetime.now)
    updated = Column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp())

blocklist_address_association = Table(
    'blocklist_address',
    Base.metadata,
    Column('blocklist_id', Integer, ForeignKey('blocklist.id'), primary_key=True),
    Column('address_id', Integer, ForeignKey('address.id'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(32), nullable=True)
    last_name = Column(String(32), nullable=True)
    username = Column(String(32), nullable=False, unique=True)
    admin_rights = Column(Boolean, nullable=False)

    history_command = relationship('History', backref='user')
    blcok_ip = relationship('BlockList', backref='user')

class History(Base):
    __tablename__ = 'history'

    message_id= Column(Integer, primary_key=True)
    chat_id = Column(BigInteger, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    message = Column(String(4096), nullable=True)
    file_path = Column(String(255), nullable=True)

class Address(Base):
    __tablename__ = 'address'

    id = Column(Integer, primary_key=True)
    ip = Column(String(256), nullable=False, unique=True)
    blocklists = relationship('BlockList', secondary=blocklist_address_association, back_populates='addresses')
    virustotal = relationship('Virustotal', backref='Address', uselist=False)
    ipinfo = relationship('Ipinfo', backref='Address', uselist=False)
    abuseipdb = relationship('Abuseipdb', backref='Address', uselist=False)
    kaspersky = relationship('Kaspersky', backref='Address', uselist=False)
    vriminalip = relationship('CriminalIP', backref='Address', uselist=False)
    alienvault = relationship('Alienvault', backref='Address', uselist=False)
    ipqualityscore = relationship('Ipqualityscore', backref='Address', uselist=False)

class BlockList(Base):
    __tablename__ = 'blocklist'  # Название таблицы

    id = Column(Integer, primary_key=True)  # Уникальный идентификатор записи
    name = Column(String(255), nullable=False, unique=True)  # Название блокировки
    description = Column(String(255), nullable=True)  # Описание блокировки
    bid = Column(Integer, nullable=True)  # Дополнительный идентификатор (например, для внешних систем)

    user_id_blocker = Column(Integer, ForeignKey('users.id'), nullable=True)
    addresses = relationship('Address', secondary=blocklist_address_association, back_populates='blocklists')
    rules = relationship('Rule', backref='blocklist')

class SecurityHost(Base):
    __tablename__ = 'security_host'  # Название таблицы

    id = Column(Integer, primary_key=True)  # Уникальный идентификатор записи
    rules = relationship('Rule', backref='security_host', cascade='all, delete-orphan')

class Rule(Base):
    __tablename__ = 'rule'  # Название таблицы

    id = Column(Integer, primary_key=True)  # Уникальный идентификатор записи
    name = Column(String(255), nullable=False, unique=True)  # Название правила
    security_host_id = Column(Integer, ForeignKey('security_host.id'))
    blocklist_id = Column(Integer, ForeignKey('blocklist.id'), nullable=False)
    commit = Column(Boolean, default=False)

class Virustotal(Base):
    __tablename__ = 'virustotal'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    verdict = Column(String(32), nullable=True)
    network = Column(String(20), nullable=True)
    owner = Column(String(255), nullable=True)
    country = Column(String(24), nullable=True)
    rep_score = Column(Float, nullable=True)
    votes = Column(JSON, nullable=True)
    stats = Column(JSON, nullable=True)

class Ipinfo(Base):
    __tablename__ = 'ipinfo'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    country = Column(String(24), nullable=True)
    region = Column(String(255), nullable=True)
    city = Column(String(255), nullable=True)
    org = Column(String(255), nullable=True)
    loc = Column(String(255), nullable=True)

class Abuseipdb(Base):
    __tablename__ = 'abuseipdb'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    is_public = Column(Boolean, default=True)
    ip_version = Column(Integer, nullable=False)
    is_whitelisted = Column(Boolean, nullable=True)
    abuse_confidence_score = Column(Integer, nullable=True)
    country = Column(String(24), nullable=True)
    usage_type = Column(String(255), nullable=True)
    isp = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    total_reports = Column(Integer, nullable=True)
    num_distinct_users = Column(Integer, nullable=True)
    verdict = Column(String(32), nullable=True)

class Kaspersky(Base):
    __tablename__ = 'kaspersky'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    status = Column(String(32), nullable=True)
    country = Column(String(24), nullable=True)
    net_name = Column(String(255), nullable=True)
    verdict = Column(String(32), nullable=True)

class CriminalIP(Base):
    __tablename__ = 'criminalip'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    verdict = Column(String(32), nullable=True)
    open_ports = Column(JSON, nullable=True)
    hostname = Column(String(255), nullable=True)
    country = Column(String(24), nullable=True)

class Alienvault(Base):
    __tablename__ = 'alienvault'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    country = Column(String(24), nullable=True)
    asn = Column(String(255), nullable=True)
    verdict = Column(String(32), nullable=True)

class Ipqualityscore(Base):
    __tablename__ = 'ipqualityscore'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=False)
    country = Column(String(24), nullable=True)
    host = Column(String(255), nullable=True)
    isp = Column(String(255), nullable=True)
    verdict = Column(String(32), nullable=True)
    fraud_score = Column(Integer, nullable=True)
    proxy = Column(Boolean, nullable=True)
    vpn = Column(Boolean, nullable=True)
    tor = Column(Boolean, nullable=True)
    active_vpn = Column(Boolean, nullable=True)
    active_tor = Column(Boolean, nullable=True)
    recent_abuse = Column(Boolean, nullable=True)
    bot_status = Column(Boolean, nullable=True)
