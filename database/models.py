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
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import relationship, DeclarativeBase

class Base(DeclarativeBase):
    created = Column(DateTime, default=datetime.datetime.now)
    updated = Column(DateTime, default=func.current_timestamp(), onupdate=func.current_timestamp())

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(32), nullable=True)
    last_name = Column(String(32), nullable=True)
    username = Column(String(32), nullable=False)
    history_command = relationship('History', backref='user')
    blcok_ip = relationship('Address', backref='user')

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
    ip = Column(String(256), nullable=True)
    block = Column(Boolean, nullable=True)
    user_id_blocker = Column(Integer, ForeignKey('users.id'), nullable=True)
    virustotal = relationship('Vt_ip', backref='Address', uselist=False)
    ipinfo = relationship('Ipi_ip', backref='Address', uselist=False)
    abuseipdb = relationship('Abuseipdb', backref='Address', uselist=False)
    kaspersky = relationship('Kaspersky', backref='Address', uselist=False)

class Vt_ip(Base):
    __tablename__ = 'vt_ip'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
    verdict = Column(Boolean, nullable=False)
    network = Column(String(20), nullable=True)
    owner = Column(String(255), nullable=True)
    country = Column(String(24), nullable=True)
    rep_score = Column(Float, nullable=True)
    vote_malicious = Column(Integer, nullable=True)
    vote_harmless = Column(Integer, nullable=True)
    stat_malicious = Column(Integer, nullable=True)
    stat_suspicious = Column(Integer, nullable=True)
    stat_harmless = Column(Integer, nullable=True)
    stat_undetected = Column(Integer, nullable=True)
    last_analysis_date = Column(DateTime, nullable=True)

class Ipi_ip(Base):
    __tablename__ = 'ipi_ip'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
    country = Column(String(24), nullable=True)
    region = Column(String(255), nullable=True)
    city = Column(String(255), nullable=True)
    org = Column(String(255), nullable=True)
    loc = Column(String(255), nullable=True)

class Abuseipdb(Base):
    __tablename__ = 'abuseipdb'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
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
    #last_reported_at = Column(DateTime, nullable=True)

class Kaspersky(Base):
    __tablename__ = 'kaspersky'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
    status = Column(String(32), nullable=True)
    country = Column(String(24), nullable=True)
    net_name = Column(String(255), nullable=True)
    zone = Column(String(32), nullable=True)
    last_changed_at = Column(DateTime, nullable=True)
