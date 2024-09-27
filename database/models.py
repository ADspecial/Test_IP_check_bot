import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
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
    updated = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

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

    id = Column(Integer, primary_key=True)
    chat_id = Column(BigInteger, nullable=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    message_id = Column(Integer, nullable=True)
    message = Column(String(4096), nullable=True)

class Address(Base):
    __tablename__ = 'address'

    id = Column(Integer, primary_key=True)
    ip = Column(String(256), nullable=True)
    block = Column(Boolean, nullable=True)
    user_id_blocker = Column(Integer, ForeignKey('users.id'), nullable=True)
    virustotal = relationship('Vt_ip', backref='Address', uselist=False)

class Vt_ip(Base):
    __tablename__ = 'vt_ip'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
    verdict = Column(Boolean, nullable=False)
    network = Column(String(20), nullable=True)
    owner = Column(String(255), nullable=True)
    country = Column(String(24), nullable=True)
    rep_score = Column(Integer, nullable=True)
    vote_malicious = Column(Integer, nullable=True)
    vote_harmless = Column(Integer, nullable=True)
    stat_malicious = Column(Integer, nullable=True)
    stat_suspicious = Column(Integer, nullable=True)
    stat_harmless = Column(Integer, nullable=True)
    stat_undetected = Column(Integer, nullable=True)
    last_analysis_date = Column(DateTime, nullable=True)
