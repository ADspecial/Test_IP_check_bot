from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    BigInteger,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(32), nullable=True)
    last_name = Column(String(32), nullable=True)
    username = Column(String(32), nullable=False)
    history_command = relationship('History', backref='user')

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
    ipv4 = Column(INET, nullable=True)
    ipv6 = Column(INET, nullable=True)
    dns_name = Column(String(256), nullable=True)
    block = Column(Boolean)
    user_id_blocker = Column(Integer, ForeignKey('users.id'), nullable=True)

class Vt_ip(Base):
    __tablename__ = 'vt_ip'

    id = Column(Integer, primary_key=True)
    address = Column(Integer, ForeignKey('address.id'),  nullable=True)
    verdict = Column(Boolean, nullable=False)
    network = Column(String(20), nullable=True)
    owner = Column(String(255), nullable=True)
    country = Column(String(24), nullable=True)
    vote_malicious = Column(Integer, nullable=True)
    vote_harmless = Column(Integer, nullable=True)
    stat_malicious = Column(Integer, nullable=True)
    stat_suspicious = Column(Integer, nullable=True)
    stat_harmless = Column(Integer, nullable=True)
    stat_undetected = Column(Integer, nullable=True)
    last_analysis_date = Column(DateTime, nullable=True)
