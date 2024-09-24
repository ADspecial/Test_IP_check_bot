from typing import List

from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import DateTime, ForeignKey, String, Text, func

class Base(DeclarativeBase):
    created: Mapped[DateTime] = mapped_column(DateTime, default=func.now())
    updated: Mapped[DateTime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

class User(Base):
    __tablename__ = 'users'

    id:Mapped[str] = mapped_column(String, primary_key=True)
    first_name: Mapped[str] = mapped_column(String, nullable = True)
    last_name: Mapped[str] = mapped_column(String, nullable = True)
    username: Mapped[str] = mapped_column(String, nullable=True)
    history_command: Mapped[List["History"]] = relationship()

class History(Base):
    __tablename__ = 'history'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    chat_id: Mapped[str] = mapped_column(String, nullable = True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    message_id: Mapped[str] = mapped_column(String, nullable = True)
    message: Mapped[str] = mapped_column(Text, nullable = True)


class IP_ADDRESS(Base):
    __tablename__ = 'ip_address'

    id: Mapped[int] = mapped_column(autoincrement=True)
    ip: Mapped[str] = mapped_column(String,primary_key=True)
    vt: Mapped[List["VT_IP"]] = relationship()

class VT_IP(Base):
    __tablename__ = 'vt_ip'

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(ForeignKey("ip_address.ip"))
    verdict: Mapped[str] = mapped_column(String, nullable = False)
    network: Mapped[str] = mapped_column(String, nullable = True)
    owner: Mapped[str] = mapped_column(String, nullable = True)
    country: Mapped[str] = mapped_column(String, nullable = True)
    vote_malicious: Mapped[str] = mapped_column(String, nullable = True)
    vote_harmless: Mapped[str] = mapped_column(String, nullable = True)
    stat_malicious: Mapped[str] = mapped_column(String, nullable = True)
    stat_suspicious: Mapped[str] = mapped_column(String, nullable = True)
    stat_harmless: Mapped[str] = mapped_column(String, nullable = True)
    stat_undetected: Mapped[str] = mapped_column(String, nullable = True)
    last_analysis_date: Mapped[str] = mapped_column(String, nullable = True)
