import datetime
import enum
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
from sqlalchemy import Enum
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.types import JSON
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy import Index

from config.config import CRYPT
from cryptography.fernet import Fernet


# Создаем объект шифрования Fernet
password_cipher = Fernet(CRYPT.PASSWORD_ENCRYPTION_KEY)
login_cipher = Fernet(CRYPT.LOGIN_ENCRYPTION_KEY)
api_token_cipher = Fernet(CRYPT.API_TOKEN_ENCRYPTION_KEY)

class Base(DeclarativeBase):
    created = Column(DateTime, default=datetime.datetime.now)
    updated = Column(DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)

blocklist_address_association = Table(
    'blocklist_address',
    Base.metadata,
    Column('blocklist_id', Integer, ForeignKey('blocklist.id'), primary_key=True),
    Column('address_id', Integer, ForeignKey('address.id'), primary_key=True)
)

group_security_host_association = Table(
    'group_security_host_association',
    Base.metadata,
    Column('group_id', Integer, ForeignKey('group_security_host.id'), primary_key=True),
    Column('security_host_id', Integer, ForeignKey('security_host.id'), primary_key=True)
)

rule_blocklist_association = Table(
    'rule_blocklist',
    Base.metadata,
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True),
    Column('blocklist_id', Integer, ForeignKey('blocklist.id'), primary_key=True)
)

rule_securityhost_association = Table(
    'rule_securityhost',
    Base.metadata,
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True),
    Column('security_host_id', Integer, ForeignKey('security_host.id'), primary_key=True)
)

rule_groupsecurityhost_association = Table(
    'rule_groupsecurityhost',
    Base.metadata,
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True),
    Column('group_id', Integer, ForeignKey('group_security_host.id'), primary_key=True)
)

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    first_name = Column(String(32), nullable=True)
    last_name = Column(String(32), nullable=True)
    username = Column(String(32), nullable=False, unique=True)
    superadmin_rights = Column(Boolean, nullable=False)
    admin_rights = Column(Boolean, nullable=False)

    history_command = relationship('History', backref='user')
    blcok_ip = relationship('BlockList', backref='user')

    __table_args__ = (
        Index('idx_id_admin_superadmin', 'id', 'admin_rights', 'superadmin_rights'),
    )

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
    __tablename__ = 'blocklist'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(String(255), nullable=True)

    user_id_blocker = Column(Integer, ForeignKey('users.id'), nullable=True)
    addresses = relationship('Address', secondary=blocklist_address_association, back_populates='blocklists')
    rules = relationship('Rule', secondary=rule_blocklist_association, back_populates='blocklists')

    def __repr__(self):
        return f"<BlockList(id={self.id}, name={self.name})>"

class TypeSechosts(enum.Enum):
    VIPNET = "vipnet"
    USERGATE = "utm"
    CONTINENT = "cont"
    NONE = "none"

class SecurityHost(Base):
    __tablename__ = 'security_host'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(String(255), nullable=True)
    address = Column(String(255), nullable=False, unique=True)
    type = Column(Enum(TypeSechosts), default=TypeSechosts.NONE)
    _api_token = Column(String(255), nullable=True)  # Зашифрованный API токен
    _login = Column(String(255), nullable=False)  # Зашифрованный логин
    _password = Column(String(255), nullable=False)  # Зашифрованный пароль

    groups = relationship('GroupSecurityHost', secondary=group_security_host_association, back_populates='security_hosts')
    rules = relationship('Rule', secondary=rule_securityhost_association, back_populates='security_hosts')

    # Методы для шифрования и дешифрования пароля
    @property
    def password(self):
        raise AttributeError("Пароль недоступен для чтения напрямую")

    @password.setter
    def password(self, plain_password):
        encrypted_password = password_cipher.encrypt(plain_password.encode('utf-8'))
        self._password = encrypted_password.decode('utf-8')

    def verify_password(self, plain_password):
        return password_cipher.decrypt(self._password.encode('utf-8')) == plain_password.encode('utf-8')

    # Методы для шифрования и дешифрования логина
    @property
    def login(self):
        raise AttributeError("Логин недоступен для чтения напрямую")

    @login.setter
    def login(self, plain_login):
        encrypted_login = login_cipher.encrypt(plain_login.encode('utf-8'))
        self._login = encrypted_login.decode('utf-8')

    def get_login(self):
        return login_cipher.decrypt(self._login.encode('utf-8')).decode('utf-8')

    # Методы для шифрования и дешифрования API токена
    @property
    def api_token(self):
        raise AttributeError("API токен недоступен для чтения напрямую")

    @api_token.setter
    def api_token(self, plain_api_token):
        encrypted_api_token = api_token_cipher.encrypt(plain_api_token.encode('utf-8'))
        self._api_token = encrypted_api_token.decode('utf-8')

    def get_api_token(self):
        return api_token_cipher.decrypt(self._api_token.encode('utf-8')).decode('utf-8')

    # Метод для получения всех данных для SSH
    def get_ssh_credentials(self):
        return {
            "address": self.address,
            "username": self.get_login(),
            "password": password_cipher.decrypt(self._password.encode('utf-8')).decode('utf-8')
        }

    def __repr__(self):
        return f"<SecurityHost(id={self.id}, name={self.name}, address={self.address})>"

class GroupSecurityHost(Base):
    __tablename__ = 'group_security_host'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(String(255), nullable=True)

    security_hosts = relationship('SecurityHost', secondary=group_security_host_association, back_populates='groups')
    rules = relationship('Rule', secondary=rule_groupsecurityhost_association, back_populates='group_security_hosts')

    def __repr__(self):
        return f"<GroupSecurityHost(id={self.id}, name={self.name})>"

class RuleFullStatus(enum.Enum):
    BLOCK = "block"
    FULL = "full"
    EMPTY = "empty"

class Rule(Base):
    __tablename__ = 'rule'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    commit = Column(Boolean, default=False)

    # Поле action теперь Boolean
    action = Column(Boolean, nullable=False, default=False)  # False = drop, True = pass

    # Списковые поля
    source_ip = Column(ARRAY(String(32)), nullable=True)
    destination_ip = Column(ARRAY(String(32)), nullable=True)
    source_port = Column(ARRAY(Integer), nullable=True)
    destination_port = Column(ARRAY(Integer), nullable=True)
    protocol = Column(ARRAY(String(32)), nullable=True)

    # Поле для статуса заполненности
    full = Column(Enum(RuleFullStatus), default=RuleFullStatus.EMPTY)
    status = Column(Boolean, default=False)

    # Связи с блок-листами, хостами безопасности и группами хостов безопасности
    blocklists = relationship('BlockList', secondary=rule_blocklist_association, back_populates='rules')
    security_hosts = relationship('SecurityHost', secondary=rule_securityhost_association, back_populates='rules')
    group_security_hosts = relationship('GroupSecurityHost', secondary=rule_groupsecurityhost_association, back_populates='rules')

    def __repr__(self):
        return f"<Rule(id={self.id}, name={self.name}, full={self.full}, action={'pass' if self.action else 'drop'})>"

    def update_full_status(self):
        """
        Обновляет значение поля `full` в зависимости от заполненности данных правила.
        """
        # Для правила типа block
        if (
            self.name
            and self.commit is not None
            and self.blocklists
            and (self.security_hosts or self.group_security_hosts)
        ):
            self.full = RuleFullStatus.BLOCK

        # Для правила типа full
        elif (
            self.name
            and self.commit is not None
            and self.source_ip
            and self.destination_ip
            and self.source_port
            and self.destination_port
            and self.protocol
        ):
            self.full = RuleFullStatus.FULL

        # Если не заполнено ни для блокирующего, ни для общего правила
        else:
            self.full = RuleFullStatus.EMPTY

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
