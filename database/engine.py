from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from database.models import Base
from config.config import DB


engine = create_async_engine(
    DB.url,
    echo=True,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=1800
)

session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def create_db():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("Database created successfully")
    except Exception as e:
        print(f"Error creating database: {e}")


async def drop_db():
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        print("Database dropped successfully")
    except Exception as e:
        print(f"Error dropping database: {e}")

async def shutdown_db():
    await engine.dispose()
