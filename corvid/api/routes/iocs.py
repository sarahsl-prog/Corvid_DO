"""IOC (Indicator of Compromise) CRUD endpoints."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from corvid.api.models.ioc import IOCCreate, IOCListResponse, IOCResponse
from corvid.db.models import IOC
from corvid.db.session import get_db

router = APIRouter(prefix="/iocs", tags=["IOCs"])


@router.post("/", response_model=IOCResponse, status_code=201)
async def create_ioc(ioc_in: IOCCreate, db: AsyncSession = Depends(get_db)) -> IOC:
    """Create a new IOC or update an existing one (dedup by type+value).

    If an IOC with the same type and value already exists:
    - Updates last_seen timestamp
    - Merges tags from the new submission
    """
    logger.info("Creating IOC: type={}, value={}", ioc_in.type.value, ioc_in.value)

    # Check for existing IOC with same type+value
    stmt = select(IOC).where(IOC.type == ioc_in.type.value, IOC.value == ioc_in.value)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        logger.info("IOC already exists (id={}), updating last_seen and merging tags", existing.id)
        existing.last_seen = func.now()
        existing.tags = list(set(existing.tags or []) | set(ioc_in.tags))
        await db.commit()
        await db.refresh(existing)
        return existing

    ioc = IOC(type=ioc_in.type.value, value=ioc_in.value, tags=ioc_in.tags)
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    logger.info("IOC created: id={}", ioc.id)
    return ioc


@router.get("/", response_model=IOCListResponse)
async def list_iocs(
    type: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> IOCListResponse:
    """List IOCs with optional type filter and pagination."""
    stmt = select(IOC)
    count_stmt = select(func.count(IOC.id))

    if type:
        stmt = stmt.where(IOC.type == type)
        count_stmt = count_stmt.where(IOC.type == type)

    stmt = stmt.offset(offset).limit(limit).order_by(IOC.created_at.desc())

    result = await db.execute(stmt)
    count_result = await db.execute(count_stmt)

    return IOCListResponse(items=result.scalars().all(), total=count_result.scalar())


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)) -> IOC:
    """Retrieve a single IOC by ID."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: UUID, db: AsyncSession = Depends(get_db)) -> None:
    """Delete an IOC by ID."""
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    await db.delete(ioc)
    await db.commit()
    logger.info("IOC deleted: id={}", ioc_id)
