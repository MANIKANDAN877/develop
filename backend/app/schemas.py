from typing import Any, Optional

from pydantic import BaseModel


class TransactionImportRequest(BaseModel):
    start_date: str
    end_date: str


class OrderLookupResponse(BaseModel):
    order_id: str
    status: Optional[str] = None
    payer_name: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    raw: Optional[Any] = None


class CaptureLookupResponse(BaseModel):
    capture_id: str
    status: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    raw: Optional[Any] = None
