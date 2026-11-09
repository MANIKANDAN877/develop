import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .db import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    session_tokens = relationship("SessionToken", back_populates="user", cascade="all, delete-orphan")


class SessionToken(Base):
    __tablename__ = "session_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    user = relationship("User", back_populates="session_tokens")


class ManualRecord(Base):
    __tablename__ = "manual_records"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    record_reference = Column(String, unique=True, nullable=False)
    description = Column(Text, nullable=True)
    amount = Column(Float, nullable=True)
    currency = Column(String, nullable=True)
    is_api_record = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PayPalTransactionRecord(Base):
    __tablename__ = "paypal_transactions"

    id = Column(Integer, primary_key=True, index=True)
    paypal_transaction_id = Column(String, unique=True, nullable=False, index=True)
    parent_transaction_id = Column(String, nullable=True)
    order_id = Column(String, nullable=True)
    resource_type = Column(String, nullable=True)
    transaction_type = Column(String, nullable=True)
    payer_name = Column(String, nullable=True)
    payer_email = Column(String, nullable=True)
    amount = Column(String, nullable=True)
    currency = Column(String, nullable=True)
    transaction_status = Column(String, nullable=True)
    payment_status = Column(String, nullable=True)
    payment_mode = Column(String, nullable=True)
    environment = Column(String, nullable=False, default="sandbox")
    source_reference = Column(String, nullable=False)
    invoice_id = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=True)
    captured_at = Column(DateTime(timezone=True), nullable=True)
    imported_at = Column(DateTime(timezone=True), server_default=func.now())
    payload = Column(JSON, nullable=True)
    permissions_error = Column(Text, nullable=True)


class PayPalWebhookEvent(Base):
    __tablename__ = "paypal_webhook_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    resource_id = Column(String, nullable=True, index=True)
    amount = Column(String, nullable=True)
    currency = Column(String, nullable=True)
    status = Column(String, nullable=False, default="received")
    summary = Column(Text, nullable=True)
    verified = Column(Boolean, default=False)
    source = Column(String, nullable=False, default="paypal-webhook")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    verified_at = Column(DateTime(timezone=True), nullable=True)
    raw_payload = Column(JSON, nullable=True)


class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id = Column(Integer, primary_key=True, index=True)
    paypal_transaction_id = Column(String, nullable=False, index=True)
    alert_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=True, default=0)
    message = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    source_reference = Column(String, nullable=True)
    status = Column(String, nullable=False, default="review")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
