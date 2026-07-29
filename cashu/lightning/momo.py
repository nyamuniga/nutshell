import asyncio
import base64
import hashlib
import json
import os
import time
import uuid
from datetime import datetime
from os import urandom
from typing import AsyncGenerator, Optional

import httpx
from bolt11 import (
    Bolt11,
    MilliSatoshi,
    TagChar,
    Tags,
    decode,
    encode,
)
from loguru import logger

from ..core.base import Amount, MeltQuote, Unit
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)

INVOICE_RESULT_MAP = {
    "SUCCESSFUL": PaymentResult.SETTLED,
    "SUCCESS": PaymentResult.SETTLED,
    "COMPLETED": PaymentResult.SETTLED,
    "APPROVED": PaymentResult.SETTLED,
    "FAILED": PaymentResult.FAILED,
    "REJECTED": PaymentResult.FAILED,
    "PENDING": PaymentResult.PENDING,
}

PAYMENT_RESULT_MAP = {
    "SUCCESSFUL": PaymentResult.SETTLED,
    "SUCCESS": PaymentResult.SETTLED,
    "COMPLETED": PaymentResult.SETTLED,
    "APPROVED": PaymentResult.SETTLED,
    "FAILED": PaymentResult.FAILED,
    "REJECTED": PaymentResult.FAILED,
    "PENDING": PaymentResult.PENDING,
}


class MomoWallet(LightningBackend):
    """
    Mobile Money (MoMo) Wallet backend.
    Proxies requests to PataLink Backend.
    """

    unit: Unit
    supported_units = {Unit.rwf}
    supports_incoming_payment_stream: bool = False
    supports_description: bool = True

    secret: str = "FAKEWALLET SECRET"
    privkey: str = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        b"FakeWallet",
        2048,
        32,
    ).hex()

    def __init__(self, unit: Unit = Unit.rwf, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit
        
        self.api_base_url = "http://localhost:3000/api/wallet/"
        
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            base_url=self.api_base_url,
            timeout=30.0,
        )

        # In-memory store to map checking_id to apiKey for status polling
        # In a production environment, this could be backed by a DB or Redis.
        self.api_keys = {}

    def _generate_fake_bolt11(self, payment_hash: str, amount: int, memo: str = "") -> str:
        h = hashlib.sha256(payment_hash.encode()).hexdigest()
        tags = Tags()
        tags.add(TagChar.payment_hash, h)
        tags.add(TagChar.description, memo)
        # bolt11 library requires a payment_secret (32 bytes hex). We use "01"*32 
        # instead of "00"*32 because bitstring evaluates 256 zeros to False in Python 3.
        tags.add(TagChar.payment_secret, "01" * 32)
        b11 = Bolt11(
            currency="bc",
            amount_msat=MilliSatoshi(amount * 1000),
            date=int(datetime.now().timestamp()),
            tags=tags,
        )
        return encode(b11, self.privkey)

    async def status(self) -> StatusResponse:
        return StatusResponse(
            error_message=None,
            balance=Amount(self.unit, 1000000),  # placeholder balance
        )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        expiry: Optional[int] = None,
        payment_secret: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)

        if not memo or not memo.startswith("momo:"):
            return InvoiceResponse(
                ok=False, 
                error_message="Memo must be provided in format 'momo:<phone>:<apiKey>'"
            )

        parts = memo.split(":")
        phone_number = parts[1] if len(parts) > 1 else ""
        api_key = parts[2] if len(parts) > 2 else ""
        charge_amount = int(parts[3]) if len(parts) > 3 else int(amount.amount * 1.05)
        
        logger.error(f"DEBUG MOMO: memo={memo} phone={phone_number} api_key={api_key} charge_amount={charge_amount}")

        if not api_key:
             return InvoiceResponse(ok=False, error_message="API Key is missing in memo")

        request_body = {
            "amount": charge_amount,
            "phone": phone_number,
            "network": "MTN"
        }

        try:
            r = await self.client.post(
                url="internal-momo",
                json=request_body,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"MoMo API error: {e}")
            return InvoiceResponse(ok=False, error_message=str(e))

        resp = r.json()
        if resp.get("status") != "success":
            return InvoiceResponse(
                ok=False, 
                error_message=resp.get("message", "API failed")
            )

        ref_id = resp.get("data", {}).get("reference_id")
        if not ref_id:
             return InvoiceResponse(ok=False, error_message="No reference_id returned")

        # Save api_key in memory so we can use it during status polling
        self.api_keys[ref_id] = api_key

        payment_req = self._generate_fake_bolt11(ref_id, amount.amount, memo)

        return InvoiceResponse(
            ok=True,
            checking_id=ref_id,
            payment_request=payment_req,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit: int
    ) -> PaymentResponse:
        request_str = quote.request
        phone_number = None
        api_key = None

        if request_str.startswith("momo:"):
            parts = request_str.split(":")
            phone_number = parts[1]
            if len(parts) > 2:
                api_key = parts[2]
        else:
            try:
                invoice_obj = decode(request_str)
                for tag in invoice_obj.tags:
                    if tag.char == TagChar.description and str(tag.data).startswith("momo:"):
                        parts = str(tag.data).split(":")
                        phone_number = parts[1]
                        if len(parts) > 2:
                            api_key = parts[2]
            except Exception:
                pass

        if not phone_number or not api_key:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="Could not extract phone number and API key. Expected 'momo:<phone>:<apiKey>'.",
            )

        request_body = {
            "amount": quote.amount,
            "phone": phone_number,
            "network": "MTN"
        }

        try:
            r = await self.client.post(
                url="withdraw",
                json=request_body,
                headers={"Authorization": f"Bearer {api_key}"},
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"MoMo API error: {e}")
            return PaymentResponse(
                result=PaymentResult.UNKNOWN,
                error_message=str(e),
            )

        resp = r.json()
        if resp.get("status") != "success":
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message=resp.get("message", "Payout API failed"),
            )

        ref_id = resp.get("data", {}).get("reference_id", str(uuid.uuid4()))

        # Save api_key in memory so we can use it during status polling
        self.api_keys[ref_id] = api_key

        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=ref_id,
            fee=Amount(unit=self.unit, amount=0),
            preimage="0" * 64,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            api_key = self.api_keys.get(checking_id, "pt_test_fallback")
            r = await self.client.get(
                f"pay/{checking_id}",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"MoMo API error: {e}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

        resp = r.json()
        if resp.get("status") != "success" or "data" not in resp:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, 
                error_message=resp.get("message", "Invalid response")
            )

        status_str = resp["data"].get("status", "PENDING")
        return PaymentStatus(result=INVOICE_RESULT_MAP.get(status_str, PaymentResult.UNKNOWN))

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            api_key = self.api_keys.get(checking_id, "pt_test_fallback")
            r = await self.client.get(
                f"withdraw/{checking_id}",
                headers={"Authorization": f"Bearer {api_key}"}
            )
            r.raise_for_status()
        except Exception as e:
            logger.error(f"MoMo API error: {e}")
            return PaymentStatus(result=PaymentResult.UNKNOWN, error_message=str(e))

        resp = r.json()
        if resp.get("status") != "success" or "data" not in resp:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, 
                error_message=resp.get("message", "Invalid response")
            )

        status_str = resp["data"].get("status", "PENDING")
        return PaymentStatus(result=PAYMENT_RESULT_MAP.get(status_str, PaymentResult.UNKNOWN))

    async def get_payment_quote(
        self,
        melt_quote: PostMeltQuoteRequest,
    ) -> PaymentQuoteResponse:
        request_str = melt_quote.request
        amount = 0
        if request_str.startswith("momo:"):
            parts = request_str.split(":")
            if len(parts) > 3:
                try:
                    amount = int(parts[3])
                except ValueError:
                    pass

        return PaymentQuoteResponse(
            checking_id=str(uuid.uuid4()),
            amount=Amount(self.unit, amount),
            fee=Amount(self.unit, 0),
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            await asyncio.sleep(1)
            yield ""
