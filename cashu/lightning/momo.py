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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
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
    Proxies requests to the MoMo API wrapper (octoba).
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
        
        self.api_base_url = os.environ.get("MOMO_API_BASE_URL")
        enc_key_b64 = os.environ.get("MOMO_ENCRYPTION_KEY")
        
        if not self.api_base_url or not enc_key_b64:
            raise ValueError("MOMO_API_BASE_URL and MOMO_ENCRYPTION_KEY environment variables must be set in your .env file.")
            
        self.encryption_key = base64.b64decode(enc_key_b64)
        
        self.client = httpx.AsyncClient(
            verify=not settings.debug,
            base_url=self.api_base_url,
            timeout=30.0,
        )

    def _encrypt_payload(self, data: dict) -> dict:
        iv = os.urandom(16)
        data_str = json.dumps(data)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data_str.encode("utf-8")) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        h = HMAC(self.encryption_key, hashes.SHA256(), backend=default_backend())
        h.update(data_str.encode("utf-8"))
        hmac_val = h.finalize()

        return {
            "encrypted": base64.b64encode(encrypted).decode("utf-8"),
            "iv": iv.hex(),
            "hmac": hmac_val.hex(),
            "timestamp": int(time.time() * 1000),
        }

    def _create_secure_request(self, request_body: dict) -> tuple[dict, dict]:
        nonce = os.urandom(8).hex()
        payload = {
            "transaction": request_body,
            "security": {
                "nonce": nonce,
                "timestamp": int(time.time() * 1000),
            },
        }
        
        request_data = self._encrypt_payload(payload)
        headers = {
            "Content-Type": "application/json",
            "X-Encrypted": "true",
            "X-Request-ID": nonce,
        }
        return request_data, headers

    def _generate_fake_bolt11(self, checking_id: str, amount: int, memo: str) -> str:
        tags = Tags()
        payment_hash = hashlib.sha256(checking_id.encode()).hexdigest()
        tags.add(TagChar.payment_hash, payment_hash)
        tags.add(TagChar.payment_secret, urandom(32).hex())
        tags.add(TagChar.description, memo)
        tags.add(TagChar.expire_time, 3600)

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
                error_message="Memo must be provided in format 'momo:<phone>'"
            )

        phone_number = memo.split(":")[1]
        tx_id = str(uuid.uuid4())
        external_id = f"payment_{int(time.time() * 1000)}"

        request_body = {
            "txId": tx_id,
            "amount": str(amount.amount),
            "btcamount": "0",
            "ecashamount": str(amount.amount),
            "currency": "RWF",
            "externalId": external_id,
            "phone": phone_number,
            "payerMessage": "Bridge Payment",
            "payeeNote": f"Order {external_id}",
        }

        request_data, headers = self._create_secure_request(request_body)

        try:
            r = await self.client.post(
                url="/payment/request/octoba",
                json=request_data,
                headers=headers,
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

        ref_id = resp.get("data", {}).get("reference_id", tx_id)
        payment_req = self._generate_fake_bolt11(ref_id, amount.amount, memo)

        return InvoiceResponse(
            ok=True,
            checking_id=tx_id,
            payment_request=payment_req,
        )

    async def pay_invoice(
        self, quote: MeltQuote, fee_limit: int
    ) -> PaymentResponse:
        request_str = quote.request
        phone_number = None

        if request_str.startswith("momo:"):
            phone_number = request_str.split(":")[1]
        else:
            try:
                invoice_obj = decode(request_str)
                for tag in invoice_obj.tags:
                    if tag.char == TagChar.description and str(tag.data).startswith("momo:"):
                        phone_number = str(tag.data).split(":")[1]
            except Exception:
                pass

        if not phone_number:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="Could not extract phone number. Expected 'momo:<phone>' or BOLT11 with description.",
            )

        tx_id = str(uuid.uuid4())
        external_id = f"payout_{int(time.time() * 1000)}"

        request_body = {
            "txId": tx_id,
            "amount": str(quote.amount),
            "btcamount": "0",
            "currency": "RWF",
            "externalId": external_id,
            "phone": phone_number,
            "payerMessage": "RWF Bridge Payout",
            "payeeNote": f"Payout {external_id}",
        }

        request_data, headers = self._create_secure_request(request_body)

        try:
            r = await self.client.post(
                url="/payment/payout/octoba",
                json=request_data,
                headers=headers,
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

        return PaymentResponse(
            result=PaymentResult.SETTLED,
            checking_id=tx_id,
            fee=Amount(unit=self.unit, amount=0),
            preimage="0" * 64,
        )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(f"/payment/request/octoba/status/{checking_id}")
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

        status_str = resp["data"].get("status", "").upper()
        result = INVOICE_RESULT_MAP.get(status_str, PaymentResult.PENDING)

        if result == PaymentResult.FAILED:
            return PaymentStatus(result=result, error_message=f"Status: {status_str}")

        return PaymentStatus(result=result)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        try:
            r = await self.client.get(f"/payment/payout/octoba/status/{checking_id}")
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

        status_str = resp["data"].get("status", "").upper()
        result = PAYMENT_RESULT_MAP.get(status_str, PaymentResult.PENDING)

        if result == PaymentResult.FAILED:
            return PaymentStatus(result=result, error_message=f"Status: {status_str}")

        return PaymentStatus(result=result)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        request_str = melt_quote.request
        amount = 0
        if request_str.startswith("momo:"):
            parts = request_str.split(":")
            if len(parts) >= 3:
                try:
                    amount = int(parts[2])
                except ValueError:
                    pass
        elif request_str.startswith("ln"):
            try:
                invoice_obj = decode(request_str)
                amount = int(invoice_obj.amount_msat / 1000)
            except Exception:
                pass

        return PaymentQuoteResponse(
            checking_id=str(uuid.uuid4()),
            fee=Amount(unit=self.unit, amount=0),
            amount=Amount(unit=self.unit, amount=amount),
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            await asyncio.sleep(100)
            yield ""
