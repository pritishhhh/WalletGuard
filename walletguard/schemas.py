from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Credentials(StrictModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-z][a-z0-9_]+$", strict=True)
    password: SecretStr = Field(min_length=12, max_length=128)


class WalletCreate(StrictModel):
    label: str = Field(default="My wallet", min_length=1, max_length=60, strict=True, pattern=r"^[\w .-]+$")
    currency: Literal["INR"] = "INR"


Amount = Annotated[int, Field(strict=True, gt=0, le=1_000_000_000)]


class TransferCreate(StrictModel):
    source_id: UUID
    destination_id: UUID
    amount_minor: Amount


class FundingCreate(StrictModel):
    amount_minor: Amount
