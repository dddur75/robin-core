"""Single-attempt Cloudflare R2 adapter for the Chronos effect executor."""

from __future__ import annotations

import importlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from robin.prospective_observatory.chronos_control_plane import (
    ConditionalPutOutcome,
    ConditionalPutResult,
    ObservedObject,
)

_DEFINITE_REJECTION_STATUSES = frozenset({401, 403, 404, 405, 411, 413, 414, 415, 417, 422})


class ChronosR2Error(RuntimeError):
    """Fail-closed adapter or response error."""


@dataclass(frozen=True, slots=True)
class LatestProjection:
    """Exact mutable projection read with the ETag needed for CAS."""

    data: bytes
    metadata: Mapping[str, str]
    etag: str


class S3ConditionalClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise ChronosR2Error(f"CHRONOS_MISSING_SECRET:{name}")
    return value


def create_single_attempt_r2_client(
    environment: Mapping[str, str],
) -> tuple[S3ConditionalClient, str]:
    """Construct R2 with SDK retries disabled; never log credentials."""

    account = _required(environment, "R2_ACCOUNT_ID")
    access_key = _required(environment, "R2_ACCESS_KEY_ID")
    secret_key = _required(environment, "R2_SECRET_ACCESS_KEY")
    bucket = _required(environment, "R2_BUCKET_NAME")
    boto3 = importlib.import_module("boto3")
    client: Any = boto3.client(
        "s3",
        endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(
            retries={"total_max_attempts": 1, "mode": "standard"},
        ),
    )
    return cast(S3ConditionalClient, client), bucket


def _error_code(error: ClientError) -> str:
    details = error.response.get("Error", {})
    if not isinstance(details, Mapping):
        return "UNKNOWN"
    return str(details.get("Code", "UNKNOWN"))


def _http_status(error: ClientError) -> int | None:
    metadata = error.response.get("ResponseMetadata", {})
    if not isinstance(metadata, Mapping):
        return None
    status = metadata.get("HTTPStatusCode")
    return status if isinstance(status, int) else None


def _request_id(response: Mapping[str, object]) -> str | None:
    metadata = response.get("ResponseMetadata", {})
    if not isinstance(metadata, Mapping):
        return None
    request_id = metadata.get("RequestId")
    return request_id if isinstance(request_id, str) else None


def _conditional_failure(error: ClientError) -> ConditionalPutResult:
    code = _error_code(error)
    status = _http_status(error)
    if status is not None:
        if status == 409:
            outcome = ConditionalPutOutcome.CONFLICT
        elif status == 412:
            outcome = ConditionalPutOutcome.PRECONDITION_FAILED
        elif status in _DEFINITE_REJECTION_STATUSES:
            outcome = ConditionalPutOutcome.DEFINITE_FAILURE
        else:
            # RequestTimeout is an S3 HTTP 400, while 408, 425, 429 and
            # unknown 4xx responses are likewise not proof of rejection.
            outcome = ConditionalPutOutcome.AMBIGUOUS
    elif code in {"409", "ConditionalRequestConflict"}:
        outcome = ConditionalPutOutcome.CONFLICT
    elif code in {"412", "PreconditionFailed"}:
        outcome = ConditionalPutOutcome.PRECONDITION_FAILED
    else:
        outcome = ConditionalPutOutcome.AMBIGUOUS
    return ConditionalPutResult(
        outcome=outcome,
        transport_attempts=1,
        automatic_retry_possible=False,
        request_id=_request_id(error.response),
    )


class ChronosR2ConditionalStore:
    """No LIST/HEAD/DELETE surface and exactly one SDK write attempt."""

    def __init__(self, client: S3ConditionalClient, bucket: str) -> None:
        if not bucket or bucket.strip() != bucket:
            raise ChronosR2Error("CHRONOS_R2_BUCKET_INVALID")
        self._client = client
        self._bucket = bucket

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
    ) -> ChronosR2ConditionalStore:
        client, bucket = create_single_attempt_r2_client(environment)
        return cls(client, bucket)

    def put_if_absent(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult:
        # This durable permit is committed before boto can send the first byte.
        on_dispatch()
        try:
            response = self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=data,
                IfNoneMatch="*",
                Metadata=dict(metadata),
            )
        except ClientError as error:
            return _conditional_failure(error)
        except Exception:
            return ConditionalPutResult(
                outcome=ConditionalPutOutcome.AMBIGUOUS,
                transport_attempts=1,
                automatic_retry_possible=False,
            )
        etag = response.get("ETag")
        return ConditionalPutResult(
            outcome=ConditionalPutOutcome.CREATED,
            transport_attempts=1,
            automatic_retry_possible=False,
            request_id=_request_id(response),
            etag=etag if isinstance(etag, str) else None,
        )

    def get_latest_projection(self, key: str) -> LatestProjection | None:
        """Read a mutable projection without exposing dependency diagnostics."""

        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except ClientError as error:
            if _error_code(error) in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise ChronosR2Error("CHRONOS_R2_LATEST_READ_FAILED") from None
        except Exception:
            raise ChronosR2Error("CHRONOS_R2_LATEST_READ_FAILED") from None
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise ChronosR2Error("CHRONOS_R2_LATEST_BODY_INVALID")
        try:
            data = body.read()
        except Exception:
            raise ChronosR2Error("CHRONOS_R2_LATEST_BODY_INVALID") from None
        if not isinstance(data, bytes):
            raise ChronosR2Error("CHRONOS_R2_LATEST_BODY_INVALID")
        raw_metadata = response.get("Metadata", {})
        if not isinstance(raw_metadata, Mapping):
            raise ChronosR2Error("CHRONOS_R2_LATEST_METADATA_INVALID")
        metadata = {
            str(name): str(value)
            for name, value in raw_metadata.items()
            if isinstance(name, str) and isinstance(value, str)
        }
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ChronosR2Error("CHRONOS_R2_LATEST_ETAG_INVALID")
        return LatestProjection(data=data, metadata=metadata, etag=etag)

    def put_latest_projection(
        self,
        key: str,
        data: bytes,
        *,
        metadata: Mapping[str, str],
        expected_etag: str | None,
        on_dispatch: Callable[[], None],
    ) -> ConditionalPutResult:
        """Advance a mutable projection once, then require exact readback."""

        conditions = {"IfNoneMatch": "*"} if expected_etag is None else {"IfMatch": expected_etag}
        on_dispatch()
        try:
            response = self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=data,
                Metadata=dict(metadata),
                **conditions,
            )
        except ClientError as error:
            return _conditional_failure(error)
        except Exception:
            raise ChronosR2Error("CHRONOS_R2_LATEST_WRITE_FAILED") from None
        etag = response.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ChronosR2Error("CHRONOS_R2_LATEST_ETAG_INVALID")
        observed = self.get_latest_projection(key)
        if (
            observed is None
            or observed.data != data
            or dict(observed.metadata) != dict(metadata)
            or observed.etag != etag
        ):
            raise ChronosR2Error("CHRONOS_R2_LATEST_READBACK_MISMATCH")
        return ConditionalPutResult(
            outcome=ConditionalPutOutcome.CREATED,
            transport_attempts=1,
            automatic_retry_possible=False,
            request_id=_request_id(response),
            etag=etag,
        )

    def get_object(self, key: str) -> ObservedObject | None:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except ClientError as error:
            if _error_code(error) in {"404", "NoSuchKey", "NotFound"}:
                return None
            raise
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise ChronosR2Error("CHRONOS_R2_BODY_INVALID")
        data = body.read()
        if not isinstance(data, bytes):
            raise ChronosR2Error("CHRONOS_R2_BODY_INVALID")
        raw_metadata = response.get("Metadata", {})
        if not isinstance(raw_metadata, Mapping):
            raise ChronosR2Error("CHRONOS_R2_METADATA_INVALID")
        metadata = {
            str(name): str(value)
            for name, value in raw_metadata.items()
            if isinstance(name, str) and isinstance(value, str)
        }
        return ObservedObject(data=data, metadata=metadata)


__all__ = [
    "ChronosR2ConditionalStore",
    "ChronosR2Error",
    "LatestProjection",
    "S3ConditionalClient",
    "create_single_attempt_r2_client",
]
