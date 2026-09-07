"""The Proxmox read-only transport. The only code in ACOP that opens a socket
to a hypervisor.

**There is no method parameter.** :meth:`ProxmoxClient.get_data` is the entire
public surface, and it issues ``GET``. That is how "no write operation is
reachable" is made structural rather than reviewed: a future contributor cannot
POST by passing an argument, because there is no argument to pass, and adding
one is a visible change to this file rather than a call site somewhere else.

**There is no path parameter either.** The caller names a *tool*, and the path
comes from :data:`~acop.tools.adapters.proxmox.endpoints.TOOL_ENDPOINTS`. A
string that is not a key in that mapping cannot become a request.

**Credentials are read here and nowhere else.** The token id and secret come
from :class:`~acop.config.Settings`, are assembled into the ``Authorization``
header inside :meth:`_headers`, and never leave this object. Nothing returns
them, no exception carries them, and the token secret is a ``SecretStr`` so a
``repr`` of the settings object cannot spill it either. Import rule 9 guarantees
no tool input schema could carry one in the other direction.

**Timeouts are a budget, not a per-request setting.** ``proxmox.storage.list``
makes ``1 + N`` requests, and giving each one the full configured timeout would
let the tool run for ``N`` times its declared deadline - at which point the
dispatcher's ``asyncio.wait_for`` cancels it from outside and the invocation is
``TIMED_OUT`` with no indication which call was slow. Instead the adapter opens
a deadline for the whole invocation and each request gets
``min(configured_timeout, time remaining)``, so an over-budget tool fails as a
timeout it can explain.

**Responses are bounded and streamed.** A hypervisor returning an unbounded body
would otherwise be a memory exhaustion path into ACOP. The body is read in
chunks and abandoned the moment it exceeds :data:`MAX_RESPONSE_BYTES`.

**Redirects are refused.** ``follow_redirects=False``, deliberately: a redirect
is a server-controlled instruction to send the ``Authorization`` header
somewhere else, and there is no legitimate reason for the Proxmox API to issue
one for a GET under ``/api2/json/``.
"""

from __future__ import annotations

import json
import time
from types import TracebackType
from typing import Any, Final

import httpx

from acop.config import Settings
from acop.core.logging import get_logger
from acop.tools.adapters.proxmox.endpoints import TOOL_ENDPOINTS
from acop.tools.adapters.proxmox.errors import (
    ProxmoxAuthenticationError,
    ProxmoxAuthorizationError,
    ProxmoxConnectionError,
    ProxmoxHTTPStatusError,
    ProxmoxNotConfiguredError,
    ProxmoxProtocolError,
    ProxmoxTimeoutError,
)

logger = get_logger(__name__)

#: 8 MiB. Comfortably above any plausible ``/cluster/resources`` on a home lab or
#: a mid-sized cluster, and far below anything that would trouble the process.
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024

#: Connections ACOP will hold open to one Proxmox instance. Small because a
#: single invocation's widest fan-out is one request per node, issued in
#: sequence: the budget is shared, so concurrency would only make the requests
#: race each other for the same seconds.
_MAX_CONNECTIONS: Final = 4


class ProxmoxClient:
    """A read-only, token-authenticated, HTTPS-only Proxmox API client."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Build a client from ACOP configuration.

        Args:
            settings: The application settings. Base URL, token, TLS
                verification and timeout are read from here and from nowhere
                else.
            transport: Test seam. Supplying an ``httpx.MockTransport`` lets the
                real request-building, error-translation and envelope-parsing
                code run against a scripted upstream, rather than being replaced
                by a stub that proves nothing.

        Raises:
            ProxmoxNotConfiguredError: The integration is disabled, or a
                required setting is empty, or the base URL is not ``https``.
        """
        if not settings.proxmox_enabled:
            raise ProxmoxNotConfiguredError(
                "The Proxmox integration is disabled. Set ACOP_PROXMOX_ENABLED.",
                context={"setting": "ACOP_PROXMOX_ENABLED"},
            )
        base_url = settings.proxmox_base_url.strip().rstrip("/")
        token_id = settings.proxmox_token_id.strip()
        token_secret = settings.proxmox_token_secret.get_secret_value()
        if not base_url or not token_id or not token_secret:
            # Names the *setting*, never the value, and the secret is not even
            # compared against a sample - only tested for emptiness.
            raise ProxmoxNotConfiguredError(
                "The Proxmox integration is enabled but incompletely configured.",
                context={
                    "base_url_set": bool(base_url),
                    "token_id_set": bool(token_id),
                    "token_secret_set": bool(token_secret),
                },
            )
        if not base_url.lower().startswith("https://"):
            # The settings validator already refuses this. Repeated here because
            # this is the object that would actually put a token on the wire,
            # and a guarantee is worth having at the point of use as well as at
            # the point of configuration.
            raise ProxmoxNotConfiguredError(
                "ACOP_PROXMOX_BASE_URL must use https. The API token travels in "
                "a request header.",
                context={"scheme_ok": False},
            )

        self._instance_id = settings.proxmox_instance_id
        self._request_timeout = float(settings.proxmox_timeout_seconds)
        self._verify_tls = bool(settings.proxmox_verify_tls)
        self._base_url = base_url
        self._owns_client = transport is None
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=self._headers(token_id, token_secret),
            verify=self._verify_tls,
            timeout=httpx.Timeout(self._request_timeout),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=_MAX_CONNECTIONS),
            transport=transport,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _headers(token_id: str, token_secret: str) -> dict[str, str]:
        """The static request headers, including the API token.

        Proxmox API-token authentication, and only that. Ticket/password
        authentication is not implemented and must not be: a ticket flow means
        ACOP holds a user password, obtains a session cookie and a CSRF token,
        and renews them - three more secrets and a session lifecycle, in
        exchange for nothing a token does not already provide for a read.

        The token is built here so it exists only inside the client's header
        dict. ``httpx`` does not render headers in a ``repr``, and no code path
        in this module reads them back out.
        """
        return {
            "Authorization": f"PVEAPIToken={token_id}={token_secret}",
            "Accept": "application/json",
        }

    @property
    def instance_id(self) -> str:
        """The ACOP-owned id of the instance this client is configured for."""
        return self._instance_id

    @property
    def request_timeout(self) -> float:
        return self._request_timeout

    @property
    def verify_tls(self) -> bool:
        """Whether this client verifies the Proxmox certificate.

        Public so a test can assert the setting was honoured without reaching
        into ``httpx`` internals. It mirrors ``ACOP_PROXMOX_VERIFY_TLS`` and is
        what was handed to :class:`httpx.AsyncClient` as ``verify``.
        """
        return self._verify_tls

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> ProxmoxClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    # ------------------------------------------------------------------
    async def get_data(
        self,
        endpoint_key: str,
        *,
        deadline: float,
        **segments: str,
    ) -> Any:
        """Perform one allow-listed GET and return the ``data`` envelope.

        Args:
            endpoint_key: A key of
                :data:`~acop.tools.adapters.proxmox.endpoints.TOOL_ENDPOINTS`.
                Not a path, and not caller-supplied: the adapter passes a tool
                name it has already matched.
            deadline: ``time.monotonic()`` value at which the whole invocation's
                budget expires.
            segments: Trusted path segments - a node name from Proxmox's own
                inventory, a VMID parsed out of a registered identifier.

        Returns:
            Whatever was under ``data``: a list for the collection endpoints, a
            mapping for the object ones. Never the raw response, and never the
            headers.
        """
        endpoint = TOOL_ENDPOINTS.get(endpoint_key)
        if endpoint is None:  # pragma: no cover - the adapter matches first
            raise ProxmoxProtocolError(
                f"{endpoint_key!r} is not an allow-listed Proxmox endpoint.",
                context={"endpoint_key": endpoint_key},
            )
        path, query = endpoint.build(**segments)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProxmoxTimeoutError(
                "The invocation's time budget was exhausted before this request.",
                context={"path": path},
            )
        body = await self._send(
            path, query, timeout=min(self._request_timeout, remaining)
        )
        return self._envelope(body, path)

    # ------------------------------------------------------------------
    async def _send(self, path: str, query: dict[str, str], *, timeout: float) -> bytes:
        """Issue the GET, bound the body, and translate transport failures."""
        try:
            async with self._client.stream(
                "GET", path, params=query, timeout=timeout
            ) as response:
                self._check_status(response.status_code, path)
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        # Abandoned mid-stream rather than after the fact: the
                        # point is not to have held it in memory.
                        raise ProxmoxProtocolError(
                            "The Proxmox response exceeded the size ACOP accepts.",
                            context={"path": path, "limit_bytes": MAX_RESPONSE_BYTES},
                        )
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise ProxmoxTimeoutError(
                f"Proxmox did not answer {path} within {timeout:.1f}s.",
                context={"path": path, "timeout_seconds": round(timeout, 3)},
            ) from exc
        except httpx.TooManyRedirects as exc:
            # Refusing to follow is the feature: a redirect would move the
            # Authorization header to a host the configuration never named.
            raise ProxmoxProtocolError(
                f"Proxmox redirected {path}, which ACOP does not follow.",
                context={"path": path},
            ) from exc
        except httpx.ConnectError as exc:
            # A TLS verification failure surfaces as a ConnectError whose cause
            # is an ssl.SSLCertVerificationError. Told apart here because the
            # two need opposite responses: one is retryable and the other must
            # never be retried. See errors.py.
            if _is_tls_failure(exc):
                raise ProxmoxAuthenticationError(
                    "Proxmox did not present a certificate ACOP could verify.",
                    context={"path": path, "verify_tls": self._verify_tls},
                ) from exc
            raise ProxmoxConnectionError(
                f"Could not connect to the Proxmox host for {path}.",
                context={"path": path},
            ) from exc
        except httpx.HTTPError as exc:
            raise ProxmoxConnectionError(
                f"The connection to Proxmox failed for {path}: {type(exc).__name__}.",
                context={"path": path},
            ) from exc
        return b"".join(chunks)

    @staticmethod
    def _check_status(status_code: int, path: str) -> None:
        """Map a status onto the taxonomy. The body is never read for this."""
        if status_code == 200:
            return
        if status_code == 401:
            raise ProxmoxAuthenticationError(
                "Proxmox rejected the API token.",
                context={"path": path, "status_code": status_code},
            )
        if status_code == 403:
            raise ProxmoxAuthorizationError(
                "The Proxmox API token is not permitted to perform this read.",
                context={"path": path, "status_code": status_code},
            )
        raise ProxmoxHTTPStatusError(
            f"Proxmox answered {status_code} for {path}.",
            # The status and the path, never the body. An error body may quote
            # the request, and the request carried the token.
            context={"path": path, "status_code": status_code},
        )

    @staticmethod
    def _envelope(body: bytes, path: str) -> Any:
        """Unwrap ``{"data": ...}``, or fail.

        Never ``{}``, never ``[]``, never ``None`` as a stand-in for a response
        ACOP could not read. An empty inventory and an unreadable one are
        different facts, and the checkpoint that consumes this would act on the
        second as though it were the first.
        """
        try:
            decoded = json.loads(body)
        except ValueError as exc:
            raise ProxmoxProtocolError(
                f"Proxmox returned a non-JSON body for {path}.",
                context={"path": path, "bytes": len(body)},
            ) from exc
        if not isinstance(decoded, dict) or "data" not in decoded:
            raise ProxmoxProtocolError(
                f"The response for {path} carried no Proxmox data envelope.",
                context={"path": path, "keys": sorted(map(str, _keys(decoded)))},
            )
        return decoded["data"]


def _keys(decoded: object) -> list[str]:
    """Top-level key names of a decoded body, for diagnosis. Names only."""
    if isinstance(decoded, dict):
        return [str(key) for key in decoded]
    return []


def _is_tls_failure(exc: BaseException) -> bool:
    """Whether a connection error was a certificate verification failure.

    Walks ``__cause__`` and ``__context__`` looking for an ``ssl`` exception
    rather than matching on message text, which is a Python-version-dependent
    string and would fail open the first time it changed.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        module = type(current).__module__
        if module == "ssl" or type(current).__name__.startswith("SSL"):
            return True
        current = current.__cause__ or current.__context__
    return False


__all__ = ["MAX_RESPONSE_BYTES", "ProxmoxClient"]
