"""Proxmox transport failures, mapped onto Milestone 4's error taxonomy.

Every class here is a :class:`~acop.tools.errors.ToolError` subclass carrying an
**existing** :class:`~acop.models.tool_vocabulary.ToolErrorCategory`. No new
category is introduced, and none is needed: the framework's categories already
name every condition this transport can be in, and adding a Proxmox-shaped
category would put a vendor into a vocabulary that is deliberately about ACOP's
own semantics.

These live beside the adapter rather than in :mod:`acop.tools.errors` for the
same reason: that module is the framework's taxonomy, and one integration's
failure modes are not part of it.

Three mappings are worth defending, because the obvious answer is wrong:

**A TLS verification failure is ``AUTHENTICATION``, not a connection failure.**
The socket opened. What failed is the server proving it is the server, which is
authentication in the exact sense the category means - and, unlike
``TARGET_UNAVAILABLE``, it is not retryable. Retrying a certificate mismatch
cannot succeed, and if the mismatch is an active interception, retrying is the
one thing that should not happen.

**A guest that live inventory does not list is ``INVALID_TARGET``, not
``TARGET_UNAVAILABLE``.** "Unavailable" means ACOP could not reach it and is
retryable; a VMID that Proxmox has no record of is not unreachable, it is gone.
Retrying returns the same empty answer, and the honest phrase - "the target is
unknown or out of scope" - is the one an operator needs in order to look at the
CMDB rather than at the network.

**A malformed response is ``EXECUTION_FAILED``, never
``OUTPUT_CONTRACT_VIOLATION``.** ADR-0023 gives that category one meaning: the
adapter's projection or the tool's declaration is wrong, and the fix is in
ACOP's code. A response that is not JSON, or carries no ``data`` envelope, or
omits a field the API is documented to return, is Proxmox disagreeing with
ACOP - a different fault with a different remediation. Conflating them would
send an engineer to read ``projection.py`` when the answer is on the other host.
"""

from __future__ import annotations

from acop.models.tool_vocabulary import ToolErrorCategory
from acop.tools.errors import ToolError


class ProxmoxError(ToolError):
    """Base for every Proxmox transport failure.

    Inherits :class:`~acop.tools.errors.ToolError`'s guarantee that the public
    message comes from :data:`~acop.models.tool_vocabulary.ERROR_PHRASES` and
    never from an upstream response body.
    """

    code = "proxmox_error"
    http_status = 502
    category = ToolErrorCategory.EXECUTION_FAILED


class ProxmoxNotConfiguredError(ProxmoxError):
    """The Proxmox integration is disabled, or its settings are incomplete.

    ``ADAPTER_UNAVAILABLE`` rather than ``INTERNAL_ERROR`` because that is what
    an operator needs to read: the adapter cannot be used, so look at
    ``ACOP_PROXMOX_*``. ``INTERNAL_ERROR`` already carries unhandled adapter
    exceptions and policy-engine malfunctions, and a category shared by three
    unrelated causes stops directing an investigation anywhere - the same
    argument Milestone 4 finding F-4 made.

    It is a retryable category, and a retry will not fix a disabled
    integration. That costs one extra call that makes no HTTP request and
    resolves the same way, which is a smaller price than a misdirected
    category.
    """

    code = "proxmox_not_configured"
    http_status = 503
    category = ToolErrorCategory.ADAPTER_UNAVAILABLE


class ProxmoxIdentifierError(ProxmoxError):
    """The target carries no usable Proxmox identifier, or a malformed one.

    Raised before any HTTP request. An asset the CMDB says is a Proxmox guest
    but which has no ``proxmox:guest`` identifier cannot be addressed, and
    guessing - from the display name, from a fact, from anything - is exactly
    the substitution this architecture exists to refuse.
    """

    code = "proxmox_identifier_invalid"
    http_status = 422
    category = ToolErrorCategory.INVALID_TARGET


class ProxmoxInstanceMismatchError(ProxmoxError):
    """The identifier belongs to a different Proxmox instance.

    The hard failure the ratified design places **before** the first HTTP
    request. Without it, an asset correlated to another instance would be read
    against this one's base URL, and a VMID that exists on both would return a
    confident answer about the wrong machine.
    """

    code = "proxmox_instance_mismatch"
    http_status = 422
    category = ToolErrorCategory.INVALID_TARGET


class ProxmoxObjectNotFoundError(ProxmoxError):
    """Live inventory contains no such node or guest.

    Zero matches, where the design requires exactly one.
    """

    code = "proxmox_object_not_found"
    http_status = 422
    category = ToolErrorCategory.INVALID_TARGET


class ProxmoxAmbiguousObjectError(ProxmoxError):
    """Live inventory contains more than one match, where one was required.

    Not ``INVALID_TARGET``: the target was named correctly and Proxmox answered
    with something that should be impossible - two guests sharing a VMID and
    type. Picking one would be a guess about infrastructure, which is the one
    thing this integration may never do.
    """

    code = "proxmox_object_ambiguous"
    http_status = 502
    category = ToolErrorCategory.EXECUTION_FAILED


class ProxmoxAuthenticationError(ProxmoxError):
    """Proxmox rejected the API token, or did not authenticate itself.

    Covers HTTP 401 and TLS verification failure. The second is deliberate: see
    this module's docstring.
    """

    code = "proxmox_authentication_failed"
    http_status = 502
    category = ToolErrorCategory.AUTHENTICATION


class ProxmoxAuthorizationError(ProxmoxError):
    """The token authenticated but lacks privilege for this read (HTTP 403).

    Distinct from :class:`ProxmoxAuthenticationError` because the remediation is
    distinct: a role or ACL on the Proxmox side, not a credential.
    """

    code = "proxmox_not_authorized"
    http_status = 502
    category = ToolErrorCategory.AUTHORIZATION


class ProxmoxTimeoutError(ProxmoxError):
    """A request, or the invocation's whole budget, ran out of time.

    Not retryable, following the framework's rule that a request which timed out
    may still be in flight. That rule is about writes and this transport only
    reads, but a read-only exception to it would be a second timeout policy for
    someone to reason about.
    """

    code = "proxmox_timeout"
    http_status = 504
    category = ToolErrorCategory.TIMEOUT


class ProxmoxConnectionError(ProxmoxError):
    """The host could not be reached: DNS, refused connection, reset.

    Retryable, and one of only two categories that are.
    """

    code = "proxmox_unreachable"
    http_status = 503
    category = ToolErrorCategory.TARGET_UNAVAILABLE


class ProxmoxHTTPStatusError(ProxmoxError):
    """Proxmox answered with a status this transport does not accept.

    Everything that is not 200, 401 or 403. The status code goes to the
    structured log; the response body does not, because an error body is the
    least trustworthy string in the exchange and may quote a request header.
    """

    code = "proxmox_http_error"
    http_status = 502
    category = ToolErrorCategory.EXECUTION_FAILED


class ProxmoxProtocolError(ProxmoxError):
    """The response was not the shape the Proxmox API is documented to return.

    Non-JSON, no ``data`` envelope, a list where an object was required, a
    record missing a field routing depends on, or a body over the size cap.

    Deliberately **not** answered with an empty result. An empty guest
    inventory and an unparseable one are different facts, and the discovery
    checkpoint that consumes this would read the second as "every guest is
    gone" and retire the lot.
    """

    code = "proxmox_protocol_error"
    http_status = 502
    category = ToolErrorCategory.EXECUTION_FAILED


__all__ = [
    "ProxmoxAmbiguousObjectError",
    "ProxmoxAuthenticationError",
    "ProxmoxAuthorizationError",
    "ProxmoxConnectionError",
    "ProxmoxError",
    "ProxmoxHTTPStatusError",
    "ProxmoxIdentifierError",
    "ProxmoxInstanceMismatchError",
    "ProxmoxNotConfiguredError",
    "ProxmoxObjectNotFoundError",
    "ProxmoxProtocolError",
    "ProxmoxTimeoutError",
]
