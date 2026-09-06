"""The tool catalog — every capability ACOP can execute, declared in code.

``git log src/acop/tools/catalog/`` is the complete capability change history.
That is the whole argument for keeping definitions here rather than in a table:
adding a capability requires a commit, a review and a deploy, so no SQL
injection, compromised credential, careless migration or restored backup can
mint one.

Milestone 4 declares six tools, and all six exist to prove the framework rather
than to do useful work. Two report on ACOP itself, one reads the CMDB, two make
simulated changes, and one is prohibited and must never execute. None can
affect the host, Docker, the network, or real infrastructure.

Importing this module registers all six. The adapters are imported first
because import rule 13 refuses a declaration whose adapter does not resolve.
"""

# Adapters first: rule 13 checks the binding at declaration time.
import acop.tools.adapters  # noqa: F401
from acop.tools.catalog.echo import ECHO_METADATA
from acop.tools.catalog.health import SYSTEM_HEALTH
from acop.tools.catalog.prohibited import PROHIBITED_SHELL_EXEC
from acop.tools.catalog.rotate_key import ROTATE_KEY
from acop.tools.catalog.service_restart import SERVICE_RESTART
from acop.tools.catalog.status import DEVICE_STATUS

#: Every tool this build declares. Used by the acceptance verifier and by the
#: unit test that asserts exactly one tool carries the testing marker.
CATALOG = (
    SYSTEM_HEALTH,
    ECHO_METADATA,
    DEVICE_STATUS,
    SERVICE_RESTART,
    ROTATE_KEY,
    PROHIBITED_SHELL_EXEC,
)

__all__ = [
    "CATALOG",
    "DEVICE_STATUS",
    "ECHO_METADATA",
    "PROHIBITED_SHELL_EXEC",
    "ROTATE_KEY",
    "SERVICE_RESTART",
    "SYSTEM_HEALTH",
]
