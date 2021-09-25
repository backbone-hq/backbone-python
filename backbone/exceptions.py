from dataclasses import dataclass, field
from typing import List, Optional

from .models import Permission


class BackboneException(Exception):
    message: str
    __status_code__: int
    type: str


@dataclass
class MalformedRequestException(BackboneException):
    type: str = "malformed_request"
    __status_code__: int = 400


@dataclass
class InvalidTokenException(BackboneException):
    type: str = "invalid_token"
    __status_code__: int = 401


@dataclass
class NonexistentTokenException(BackboneException):
    type: str = "nonexistent_token"
    __status_code__: int = 401


@dataclass
class UnauthorizedTokenException(BackboneException):
    expected: List[Permission]
    provided: List[Permission]

    type: str = "unauthorized_token"
    __status_code__: int = 403


@dataclass
class ExpiringTokenException(BackboneException):
    type: str = "expiring_token"
    __status_code__: int = 409


@dataclass
class ConflictingWorkspaceException(BackboneException):
    workspace: str
    type: str = "conflicting_workspace"
    __status_code__: int = 409


@dataclass
class ConflictingUserException(BackboneException):
    username: str
    public_key: str
    type: str = "conflicting_user"
    __status_code__: int = 409


@dataclass
class NonexistentUserException(BackboneException):
    username: Optional[str] = None
    public_key: Optional[str] = None
    __status_code__: int = 404
    type: str = "nonexistent_user"


@dataclass
class InsufficientPrivilegedUsersException(BackboneException):
    type: str = "insufficient_privileged_users"
    __status_code__: int = 409


@dataclass
class DanglingGrantsException(BackboneException):
    __status_code__: int = 409
    type: str = "dangling_grants"


@dataclass
class NonexistentStoreKeyException(BackboneException):
    __status_code__: int = 404
    type: str = "nonexistent_store_key"


@dataclass
class UnauthorizedGrantException(BackboneException):
    __status_code__: int = 403
    type: str = "unauthorized_grant"


@dataclass
class ConflictingStoreKeyException(BackboneException):
    __status_code__: int = 409
    type: str = "conflicting_store_key"


@dataclass
class GrantLimitException(BackboneException):
    __status_code__: int = 409
    type: str = "grant_limit"


@dataclass
class ConflictingGrantException(BackboneException):
    __status_code__: int = 409
    type: str = "conflicting_grant"


_ERR_MAP = {cls.type: cls for cls in BackboneException.__subclasses__()}


def deserialize_exception(error: dict):
    error_type = error.get("type")
    if not error_type:
        raise (f"Unknown error: {error}")

    exception = _ERR_MAP.get(error_type)
    if not exception:
        raise NotImplementedError(f"Received unknown error type: {error}")

    raise exception