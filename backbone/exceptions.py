from abc import abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from .models import Permission


@dataclass
class BackboneException(Exception):
    message: str

    def __str__(self) -> str:
        return self.message

    @property
    @abstractmethod
    def __status_code__(self) -> int:
        pass

    @property
    @abstractmethod
    def type(self) -> str:
        pass


@dataclass
class InternalServerError(BackboneException):
    __status_code__: int = 500
    type: str = "internal_server_error"


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
class InvalidTokenChallengeException(BackboneException):
    type: str = "invalid_token_challenge"
    __status_code__: int = 400


@dataclass
class InvalidTokenResponseException(BackboneException):
    type: str = "invalid_token_response"
    __status_code__: int = 400


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


@dataclass
class RateLimitException(BackboneException):
    __status_code__: int = 429
    type: str = "rate_limit"


_ERR_MAP = {cls.type: cls for cls in BackboneException.__subclasses__()}


def deserialize_exception(exception: dict):
    error_type = exception.get("type")
    if not error_type:
        raise BackboneException(message=exception.get("message"))

    exception_class = _ERR_MAP.get(error_type)
    if not exception:
        raise NotImplementedError(f"Unknown error: {exception}")

    raise exception_class(**exception)
