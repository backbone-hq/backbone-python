from datetime import datetime
from enum import Enum
from functools import partial
from typing import List, Optional

from pydantic import BaseModel, Field, conint, conlist, conset, constr

# Primitive types
safe_base64 = partial(constr, strip_whitespace=True, regex=r"[a-zA-Z0-9-_]+={0,3}")
public_key = partial(safe_base64, min_length=44, max_length=44)

# Backbone restrictions
workspace_name = partial(constr, strip_whitespace=True, min_length=1, max_length=128, regex=r"[a-z-_]+")
user_name = partial(constr, strip_whitespace=True, min_length=1, max_length=128, regex=r"[a-zA-Z0-9-_]+")
store_key = partial(constr, strip_whitespace=True, max_length=256)

# Token
entry_duration = partial(conint, gt=0)
token_duration = partial(conint, gt=0, le=30 * 86_400)


class Permission(str, Enum):
    """Access control for endpoints"""

    # Root permissions
    ROOT = "root"

    # User permissions
    USER_MANAGE = "user:manage"

    # Store permissions
    STORE_USE = "store:use"
    STORE_SHARE = "store:share"


class GrantAccess(str, Enum):
    """Access control within the store"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EJECT = "eject"


class BackboneModel(BaseModel):
    class Config:
        orm_mode = True


class User(BackboneModel):
    name: user_name()
    public_key: public_key()
    permissions: List[Permission]


class UserPermissionModification(BackboneModel):
    name: user_name()
    permissions: List[Permission]


class Workspace(BackboneModel):
    name: workspace_name()
    display_name: constr(min_length=1, max_length=128)


class BaseGrant(BackboneModel):
    active: bool = Field(default=True)
    subject_pk: Optional[public_key()] = Field(default=None)
    grantee_pk: public_key()
    value: safe_base64(min_length=96, max_length=108)
    access: conset(GrantAccess, min_items=1)


class NamespaceGrant(BaseGrant):
    value: safe_base64(min_length=96, max_length=96)


class EntryGrant(BaseGrant):
    value: safe_base64(min_length=108, max_length=108)


class Chain(BackboneModel):
    key: store_key()
    chain: List[NamespaceGrant]


class NamespaceDefinition(BackboneModel):
    public_key: public_key()
    grants: conlist(NamespaceGrant, min_items=1)


class Namespace(NamespaceDefinition, Chain):
    pass


class EntryDefinition(BackboneModel):
    value: safe_base64(max_length=4096)
    grants: conlist(EntryGrant, min_items=1)
    duration: Optional[entry_duration()] = Field(default=None)


class Entry(EntryDefinition, Chain):
    pass


class WorkspaceCreation(BackboneModel):
    workspace: Workspace
    user: User
    namespace: NamespaceDefinition


class Token(BackboneModel):
    encrypted_value: safe_base64()
    duration: token_duration()
    permissions: Optional[List[Permission]]


class TokenDerivation(BackboneModel):
    permissions: Optional[List[Permission]] = Field(default=None)
    duration: token_duration() = Field(default=86_400)


class TokenRequest(BackboneModel):
    permissions: Optional[List[Permission]] = Field(default=None)
    workspace: workspace_name()
    username: user_name()
    duration: token_duration() = Field(default=86_400)


class TokenResponse(TokenRequest):
    response: safe_base64()


class TokenChallenge(BackboneModel):
    challenge: safe_base64()
    expires_on: datetime


class Action(str, Enum):
    # Audit Log
    AUDIT_ALL = "audit_all"
    AUDIT_SELF = "audit_self"

    # Workspace
    WORKSPACE_GET = "workspace_get"
    WORKSPACE_CREATE = "workspace_create"
    WORKSPACE_DELETE = "workspace_delete"

    # User
    USERS_GET = "users_get"
    USERS_SEARCH = "users_search"
    USER_GET = "user_get"
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    USER_MODIFY = "user_modify"

    # Token
    TOKENS_GET = "tokens_get"
    TOKEN_GET = "token_get"
    TOKEN_AUTHENTICATE = "token_authenticate"
    TOKEN_DERIVE = "token_derive"
    TOKEN_REVOKE = "token_revoke"

    # Entry
    ENTRY_GET = "entry_get"
    ENTRY_CREATE = "entry_create"
    ENTRY_DELETE = "entry_delete"
    ENTRY_LIST = "entry_list"

    # Entry Grants
    ENTRY_GRANT = "entry_grant"
    ENTRY_REVOKE = "entry_revoke"

    # Namespace
    NAMESPACE_GET = "namespace_get"
    NAMESPACE_CREATE = "namespace_create"
    NAMESPACE_DELETE = "namespace_delete"
    NAMESPACE_LIST = "namespace_list"

    # Namespace Grants
    NAMESPACE_GRANT = "namespace_grant"
    NAMESPACE_REVOKE = "namespace_revoke"

    # Chain
    CHAIN_GET = "chain_get"
