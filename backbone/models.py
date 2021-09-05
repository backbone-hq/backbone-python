from enum import Enum
from functools import partial
from typing import List, Optional

from pydantic import BaseModel, Field, conint, conlist, conset, constr

# Primitive types
safe_base64 = partial(constr, strip_whitespace=True, regex=r"[a-zA-Z0-9-_]+={0,3}")

# Semantic types
email_address = partial(
    constr,
    strip_whitespace=True,
    regex=r"[^@ \t\r\n]+@[^@ \t\r\n]+\.[^@ \t\r\n]+",
    min_length=8,
    max_length=128,
)
public_key = partial(safe_base64, min_length=44, max_length=44)

# Store primitives
store_key = partial(constr, strip_whitespace=True, max_length=256)

# Token
entry_duration = conint(gt=0)
token_duration = conint(gt=0, le=30 * 86_400)


class Permission(Enum):
    """Access control for API endpoints"""

    # Root permissions
    ROOT = "root"

    # User permissions
    USER_MANAGE = "user:manage"

    # Store permissions
    STORE_USE = "store:use"
    STORE_SHARE = "store:share"


class GrantAccess(Enum):
    """Access control within the store"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EJECT = "eject"


class BackboneModel(BaseModel):
    class Config:
        orm_mode = True


class User(BackboneModel):
    name: constr(min_length=1, max_length=128)
    email_address: Optional[email_address()]
    public_key: public_key()
    permissions: List[Permission]


class Workspace(BackboneModel):
    name: constr(min_length=1, max_length=128)
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
    duration: Optional[entry_duration] = Field(default=None)


class Entry(EntryDefinition, Chain):
    pass


class Token(BackboneModel):
    hidden_token: safe_base64()
    duration: token_duration
    permissions: Optional[List[Permission]]


class TokenDerivationRequest(BackboneModel):
    permissions: Optional[List[Permission]] = Field(default=None)
    duration: token_duration = Field(default=86_400)


class TokenAuthenticationRequest(BackboneModel):
    permissions: Optional[List[Permission]] = Field(default=None)
    workspace: constr(min_length=1, max_length=128)
    username: constr(min_length=1, max_length=128)
    duration: token_duration = Field(default=86_400)


class Action(Enum):
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
