from enum import Enum


class Permission(Enum):
    ROOT = "root"
    USER_MANAGE = "user:manage"
    STORE_READ = "store:read"
    STORE_WRITE = "store:write"


class GrantAccess(Enum):
    READ = "read"
    WRITE = "write"
    DELEGATE = "delegate"
    DELETE = "delete"
