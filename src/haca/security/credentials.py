"""Credential loading from keyring or environment."""

from __future__ import annotations

import os
from typing import Protocol

import keyring
from pydantic import BaseModel, ConfigDict, SecretStr

from haca.security.redaction import register_secret


class CredentialNotFound(KeyError):
    """Raised when credentials for a reference are missing."""


class Credential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    password: SecretStr

    def __str__(self) -> str:
        return f"Credential(username={self.username!r}, password='***')"

    def __repr__(self) -> str:
        return self.__str__()


class CredentialStore(Protocol):
    def get(self, credential_ref: str) -> Credential: ...


class KeyringCredentialStore:
    def __init__(self, service: str = "haca") -> None:
        self._service = service

    def get(self, credential_ref: str) -> Credential:
        username_key = f"{credential_ref}:username"
        password_key = f"{credential_ref}:password"
        username = keyring.get_password(self._service, username_key)
        password = keyring.get_password(self._service, password_key)
        if username is None or password is None:
            raise CredentialNotFound(credential_ref)
        register_secret(password)
        return Credential(username=username, password=SecretStr(password))


class DictCredentialStore:
    """In-memory credential store (simulation and tests)."""

    def __init__(self, mapping: dict[str, Credential]) -> None:
        self._mapping = dict(mapping)

    def get(self, credential_ref: str) -> Credential:
        try:
            cred = self._mapping[credential_ref]
        except KeyError as exc:
            raise CredentialNotFound(credential_ref) from exc
        register_secret(cred.password.get_secret_value())
        return cred


class EnvCredentialStore:
    @staticmethod
    def _env_prefix(credential_ref: str) -> str:
        return f"HACA_CRED_{credential_ref.upper()}"

    def get(self, credential_ref: str) -> Credential:
        prefix = self._env_prefix(credential_ref)
        username = os.environ.get(f"{prefix}_USERNAME")
        password = os.environ.get(f"{prefix}_PASSWORD")
        if username is None or password is None:
            raise CredentialNotFound(credential_ref)
        register_secret(password)
        return Credential(username=username, password=SecretStr(password))