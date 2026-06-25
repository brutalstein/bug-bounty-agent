from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import base64
import hashlib
import json
import os

from core.http_client import SafeHttpClient
from core.run_context import RunContext
from core.scope import ScopeManager, SessionProfileConfig


@dataclass
class AuthenticatedSessionArtifact:
    session_profile_name: str
    kind: str
    login_url: str
    username: str
    role_hint: str
    derived_role: str
    acquired_at: str
    auth_header_name: str
    auth_header_prefix: str
    token_sha256: str
    token_fingerprint: str
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuthenticatedSession:
    artifact: AuthenticatedSessionArtifact
    headers: dict[str, str]


class AuthenticatedSessionManager:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.client = SafeHttpClient(timeout_seconds=10)

    def login(self, session_profile_name: str, manual_approval: bool = False) -> AuthenticatedSession:
        if self.scope.config.mode != "lab":
            raise PermissionError(
                "Authenticated session bootstrap is currently restricted to lab profiles."
            )

        if not self.scope.is_authorization_confirmed():
            raise PermissionError(
                "Authorization is not confirmed for the selected profile."
            )

        if self.scope.requires_manual_approval("authenticated_crawl") and not manual_approval:
            raise PermissionError(
                "Authenticated crawl requires explicit manual approval."
            )

        if not self.scope.is_method_allowed("POST"):
            raise PermissionError(
                "Policy does not allow POST for authenticated session bootstrap."
            )

        profile = self.scope.get_session_profile(session_profile_name)
        if not profile.login_url:
            raise ValueError(
                f"Session profile `{session_profile_name}` is missing login_url."
            )

        if not self.scope.is_target_allowed(profile.login_url):
            raise PermissionError(
                f"Login URL is out of scope for session profile `{session_profile_name}`."
            )

        username, password = self._resolve_credentials(profile)
        payload = {
            profile.username_field: username,
            profile.password_field: password,
        }

        response = self.client.post_json(profile.login_url, payload)
        if not response.success:
            raise RuntimeError(
                f"Session login failed with status {response.status_code}: {response.error}"
            )

        token = self._extract_token(response.body, profile.token_json_path)
        if not token:
            raise RuntimeError(
                f"Session login succeeded but token was not found at `{profile.token_json_path}`."
            )

        derived_role = self._derive_role_from_jwt(token)
        header_value = self._build_header_value(profile, token)
        artifact = AuthenticatedSessionArtifact(
            session_profile_name=session_profile_name,
            kind=profile.kind,
            login_url=profile.login_url,
            username=username,
            role_hint=profile.role_hint,
            derived_role=derived_role,
            acquired_at=datetime.now(timezone.utc).isoformat(),
            auth_header_name=profile.auth_header_name,
            auth_header_prefix=profile.auth_header_prefix,
            token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            token_fingerprint=self._token_fingerprint(token),
            notes=profile.notes,
        )

        self.ctx.write_json("parsed/auth_session.json", artifact.to_dict())
        self.ctx.add_event(
            event_type="auth_session_created",
            message="Authenticated lab session created.",
            data={
                "session_profile_name": session_profile_name,
                "login_url": profile.login_url,
                "username": username,
                "derived_role": derived_role,
            },
        )

        return AuthenticatedSession(
            artifact=artifact,
            headers={profile.auth_header_name: header_value},
        )

    def _resolve_credentials(self, profile: SessionProfileConfig) -> tuple[str, str]:
        username = ""
        password = ""

        if profile.username_env:
            username = str(os.getenv(profile.username_env, "")).strip()
        if profile.password_env:
            password = str(os.getenv(profile.password_env, "")).strip()

        if not username:
            username = profile.username_default
        if not password:
            password = profile.password_default

        if not username or not password:
            raise ValueError(
                f"Session profile `{profile.name}` does not have usable credentials."
            )

        return username, password

    def _extract_token(self, body: str, path: str) -> str:
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Login response was not valid JSON: {exc}") from exc

        current = data
        for part in [segment for segment in path.split(".") if segment]:
            if not isinstance(current, dict) or part not in current:
                return ""
            current = current[part]

        return str(current).strip() if current is not None else ""

    def _build_header_value(self, profile: SessionProfileConfig, token: str) -> str:
        prefix = profile.auth_header_prefix.strip()
        if not prefix:
            return token
        return f"{prefix} {token}"

    def _token_fingerprint(self, token: str) -> str:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return f"sha256:{digest[:16]}"

    def _derive_role_from_jwt(self, token: str) -> str:
        parts = token.split(".")
        if len(parts) < 2:
            return ""

        payload = parts[1]
        padding = "=" * (-len(payload) % 4)

        try:
            decoded = base64.urlsafe_b64decode(payload + padding).decode("utf-8")
            data = json.loads(decoded)
        except Exception:
            return ""

        if not isinstance(data, dict):
            return ""

        inner = data.get("data", {})
        if isinstance(inner, dict):
            return str(inner.get("role", "")).strip()

        return ""
