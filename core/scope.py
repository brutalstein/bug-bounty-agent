from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import fnmatch

import yaml


@dataclass(frozen=True)
class ScopeRules:
    max_requests_per_minute: int
    allow_subdomain_scan: bool
    allow_port_scan: bool
    allow_active_scan: bool
    allow_browser_crawl: bool
    require_scope_check: bool
    save_all_outputs: bool


@dataclass(frozen=True)
class SafetyRules:
    stop_on_scope_violation: bool
    stop_on_high_error_rate: bool
    destructive_actions_allowed: bool


@dataclass(frozen=True)
class AuthorizationConfig:
    kind: str
    confirmed: bool
    evidence: str


@dataclass(frozen=True)
class PolicyConfig:
    program_name: str
    program_url: str
    policy_reviewed_at: str
    policy_max_age_days: int
    allowed_http_methods: list[str]
    requires_manual_approval_for: list[str]
    disallowed_actions: list[str]
    notes: list[str]
    priority_categories: list[str]
    deprioritized_categories: list[str]
    core_ineligible_findings: list[str]
    focus_areas: list[dict]
    operator_recipes: list[dict]


@dataclass(frozen=True)
class SessionProfileConfig:
    name: str
    kind: str
    login_url: str
    username_field: str
    password_field: str
    username_default: str
    password_default: str
    username_env: str
    password_env: str
    token_default: str
    token_env: str
    token_json_path: str
    auth_header_name: str
    auth_header_prefix: str
    role_hint: str
    probe_urls: list[str]
    notes: list[str]


@dataclass(frozen=True)
class LabConfig:
    docker_image: str
    container_name: str
    published_port: int
    container_port: int


@dataclass(frozen=True)
class ScopeConfig:
    profile_name: str
    project_name: str
    project_description: str
    mode: str
    target_name: str
    target_type: str
    base_url: str
    allowed_hosts: list[str]
    allowed_url_patterns: list[str]
    blocked_hosts: list[str]
    blocked_path_prefixes: list[str]
    rules: ScopeRules
    safety: SafetyRules
    authorization: AuthorizationConfig
    policy: PolicyConfig
    session_profiles: dict[str, SessionProfileConfig]
    lab: LabConfig | None


class ScopeManager:
    def __init__(
        self,
        config_path: str | Path = "configs/scope.yaml",
        profile_name: str | None = None,
    ):
        self.config_path = Path(config_path)
        self.raw_config = self._load_raw_config()
        self.profile_name = profile_name or self.get_active_profile_name()
        self.config = self.load_profile(self.profile_name)

    def _load_raw_config(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Scope config not found: {self.config_path}")

        with self.config_path.open("r", encoding="utf-8") as file:
            raw_config = yaml.safe_load(file) or {}

        if not isinstance(raw_config, dict):
            raise ValueError("Scope config must contain a YAML object at the top level.")

        return self._merge_external_profiles(raw_config)

    def _merge_external_profiles(self, raw_config: dict) -> dict:
        profiles_dir = self.config_path.parent / "profiles"
        if not profiles_dir.exists() or not profiles_dir.is_dir():
            return raw_config

        merged_profiles = dict(raw_config.get("profiles", {}) or {})

        for path in sorted(profiles_dir.glob("*.y*ml")):
            with path.open("r", encoding="utf-8") as file:
                external_data = yaml.safe_load(file) or {}

            if not isinstance(external_data, dict):
                continue

            if isinstance(external_data.get("profiles"), dict):
                for profile_name, profile_config in external_data["profiles"].items():
                    merged_profiles[str(profile_name)] = profile_config or {}
                continue

            target_profile = external_data.get("target_profile", {})
            profile_name = str(target_profile.get("name", path.stem)).strip() or path.stem
            merged_profiles[profile_name] = external_data

        if not merged_profiles:
            return raw_config

        merged_config = dict(raw_config)
        merged_config["profiles"] = merged_profiles
        return merged_config

    def get_active_profile_name(self) -> str:
        active_profile = str(self.raw_config.get("active_profile", "")).strip()

        if active_profile:
            return active_profile

        profiles = self.raw_config.get("profiles", {})

        if isinstance(profiles, dict) and profiles:
            return next(iter(profiles))

        legacy_target = self.raw_config.get("target_profile", {})
        legacy_name = str(legacy_target.get("name", "")).strip()

        if legacy_name:
            return legacy_name

        raise ValueError("No active profile found in scope config.")

    def list_profiles(self) -> list[dict]:
        profiles = self.raw_config.get("profiles", {})

        if isinstance(profiles, dict) and profiles:
            items = []
            active_name = self.get_active_profile_name()

            for profile_name, profile_data in profiles.items():
                target = profile_data.get("target_profile", {})
                authorization = profile_data.get("authorization", {})
                policy = profile_data.get("policy", {})

                items.append(
                    {
                        "profile_name": profile_name,
                        "target_name": target.get("name", profile_name),
                        "target_type": target.get("type", "unknown"),
                        "base_url": target.get("base_url", ""),
                        "authorization_confirmed": bool(
                            authorization.get("confirmed", False)
                        ),
                        "program_name": policy.get("program_name", ""),
                        "is_active": profile_name == active_name,
                    }
                )

            return items

        if self.raw_config.get("target_profile"):
            legacy_target = self.raw_config.get("target_profile", {})
            return [
                {
                    "profile_name": legacy_target.get("name", "default"),
                    "target_name": legacy_target.get("name", "default"),
                    "target_type": legacy_target.get("type", "unknown"),
                    "base_url": legacy_target.get("base_url", ""),
                    "authorization_confirmed": True,
                    "program_name": "Legacy Scope",
                    "is_active": True,
                }
            ]

        return []

    def load_profile(self, profile_name: str) -> ScopeConfig:
        project = self.raw_config.get("project", {})
        profiles = self.raw_config.get("profiles", {})

        if isinstance(profiles, dict) and profiles:
            if profile_name not in profiles:
                available = ", ".join(sorted(profiles))
                raise ValueError(
                    f"Unknown scope profile: {profile_name}. Available profiles: {available}"
                )

            profile = profiles[profile_name] or {}
            target = profile.get("target_profile", {})
            scope = profile.get("scope", {})
            rules = profile.get("rules", {})
            safety = profile.get("safety", {})
            authorization = profile.get("authorization", {})
            policy = profile.get("policy", {})
            lab = profile.get("lab", {})
        else:
            target = self.raw_config.get("target_profile", {})
            scope = self.raw_config.get("scope", {})
            rules = self.raw_config.get("rules", {})
            safety = self.raw_config.get("safety", {})
            authorization = self.raw_config.get("authorization", {})
            policy = self.raw_config.get("policy", {})
            lab = self.raw_config.get("lab", {})

        allowed_methods = policy.get("allowed_http_methods", ["GET", "HEAD", "OPTIONS"])
        if not isinstance(allowed_methods, list) or not allowed_methods:
            allowed_methods = ["GET", "HEAD", "OPTIONS"]

        return ScopeConfig(
            profile_name=profile_name,
            project_name=project.get("name", "bug-bounty-agent"),
            project_description=project.get("description", ""),
            mode=project.get("mode", "lab"),
            target_name=target.get("name", profile_name),
            target_type=target.get("type", "unknown"),
            base_url=target.get("base_url", ""),
            allowed_hosts=scope.get("allowed_hosts", []),
            allowed_url_patterns=scope.get("allowed_url_patterns", []),
            blocked_hosts=scope.get("blocked_hosts", []),
            blocked_path_prefixes=scope.get("blocked_path_prefixes", []),
            rules=ScopeRules(
                max_requests_per_minute=rules.get("max_requests_per_minute", 30),
                allow_subdomain_scan=rules.get("allow_subdomain_scan", False),
                allow_port_scan=rules.get("allow_port_scan", False),
                allow_active_scan=rules.get("allow_active_scan", False),
                allow_browser_crawl=rules.get("allow_browser_crawl", False),
                require_scope_check=rules.get("require_scope_check", True),
                save_all_outputs=rules.get("save_all_outputs", True),
            ),
            safety=SafetyRules(
                stop_on_scope_violation=safety.get("stop_on_scope_violation", True),
                stop_on_high_error_rate=safety.get("stop_on_high_error_rate", True),
                destructive_actions_allowed=safety.get(
                    "destructive_actions_allowed", False
                ),
            ),
            authorization=AuthorizationConfig(
                kind=str(authorization.get("kind", "unknown")),
                confirmed=bool(authorization.get("confirmed", False)),
                evidence=str(authorization.get("evidence", "")),
            ),
            policy=PolicyConfig(
                program_name=str(policy.get("program_name", target.get("name", profile_name))),
                program_url=str(policy.get("program_url", "")),
                policy_reviewed_at=str(policy.get("policy_reviewed_at", "")).strip(),
                policy_max_age_days=max(int(policy.get("policy_max_age_days", 30)), 1),
                allowed_http_methods=[str(item).upper() for item in allowed_methods],
                requires_manual_approval_for=[
                    str(item) for item in policy.get("requires_manual_approval_for", [])
                ],
                disallowed_actions=[
                    str(item) for item in policy.get("disallowed_actions", [])
                ],
                notes=[str(item) for item in policy.get("notes", [])],
                priority_categories=[
                    str(item) for item in policy.get("priority_categories", [])
                ],
                deprioritized_categories=[
                    str(item) for item in policy.get("deprioritized_categories", [])
                ],
                core_ineligible_findings=[
                    str(item) for item in policy.get("core_ineligible_findings", [])
                ],
                focus_areas=[
                    item for item in policy.get("focus_areas", []) if isinstance(item, dict)
                ],
                operator_recipes=[
                    item for item in policy.get("operator_recipes", []) if isinstance(item, dict)
                ],
            ),
            session_profiles=self._build_session_profiles(
                profile.get("session_profiles", {})
                if isinstance(profiles, dict) and profiles
                else self.raw_config.get("session_profiles", {})
            ),
            lab=self._build_lab_config(lab, target.get("base_url", "")),
        )

    def _build_session_profiles(self, data: dict) -> dict[str, SessionProfileConfig]:
        if not isinstance(data, dict):
            return {}

        profiles: dict[str, SessionProfileConfig] = {}

        for name, item in data.items():
            if not isinstance(item, dict):
                continue

            profiles[str(name)] = SessionProfileConfig(
                name=str(name),
                kind=str(item.get("kind", "generic_bearer_json_login")).strip(),
                login_url=str(item.get("login_url", "")).strip(),
                username_field=str(item.get("username_field", "email")).strip(),
                password_field=str(item.get("password_field", "password")).strip(),
                username_default=str(item.get("username_default", "")).strip(),
                password_default=str(item.get("password_default", "")).strip(),
                username_env=str(item.get("username_env", "")).strip(),
                password_env=str(item.get("password_env", "")).strip(),
                token_default=str(item.get("token_default", "")).strip(),
                token_env=str(item.get("token_env", "")).strip(),
                token_json_path=str(item.get("token_json_path", "authentication.token")).strip(),
                auth_header_name=str(item.get("auth_header_name", "Authorization")).strip(),
                auth_header_prefix=str(item.get("auth_header_prefix", "Bearer")).strip(),
                role_hint=str(item.get("role_hint", "")).strip(),
                probe_urls=[str(url).strip() for url in item.get("probe_urls", []) if str(url).strip()],
                notes=[str(note) for note in item.get("notes", [])],
            )

        return profiles

    def _build_lab_config(self, lab: dict, base_url: str) -> LabConfig | None:
        if not isinstance(lab, dict) or not lab:
            return None

        parsed = urlparse(base_url)
        published_port = int(lab.get("published_port", parsed.port or 3000))
        container_port = int(lab.get("container_port", 3000))

        return LabConfig(
            docker_image=str(lab.get("docker_image", "")).strip(),
            container_name=str(lab.get("container_name", "")).strip(),
            published_port=published_port,
            container_port=container_port,
        )

    def normalize_url(self, target: str) -> str:
        if not target:
            raise ValueError("Target cannot be empty.")

        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        return target.rstrip("/")

    def parse_target(self, target: str) -> dict:
        normalized = self.normalize_url(target)
        parsed = urlparse(normalized)

        return {
            "url": normalized,
            "scheme": parsed.scheme,
            "host": parsed.hostname or "",
            "port": parsed.port,
            "path": parsed.path or "/",
            "netloc": parsed.netloc,
        }

    def extract_host(self, target: str) -> str:
        if not target:
            raise ValueError("Target cannot be empty.")

        if target.startswith(("http://", "https://")):
            return self.parse_target(target)["host"]

        host = target.strip().split("/", 1)[0].split(":", 1)[0]
        return host.lower()

    def is_host_allowed(self, host: str) -> bool:
        host = host.lower()

        for blocked in self.config.blocked_hosts:
            if fnmatch.fnmatch(host, blocked.lower()):
                return False

        for allowed in self.config.allowed_hosts:
            if fnmatch.fnmatch(host, allowed.lower()):
                return True

        return False

    def is_url_pattern_allowed(self, url: str) -> bool:
        for pattern in self.config.allowed_url_patterns:
            if fnmatch.fnmatch(url, pattern):
                return True
        return False

    def is_path_allowed(self, path: str) -> bool:
        for blocked_prefix in self.config.blocked_path_prefixes:
            if path.startswith(blocked_prefix):
                return False
        return True

    def is_method_allowed(self, method: str) -> bool:
        normalized_method = method.upper().strip()
        return normalized_method in self.config.policy.allowed_http_methods

    def is_authorization_confirmed(self) -> bool:
        return self.config.authorization.confirmed

    def is_lab_profile(self) -> bool:
        return (
            self.config.target_type == "training-lab"
            or self.config.authorization.kind == "local_lab"
        )

    def effective_mode(self) -> str:
        return "lab" if self.is_lab_profile() else "authorized"

    def list_session_profiles(self) -> list[dict]:
        items = []

        for name, profile in sorted(self.config.session_profiles.items()):
            items.append(
                {
                    "name": name,
                    "kind": profile.kind,
                    "login_url": profile.login_url,
                    "token_env": profile.token_env,
                    "role_hint": profile.role_hint,
                    "probe_url_count": len(profile.probe_urls),
                }
            )

        return items

    def get_session_profile(self, name: str) -> SessionProfileConfig:
        if name not in self.config.session_profiles:
            available = ", ".join(sorted(self.config.session_profiles)) or "none"
            raise ValueError(
                f"Unknown session profile: {name}. Available session profiles: {available}"
            )

        return self.config.session_profiles[name]

    def requires_manual_approval(self, capability: str) -> bool:
        normalized = capability.strip().lower()
        return normalized in {
            item.strip().lower()
            for item in self.config.policy.requires_manual_approval_for
        }

    def is_target_allowed(self, target: str) -> bool:
        parsed = self.parse_target(target)

        host_allowed = self.is_host_allowed(parsed["host"])
        url_allowed = self.is_url_pattern_allowed(
            parsed["url"] + "/*"
        ) or self.is_url_pattern_allowed(parsed["url"])
        path_allowed = self.is_path_allowed(parsed["path"])

        return host_allowed and url_allowed and path_allowed

    def explain(self, target: str, method: str = "GET") -> dict:
        parsed = self.parse_target(target)

        host_allowed = self.is_host_allowed(parsed["host"])
        url_allowed = self.is_url_pattern_allowed(
            parsed["url"] + "/*"
        ) or self.is_url_pattern_allowed(parsed["url"])
        path_allowed = self.is_path_allowed(parsed["path"])
        method_allowed = self.is_method_allowed(method)
        authorization_confirmed = self.is_authorization_confirmed()
        allowed = host_allowed and url_allowed and path_allowed

        return {
            "target": target,
            "normalized_url": parsed["url"],
            "host": parsed["host"],
            "path": parsed["path"],
            "host_allowed": host_allowed,
            "url_allowed": url_allowed,
            "path_allowed": path_allowed,
            "allowed": allowed,
            "mode": self.effective_mode(),
            "target_profile": self.config.target_name,
            "profile_name": self.config.profile_name,
            "authorization_kind": self.config.authorization.kind,
            "authorization_confirmed": authorization_confirmed,
            "authorization_evidence": self.config.authorization.evidence,
            "program_name": self.config.policy.program_name,
            "program_url": self.config.policy.program_url,
            "policy_reviewed_at": self.config.policy.policy_reviewed_at,
            "policy_max_age_days": self.config.policy.policy_max_age_days,
            "policy_status": self.policy_status(),
            "method": method.upper(),
            "method_allowed": method_allowed,
            "allowed_http_methods": self.config.policy.allowed_http_methods,
            "session_profiles": self.list_session_profiles(),
        }

    def policy_snapshot(self) -> dict:
        return {
            "profile_name": self.config.profile_name,
            "target_name": self.config.target_name,
            "target_type": self.config.target_type,
            "base_url": self.config.base_url,
            "mode": self.effective_mode(),
            "program_name": self.config.policy.program_name,
            "program_url": self.config.policy.program_url,
            "policy_reviewed_at": self.config.policy.policy_reviewed_at,
            "policy_max_age_days": self.config.policy.policy_max_age_days,
            "policy_status": self.policy_status(),
            "authorization": {
                "kind": self.config.authorization.kind,
                "confirmed": self.config.authorization.confirmed,
                "evidence": self.config.authorization.evidence,
            },
            "allowed_http_methods": self.config.policy.allowed_http_methods,
            "requires_manual_approval_for": self.config.policy.requires_manual_approval_for,
            "disallowed_actions": self.config.policy.disallowed_actions,
            "notes": self.config.policy.notes,
            "priority_categories": self.config.policy.priority_categories,
            "deprioritized_categories": self.config.policy.deprioritized_categories,
            "core_ineligible_findings": self.config.policy.core_ineligible_findings,
            "focus_areas": self.config.policy.focus_areas,
            "operator_recipes": self.config.policy.operator_recipes,
            "session_profiles": self.list_session_profiles(),
            "allow_port_scan": self.config.rules.allow_port_scan,
        }

    def policy_status(self, now: date | datetime | None = None) -> dict:
        current_date = self._normalize_policy_date(now) or datetime.now(timezone.utc).date()
        reviewed_at_raw = self.config.policy.policy_reviewed_at
        reviewed_at_date = self._parse_policy_date(reviewed_at_raw)
        max_age_days = max(int(self.config.policy.policy_max_age_days), 1)
        age_days = None
        is_stale = True
        state = "unknown"

        if reviewed_at_date is not None:
            age_days = max((current_date - reviewed_at_date).days, 0)
            is_stale = age_days > max_age_days
            state = "stale" if is_stale else "fresh"
        elif not reviewed_at_raw:
            state = "missing_review_date"
        else:
            state = "invalid_review_date"

        return {
            "profile_name": self.config.profile_name,
            "program_name": self.config.policy.program_name,
            "program_url": self.config.policy.program_url,
            "policy_reviewed_at": reviewed_at_raw or "",
            "policy_max_age_days": max_age_days,
            "age_days": age_days,
            "is_stale": is_stale,
            "state": state,
            "strict_mode_ready": not is_stale,
        }

    def _parse_policy_date(self, value: str) -> date | None:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            return date.fromisoformat(raw)
        except ValueError:
            return None

    def _normalize_policy_date(self, value: date | datetime | None) -> date | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.date()
        return value

    def assert_port_scan_allowed(self, target: str) -> None:
        host = self.extract_host(target)
        if not self.is_host_allowed(host):
            raise PermissionError(f"Port scan target host is out of scope: {host}")

        if not self.config.rules.allow_port_scan:
            raise PermissionError(
                "Port scanning is disabled for the selected profile."
            )

        if not self.is_authorization_confirmed():
            raise PermissionError(
                "Authorization is not confirmed for the selected profile."
            )

        disallowed = {
            item.strip().lower()
            for item in self.config.policy.disallowed_actions
        }
        if "port_scanning" in disallowed:
            raise PermissionError(
                "Port scanning is explicitly disallowed by policy for the selected profile."
            )

    def assert_allowed(self, target: str) -> None:
        result = self.explain(target)

        if not result["allowed"]:
            raise PermissionError(f"Target is out of scope: {result}")

    def assert_authorized(self, method: str = "GET") -> None:
        if not self.is_authorization_confirmed():
            raise PermissionError(
                "Authorization is not confirmed for the selected profile."
            )

        if not self.is_method_allowed(method):
            raise PermissionError(
                f"HTTP method is not allowed by policy: {method.upper()}"
            )

    def assert_action_allowed(self, target: str, method: str = "GET") -> None:
        self.assert_allowed(target)
        self.assert_authorized(method=method)


if __name__ == "__main__":
    scope = ScopeManager()

    test_targets = [
        "http://localhost:3000",
        "http://localhost:3000/search",
        "http://localhost:3000/payment",
        "http://127.0.0.1:3000",
        "https://example.com",
    ]

    print("Active profile:", scope.get_active_profile_name())
    print("Profiles:", scope.list_profiles())

    for target in test_targets:
        print(scope.explain(target))
