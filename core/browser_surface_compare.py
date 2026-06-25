from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import re

from core.browser_evidence import check_browser_runtime
from core.run_context import RunContext
from core.scope import ScopeManager


AUTH_LIKE_PATTERN = re.compile(r"(sess|auth|token|jwt|sid|csrf|xsrf|remember|login)", re.IGNORECASE)


@dataclass
class BrowserSurfaceCookie:
    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserSurfaceSnapshot:
    requested_target: str
    final_url: str
    page_title: str
    capture_error: str | None
    cookie_count: int
    auth_cookie_count: int
    local_storage_key_count: int
    session_storage_key_count: int
    auth_storage_key_count: int
    cookies: list[dict]
    local_storage_keys: list[str]
    session_storage_keys: list[str]
    notes: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserSurfaceHypothesis:
    hypothesis_id: str
    severity: str
    title: str
    rationale: str
    affected_surfaces: list[str]
    supporting_signals: list[str]
    safe_next_steps: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserSurfaceCompareSummary:
    profile_name: str
    program_name: str
    generated_at: str
    compared_surface_count: int
    failed_surface_count: int
    total_cookie_count: int
    total_auth_cookie_count: int
    total_auth_storage_key_count: int
    hypothesis_count: int
    surfaces: list[dict]
    hypotheses: list[dict]
    json_path: str
    markdown_path: str

    def to_dict(self) -> dict:
        return asdict(self)


class BrowserSurfaceCompareRunner:
    def __init__(self, scope: ScopeManager, run_context: RunContext):
        self.scope = scope
        self.ctx = run_context
        self.parsed_dir = Path(run_context.parsed_dir)
        self.reports_dir = Path(run_context.reports_dir)
        self.output_json_path = self.parsed_dir / "browser_surface_compare.json"
        self.output_markdown_path = self.reports_dir / "browser_surface_compare.md"

    def run(self, targets: list[str], timeout_ms: int = 15000) -> BrowserSurfaceCompareSummary:
        runtime = check_browser_runtime()
        if not runtime.available:
            raise RuntimeError(runtime.message)

        snapshots = self._capture_snapshots(targets, timeout_ms=timeout_ms)
        hypotheses = self._build_hypotheses(snapshots)
        summary = BrowserSurfaceCompareSummary(
            profile_name=self.ctx.profile_name,
            program_name=self.ctx.program_name,
            generated_at=datetime.now(timezone.utc).isoformat(),
            compared_surface_count=len(snapshots),
            failed_surface_count=sum(1 for item in snapshots if item.capture_error),
            total_cookie_count=sum(item.cookie_count for item in snapshots),
            total_auth_cookie_count=sum(item.auth_cookie_count for item in snapshots),
            total_auth_storage_key_count=sum(item.auth_storage_key_count for item in snapshots),
            hypothesis_count=len(hypotheses),
            surfaces=[item.to_dict() for item in snapshots],
            hypotheses=[item.to_dict() for item in hypotheses],
            json_path=str(self.output_json_path),
            markdown_path=str(self.output_markdown_path),
        )

        self.output_json_path.write_text(
            json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self.output_markdown_path.write_text(
            self._build_markdown(summary),
            encoding="utf-8",
        )
        self.ctx.add_event(
            event_type="browser_surface_compare_completed",
            message="Browser surface comparison completed.",
            data={
                "compared_surface_count": summary.compared_surface_count,
                "total_cookie_count": summary.total_cookie_count,
                "total_auth_cookie_count": summary.total_auth_cookie_count,
                "total_auth_storage_key_count": summary.total_auth_storage_key_count,
                "hypothesis_count": summary.hypothesis_count,
            },
        )
        return summary

    def _capture_snapshots(self, targets: list[str], timeout_ms: int) -> list[BrowserSurfaceSnapshot]:
        from playwright.sync_api import sync_playwright

        snapshots: list[BrowserSurfaceSnapshot] = []

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)

            for target in targets:
                self.scope.assert_action_allowed(target, method="GET")
                context = browser.new_context(
                    viewport={"width": 1440, "height": 1024},
                    ignore_https_errors=True,
                )
                page = context.new_page()

                try:
                    page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                    page.wait_for_timeout(1200)
                    final_url = page.url
                    page_title = page.title() or ""
                    cookies = [
                        BrowserSurfaceCookie(
                            name=str(item.get("name", "")),
                            domain=str(item.get("domain", "")),
                            path=str(item.get("path", "")),
                            secure=bool(item.get("secure", False)),
                            http_only=bool(item.get("httpOnly", False)),
                            same_site=str(item.get("sameSite", "")),
                        )
                        for item in context.cookies()
                    ]
                    local_storage_keys = page.evaluate("() => Object.keys(window.localStorage || {})")
                    session_storage_keys = page.evaluate("() => Object.keys(window.sessionStorage || {})")
                    notes = []
                    if final_url != target:
                        notes.append(f"redirected_to:{final_url}")

                    snapshots.append(
                        BrowserSurfaceSnapshot(
                            requested_target=target,
                            final_url=final_url,
                            page_title=page_title,
                            capture_error=None,
                            cookie_count=len(cookies),
                            auth_cookie_count=sum(1 for item in cookies if AUTH_LIKE_PATTERN.search(item.name or "")),
                            local_storage_key_count=len(local_storage_keys),
                            session_storage_key_count=len(session_storage_keys),
                            auth_storage_key_count=sum(
                                1
                                for key in [*local_storage_keys, *session_storage_keys]
                                if AUTH_LIKE_PATTERN.search(str(key))
                            ),
                            cookies=[item.to_dict() for item in cookies],
                            local_storage_keys=[str(item) for item in local_storage_keys],
                            session_storage_keys=[str(item) for item in session_storage_keys],
                            notes=notes,
                        )
                    )
                except Exception as exc:
                    snapshots.append(
                        BrowserSurfaceSnapshot(
                            requested_target=target,
                            final_url=target,
                            page_title="",
                            capture_error=str(exc),
                            cookie_count=0,
                            auth_cookie_count=0,
                            local_storage_key_count=0,
                            session_storage_key_count=0,
                            auth_storage_key_count=0,
                            cookies=[],
                            local_storage_keys=[],
                            session_storage_keys=[],
                            notes=[f"capture_failed:{exc}"],
                        )
                    )
                finally:
                    context.close()

            browser.close()

        return snapshots

    def _build_hypotheses(self, snapshots: list[BrowserSurfaceSnapshot]) -> list[BrowserSurfaceHypothesis]:
        hypotheses: list[BrowserSurfaceHypothesis] = []

        for snapshot in snapshots:
            public_surface = self._is_public_surface(snapshot.final_url)
            auth_cookie_names = [
                str(item.get("name", ""))
                for item in snapshot.cookies
                if AUTH_LIKE_PATTERN.search(str(item.get("name", "")))
            ]

            if public_surface and snapshot.auth_cookie_count:
                hypotheses.append(
                    BrowserSurfaceHypothesis(
                        hypothesis_id=f"BSC-{len(hypotheses)+1}",
                        severity="medium" if snapshot.requested_target != snapshot.final_url else "low",
                        title="Browser receives auth-like cookies on anonymous public surface",
                        rationale=(
                            f"Browser context for `{snapshot.final_url}` received auth-like cookies `{auth_cookie_names}` "
                            "without a completed login flow."
                        ),
                        affected_surfaces=[snapshot.final_url],
                        supporting_signals=[
                            f"auth_cookie_count={snapshot.auth_cookie_count}",
                            f"redirected={snapshot.requested_target != snapshot.final_url}",
                            f"page_title={snapshot.page_title}",
                        ],
                        safe_next_steps=[
                            "Compare this browser state against the login page and a second public page.",
                            "Review whether these cookies are anonymous bootstrap state or a stronger session construct.",
                            "Do not attempt active cookie tampering without explicit policy allowance.",
                        ],
                    )
                )

            if snapshot.auth_storage_key_count:
                hypotheses.append(
                    BrowserSurfaceHypothesis(
                        hypothesis_id=f"BSC-{len(hypotheses)+1}",
                        severity="medium",
                        title="Anonymous browser surface populates auth-like storage keys",
                        rationale=(
                            f"Browser storage on `{snapshot.final_url}` exposed auth-like keys in local/session storage."
                        ),
                        affected_surfaces=[snapshot.final_url],
                        supporting_signals=[
                            f"auth_storage_key_count={snapshot.auth_storage_key_count}",
                            f"local_storage_key_count={snapshot.local_storage_key_count}",
                            f"session_storage_key_count={snapshot.session_storage_key_count}",
                        ],
                        safe_next_steps=[
                            "Review whether the keys represent anonymous telemetry or stronger session metadata.",
                            "Keep this as a storage-policy review lead until semantics are understood.",
                        ],
                    )
                )

        if len(snapshots) >= 2:
            cookie_sets = {
                item.final_url: {str(cookie.get("name", "")) for cookie in item.cookies}
                for item in snapshots
            }
            intersection = set.intersection(*(value for value in cookie_sets.values())) if cookie_sets else set()
            auth_intersection = sorted(
                [
                    name
                    for name in intersection
                    if AUTH_LIKE_PATTERN.search(name)
                ]
            )
            if auth_intersection:
                hypotheses.append(
                    BrowserSurfaceHypothesis(
                        hypothesis_id=f"BSC-{len(hypotheses)+1}",
                        severity="medium",
                        title="Same auth-like cookies persist across multiple anonymous surfaces",
                        rationale=(
                            f"Anonymous browser visits shared auth-like cookies across surfaces: `{auth_intersection}`."
                        ),
                        affected_surfaces=[item.final_url for item in snapshots],
                        supporting_signals=[f"shared_auth_cookies={auth_intersection}"],
                        safe_next_steps=[
                            "Compare root, login, and documentation surfaces to see if the cookie semantics change.",
                            "Review whether public routes are participating in a broader session bootstrap than expected.",
                        ],
                    )
                )

        return hypotheses

    def _build_markdown(self, summary: BrowserSurfaceCompareSummary) -> str:
        lines: list[str] = []
        lines.append("# Browser Surface Compare")
        lines.append("")
        lines.append("> Read-only browser comparison across public surfaces. This does not confirm a vulnerability.")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Profile:** `{summary.profile_name}`")
        lines.append(f"- **Program:** `{summary.program_name}`")
        lines.append(f"- **Generated At:** `{summary.generated_at}`")
        lines.append(f"- **Compared Surfaces:** `{summary.compared_surface_count}`")
        lines.append(f"- **Failed Surfaces:** `{summary.failed_surface_count}`")
        lines.append(f"- **Total Cookies:** `{summary.total_cookie_count}`")
        lines.append(f"- **Total Auth-Like Cookies:** `{summary.total_auth_cookie_count}`")
        lines.append(f"- **Total Auth-Like Storage Keys:** `{summary.total_auth_storage_key_count}`")
        lines.append(f"- **Hypotheses:** `{summary.hypothesis_count}`")
        lines.append("")
        lines.append("## Surfaces")
        lines.append("")
        for index, item in enumerate(summary.surfaces, start=1):
            lines.append(f"### B{index}. {item.get('final_url')}")
            lines.append("")
            lines.append(f"- **Requested Target:** `{item.get('requested_target', '')}`")
            lines.append(f"- **Title:** `{item.get('page_title', '')}`")
            lines.append(f"- **Capture Error:** `{item.get('capture_error')}`")
            lines.append(f"- **Cookies:** `{item.get('cookie_count', 0)}`")
            lines.append(f"- **Auth-Like Cookies:** `{item.get('auth_cookie_count', 0)}`")
            lines.append(f"- **Local Storage Keys:** `{item.get('local_storage_key_count', 0)}`")
            lines.append(f"- **Session Storage Keys:** `{item.get('session_storage_key_count', 0)}`")
            lines.append(f"- **Auth-Like Storage Keys:** `{item.get('auth_storage_key_count', 0)}`")
            lines.append(f"- **Notes:** `{item.get('notes', [])}`")
            lines.append("")
        lines.append("## Hypotheses")
        lines.append("")
        if not summary.hypotheses:
            lines.append("No browser-specific hypotheses were generated.")
            lines.append("")
        else:
            for item in summary.hypotheses:
                lines.append(f"### {item.get('hypothesis_id')} — {item.get('title')}")
                lines.append("")
                lines.append(f"- **Severity:** `{item.get('severity', 'unknown')}`")
                lines.append(f"- **Affected Surfaces:** `{item.get('affected_surfaces', [])}`")
                lines.append("")
                lines.append(item.get("rationale", ""))
                lines.append("")
                lines.append("Supporting signals:")
                for signal in item.get("supporting_signals", []):
                    lines.append(f"- {signal}")
                lines.append("")
                lines.append("Safe next steps:")
                for step in item.get("safe_next_steps", []):
                    lines.append(f"- {step}")
                lines.append("")
        lines.append("## Safety Notes")
        lines.append("")
        lines.append("- Browser comparison is a passive review aid, not proof of exploitability.")
        lines.append("- Do not attempt interactive abuse, login forcing, or session tampering unless the selected policy explicitly allows it.")
        lines.append("- Keep evidence minimal and redacted.")
        lines.append("")
        return "\n".join(lines)

    def _is_public_surface(self, url: str) -> bool:
        lowered = url.lower()
        return any(
            marker in lowered
            for marker in (
                "/developers/",
                "/docs/",
                "/documentation",
                "/downloads",
                "/help",
                "/learn",
                "/blog",
                "/login",
                "www.",
            )
        )
