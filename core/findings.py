from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import json


@dataclass
class NormalizedFinding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    target: str
    source: str
    matched_at: str
    description: str
    evidence: list[str]
    recommendation: str
    raw: dict

    def to_dict(self) -> dict:
        return asdict(self)


class FindingNormalizer:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.parsed_dir = self.run_dir / "parsed"
        self.output_path = self.parsed_dir / "normalized_findings.json"

    def normalize(self) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []

        findings.extend(self._normalize_nuclei())
        findings.extend(self._normalize_httpx())
        findings.extend(self._normalize_katana())
        findings.extend(self._normalize_internal_crawl())

        deduped = self._deduplicate(findings)

        self.output_path.write_text(
            json.dumps(
                [finding.to_dict() for finding in deduped],
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        return deduped

    def _normalize_nuclei(self) -> list[NormalizedFinding]:
        path = self.parsed_dir / "pd_nuclei_findings.json"

        if not path.exists():
            return []

        data = self._read_json(path)
        raw_findings = data.get("in_scope_findings", [])

        findings: list[NormalizedFinding] = []

        for raw in raw_findings:
            info = raw.get("info", {})
            template_id = raw.get("template-id") or raw.get("templateID") or raw.get("id") or "nuclei-finding"

            title = info.get("name") or template_id
            severity = info.get("severity", "unknown")
            description = info.get("description") or f"Nuclei matched template: {template_id}"

            matched_at = (
                raw.get("matched-at")
                or raw.get("matched")
                or raw.get("host")
                or data.get("target")
                or "unknown"
            )

            evidence = []

            if raw.get("extracted-results"):
                extracted = raw.get("extracted-results")
                if isinstance(extracted, list):
                    evidence.extend(str(item) for item in extracted)
                else:
                    evidence.append(str(extracted))

            if raw.get("matcher-name"):
                evidence.append(f"Matcher: {raw.get('matcher-name')}")

            if raw.get("template"):
                evidence.append(f"Template: {raw.get('template')}")

            if not evidence:
                evidence.append(f"Nuclei produced a match for: {matched_at}")

            recommendation = self._recommendation_for_severity(severity)

            findings.append(
                NormalizedFinding(
                    finding_id=self._make_id("nuclei", str(template_id), str(matched_at)),
                    title=title,
                    severity=severity,
                    confidence="medium",
                    target=data.get("target", matched_at),
                    source="nuclei",
                    matched_at=str(matched_at),
                    description=description,
                    evidence=evidence,
                    recommendation=recommendation,
                    raw=raw,
                )
            )

        return findings

    def _normalize_httpx(self) -> list[NormalizedFinding]:
        path = self.parsed_dir / "pd_httpx_outputs.json"

        if not path.exists():
            return []

        data = self._read_json(path)
        outputs = data.get("in_scope_outputs", [])

        findings: list[NormalizedFinding] = []

        for item in outputs:
            item_str = str(item)

            findings.append(
                NormalizedFinding(
                    finding_id=self._make_id("httpx", item_str),
                    title="HTTP service detected",
                    severity="info",
                    confidence="high",
                    target=data.get("target", item_str),
                    source="httpx",
                    matched_at=item_str,
                    description="An in-scope HTTP service responded during probing.",
                    evidence=[item_str],
                    recommendation="Use this service as a valid recon target for deeper authorized analysis.",
                    raw={"output": item},
                )
            )

        return findings

    def _normalize_katana(self) -> list[NormalizedFinding]:
        path = self.parsed_dir / "pd_katana_outputs.json"

        if not path.exists():
            return []

        data = self._read_json(path)
        outputs = data.get("in_scope_outputs", [])

        findings: list[NormalizedFinding] = []

        for item in outputs:
            item_str = str(item)

            findings.append(
                NormalizedFinding(
                    finding_id=self._make_id("katana", item_str),
                    title="In-scope endpoint discovered",
                    severity="info",
                    confidence="medium",
                    target=data.get("target", item_str),
                    source="katana",
                    matched_at=item_str,
                    description="Katana discovered an in-scope URL or endpoint during crawling.",
                    evidence=[item_str],
                    recommendation="Review the endpoint for parameters, forms, API behavior, and authorization boundaries.",
                    raw={"output": item},
                )
            )

        return findings

    def _normalize_internal_crawl(self) -> list[NormalizedFinding]:
        path = self.parsed_dir / "crawl_result.json"

        if not path.exists():
            return []

        data = self._read_json(path)

        findings: list[NormalizedFinding] = []

        for script in data.get("scripts", []):
            script_str = str(script)

            findings.append(
                NormalizedFinding(
                    finding_id=self._make_id("internal-crawl-script", script_str),
                    title="JavaScript asset discovered",
                    severity="info",
                    confidence="medium",
                    target=data.get("start_url", script_str),
                    source="internal-crawl",
                    matched_at=script_str,
                    description="The internal crawler discovered a JavaScript asset.",
                    evidence=[script_str],
                    recommendation="Review JavaScript assets for API endpoints, source maps, secrets, routes, and client-side security logic.",
                    raw={"script": script},
                )
            )

        for form in data.get("forms", []):
            action = str(form.get("action", "unknown"))

            findings.append(
                NormalizedFinding(
                    finding_id=self._make_id("internal-crawl-form", action),
                    title="HTML form discovered",
                    severity="info",
                    confidence="medium",
                    target=data.get("start_url", action),
                    source="internal-crawl",
                    matched_at=action,
                    description="The internal crawler discovered an HTML form.",
                    evidence=[
                        f"Action: {action}",
                        f"Method: {form.get('method', 'unknown')}",
                        f"Inputs: {form.get('inputs', [])}",
                    ],
                    recommendation="Review the form for input validation, authentication, authorization, CSRF, and business logic issues.",
                    raw=form,
                )
            )

        return findings

    def _deduplicate(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        seen = set()
        deduped = []

        for finding in findings:
            key = finding.finding_id

            if key in seen:
                continue

            seen.add(key)
            deduped.append(finding)

        return deduped

    def _read_json(self, path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _make_id(self, *parts: str) -> str:
        raw = "|".join(parts)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"finding-{digest}"

    def _recommendation_for_severity(self, severity: str) -> str:
        normalized = severity.lower()

        if normalized in {"critical", "high"}:
            return "Manually verify impact, collect strong evidence, and prepare a high-quality responsible disclosure report."

        if normalized == "medium":
            return "Manually validate exploitability and business impact before reporting."

        if normalized == "low":
            return "Confirm whether this has security impact under the program policy before reporting."

        return "Use this as recon evidence. Do not submit as a vulnerability unless manual validation confirms security impact."


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python core/findings.py <run_dir>")
        raise SystemExit(1)

    normalizer = FindingNormalizer(sys.argv[1])
    normalized = normalizer.normalize()

    print(f"Normalized findings: {len(normalized)}")
    print(f"Output: {normalizer.output_path}")