# Example Program Policy Notes

Program URL: https://bugbounty.example.com/program

In scope:
- https://target.example.com
- Read-only validation against explicitly listed web assets

Out of scope:
- Third-party services
- Production user accounts
- Denial of service
- Brute force
- Port scanning unless explicitly approved

Rules:
- Use only safe read-only requests by default
- Authenticated testing requires prior approval and dedicated test accounts
- Browser screenshots require manual approval
- Keep evidence minimal and redacted
- Never submit automatically
