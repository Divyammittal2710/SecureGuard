# Snyk Baseline Scan — SecureGuard
**Scan Date:** 2026-06-08  
**Tool:** Snyk (app.snyk.io)  
**Repo:** Divyammittal2710/SecureGuard  

---

## Summary

| Project | Critical | High | Medium | Low | Status |
|---|---|---|---|---|---|
| backend/requirements.txt | 1 | 1 | 2 | 0 | ✅ All fixed |
| backend/Dockerfile | 0 | 0 | 0 | 44 | ⚠️ Accepted (base image) |
| frontend/Dockerfile | 0 | 0 | 0 | 44 | ⚠️ Accepted (base image) |
| Code analysis | 0 | 0 | 0 | 1 | ⚠️ Accepted (low risk) |

---

## backend/requirements.txt — Fixed

All 4 findings were transitive dependencies (pulled in by `fastapi` and `uvicorn`, not declared directly).

### 🔴 Critical — HTTP Request Smuggling
- **Package:** `h11@0.14.0`
- **CVE/CWE:** CWE-444
- **CVSS:** 9.3
- **Description:** Malformed HTTP requests could allow an attacker to smuggle requests past a reverse proxy, potentially bypassing security controls or poisoning shared caches.
- **Fix:** Upgraded to `h11>=0.16.0`

### 🟠 High — Race Condition
- **Package:** `anyio@3.7.1`
- **CVE/CWE:** CWE-362
- **CVSS:** 8.3
- **Description:** A race condition in async task handling could allow an attacker to exploit timing windows in concurrent request processing.
- **Fix:** Upgraded to `anyio>=4.4.0` (major version upgrade)

### 🟡 Medium — Infinite Loop (DoS)
- **Package:** `zipp@3.15.0`
- **CVE/CWE:** CWE-835
- **CVSS:** 6.9
- **Description:** A crafted zip file could cause an infinite loop, leading to denial of service.
- **Fix:** Upgraded to `zipp>=3.19.1`

### 🟡 Medium — ReDoS
- **Package:** `idna@3.10`
- **CVE/CWE:** CWE-1333
- **CVSS:** 5.1
- **Description:** A malicious internationalized domain name could trigger catastrophic regex backtracking, causing denial of service.
- **Fix:** Upgraded to `idna>=3.15`

---

## Dockerfile Findings — Accepted (Not Fixed)

Both `backend/Dockerfile` and `frontend/Dockerfile` use `python:3.11-slim` as the base image, which carries **44 Low severity OS-level findings** each.

**Decision:** Accepted as-is for the following reasons:
- All findings are Low severity with no known active exploits
- Fixes require upgrading the base OS image, which is outside the scope of Week 1
- Azure Container Apps applies its own security patching at the infrastructure level

**Action:** Review and update base image to `python:3.11-slim` latest digest in Week 2.

---

## Remediation Applied

The following lines were added to `backend/requirements.txt` to pin safe minimum versions:

```
# Security fixes - pinned transitive dependencies (Snyk baseline 2026-06-08)
h11>=0.16.0
anyio>=4.4.0
zipp>=3.19.1
idna>=3.15
```

**Verified installed versions after fix:**
- `anyio==4.13.0`
- `h11==0.16.0`
- `idna==3.18`
- `zipp==4.1.0`

---

## Remaining Open Items

| Finding | Location | Severity | Reason Not Fixed |
|---|---|---|---|
| 44 OS-level CVEs | backend/Dockerfile | Low | Base image — deferred to Week 2 |
| 44 OS-level CVEs | frontend/Dockerfile | Low | Base image — deferred to Week 2 |
| 1 Code analysis finding | Code analysis | Low | Low risk, no immediate impact |
