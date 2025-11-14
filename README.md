# 🔒 Private API Vulnerability Research — Phone Number–Based User Lookup (1B+ Downloads App)

> **Responsible disclosure:** This issue was responsibly disclosed to the vendor and has been patched.  
> The content below is intentionally **non-actionable** and intended for defensive, educational, and remediation purposes only. Low-level exploit code, exact packet headers, command IDs, and step-by-step instructions that would enable unauthorized access or mass enumeration have been omitted.

---

## Table of Contents

- [Executive summary](#executive-summary)  
- [Vulnerability details](#vulnerability-details)  
- [High-level research methodology](#high-level-research-methodology)  
- [Protocol analysis (high-level)](#protocol-analysis-high-level)  
- [Threat & impact analysis](#threat--impact-analysis)  
- [Safe verification guidance](#safe-verification-guidance)  
- [Mitigations & recommendations](#mitigations--recommendations)  
- [Disclosure timeline](#disclosure-timeline)  
- [Contact & reporting](#contact--reporting)  
- [License](#license)

---

## Executive summary

A critical vulnerability was discovered in a major mobile application (1,000,000,000+ installs). The app exposed a private transport endpoint using a custom binary protocol that, due to missing authentication and insufficient authorization checks, allowed queries that revealed sensitive user profile information when provided with phone numbers.

- **Severity:** Critical (CVSS-style assessment: high impact, low attacker complexity)  
- **Impact:** Potential mass enumeration of phone numbers, profile data leakage, cross-service correlation  
- **Status:** Patched following responsible disclosure

> This README intentionally omits exploit-level artifacts. It documents the findings at a level appropriate for defenders and engineers.

---

## Vulnerability details

### Classification
- **Primary issue:** Improper authorization (CWE-285)  
- **Secondary issue:** Exposure of private personal information (CWE-359)

### Affected surface (high level)
- **Transport:** Custom TCP-based transport (not standard HTTPS API)  
- **Protocol:** Compact binary framing and application-level messages  
- **Authentication:** Absent or insufficient on the affected endpoint(s)  
- **Inputs of concern:** Phone numbers passed to a lookup/lookup-like operation

### Observed impact vectors
| Impact area | Description |
|-------------|-------------|
| Privacy exposure | Profile metadata (e.g., display name, handle, limited profile fields) could be disclosed by lookup responses |
| Enumeration scale | The endpoint could be invoked programmatically at scale without adequate throttling |
| Detection avoidance | Custom binary transport reduced the effectiveness of standard HTTP-based monitoring and tooling |
| Correlation | Returned metadata enabled linking of phone numbers to accounts across services |

---

## High-level research methodology

**Purpose:** To characterize the vulnerability and produce defensive recommendations. Activities were limited to safe, non-destructive analysis and responsible verification.

1. **Traffic discovery (passive & controlled):**  
   - Observed the app’s network behavior to identify non-HTTP transports and long-lived socket sessions.  
   - Collected high-level metadata (endpoints, message timing, response sizes) without executing abusive queries.

2. **Behavioral characterization:**  
   - Sent minimal, non-sensitive probes to determine whether requests required authentication and how the server responded to unauthenticated queries.  
   - Observed session lifecycle and whether responses leaked existence/identity signals.

3. **High-level protocol modeling (defensive):**  
   - Constructed an abstract model of message framing and session flow to inform mitigations. Low-level byte sequences and command codes were not published.

4. **Responsible reporting and verification:**  
   - Shared findings privately with the vendor, supplied limited artifacts under an NDA as needed for remediation, and coordinated a patch rollout.

> All testing adhered to responsible disclosure principles. No mass scans, bulk enumeration, or harmful payloads were made public.

---

## Protocol analysis (high-level)

> Note: The contents below are intentionally high-level and non-actionable. They summarize structural observations useful for defenders.

- The app uses a **persistent socket** (long-lived TCP connection) carrying framed binary messages rather than HTTP(S) requests.
- Messages are composed of a small header and a variable payload. The header conveys framing/length and an operation identifier; the payload carries encoded fields.
- Sessions appear to be **sequence-based** (requests tracked within a session) and the protocol includes an integrity check at the message level.
- Transport encryption (TLS) was not consistently applied to the affected private endpoint in the observed version; lack of transport encryption increased the risk of passive interception.
- The server returned distinguishable responses for different probe types, which allowed confirmation of user existence/lookup success in some cases — this is a classic information disclosure fingerprint.

---

## Threat & impact analysis

### Attack surface and likely threats
- **Remote enumeration:** Adversary supplies phone numbers programmatically and receives responses indicating presence or profile data.
- **Mass harvesting:** Without rate limits or authorization checks, enumeration can be scaled using automated tooling.
- **Targeted reconnaissance:** Leaked profile metadata can aid social engineering or more targeted attacks.
- **Operational stealth:** Non-HTTP traffic can be missed by systems tuned primarily for web APIs, reducing detection likelihood.

### Risk summary
- **Scale:** High — affects a very large user population when present.  
- **Exploit difficulty:** Low-to-moderate — mainly depends on the presence/absence of authentication and rate-limiting.  
- **Detectability:** Moderate — requires domain-specific logging or network inspection to surface.

---

## Safe verification guidance (for vendors / defenders)

If you are responsible for remediating or validating systems, use the following safe, ethical verification steps:

1. **Review server-side access control:**  
   - Audit handlers for the private transport endpoint to ensure they require and validate authentication tokens and user context before returning profile data.

2. **Run limited, logged tests:**  
   - Perform a tiny set of controlled, authorized probe requests from a lab environment (not production targets) to verify that unauthenticated requests fail or return only non-sensitive responses.

3. **Enable and inspect detailed telemetry:**  
   - Add request-level logs (authenticated identity, device id, request origin, timestamp) and search for unusual access patterns or high-volume clients.

4. **Check transport security:**  
   - Ensure TLS is enforced for all transports and certificate validation is performed on the client. Encrypted channels reduce passive eavesdropping risk.

5. **Rate limit and harden responses:**  
   - Apply strong per-account, per-device, and per-IP rate limits. Avoid responses that clearly differentiate “found” vs “not found” for unauthenticated callers.

6. **Engage incident response / CERT:**  
   - If you discover suspected abuse in production, escalate per your incident response procedures and notify affected stakeholders.

---

## Mitigations & recommendations

These recommendations are defensive and safe to implement.

### Authentication & authorization
- **Require robust authentication** for all private endpoints. Do not accept unauthenticated queries that can reveal user data.
- **Validate request context** on every request — ensure that the requesting account has permission to query the target resource.
- **Use short-lived, scoped tokens** and bind them to device/session identifiers.

### Transport security
- **Enforce TLS (1.2 minimum, 1.3 preferred)** on all communications, including non-HTTP transports.
- **Employ certificate pinning** for mobile clients where appropriate, and ensure secure key management.

### Response hardening & rate limiting
- **Return minimal information** to unauthenticated or unauthorised callers. Avoid binary signals that disclose existence.
- **Apply adaptive rate limits** (per user, per device, per IP) and block or challenge high-rate clients.
- **Introduce progressive throttling** and abuse traps to detect automated enumeration.

### Monitoring & detection
- **Log enriched context** (user id, device id, token, client IP) for each request.
- **Alert on enumeration patterns** (e.g., many sequential phone lookups from same IP or token).
- **Integrate behavioral detection** (ML or rule-based) to flag large-scale, distributed scanning.

### Development lifecycle
- **Threat model custom transports** and include protocol-level controls in design reviews.
- **Test for abuse cases** during CI: run fuzz tests and anti-enumeration checks.
- **Engage third-party security review** or bug bounty programs to surface blind spots.

---

## Disclosure timeline (redacted)

- **Discovery:** [redacted]  
- **Vendor notified:** [redacted]  
- **Patch deployed:** [redacted]  
- **Public summary released:** After coordinated remediation

> Detailed timestamps and sensitive artifacts were withheld from public disclosure to prevent adversarial reuse.

---

## Contact & reporting

If you are a vendor, CERT, or authorized incident responder and need access to sensitive artifacts to remediate this issue, please request them through the original researcher's responsible disclosure contact or provide an NDAs and proof of authorization. For general questions about defensive implementation, open an issue on this repository.

---

## License

This document is provided for defensive and educational purposes under the **MIT License**. No exploit code or operational recipes for abuse are provided here.

---
