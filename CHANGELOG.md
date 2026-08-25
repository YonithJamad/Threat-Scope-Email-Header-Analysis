# Changelog

All notable changes to the **ThreatScope** platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## Changelog Purpose
The purpose of this document is to provide a standardized, transparent, and chronological audit trail of all features, enhancements, bug fixes, breaking changes, and security updates introduced in each release of ThreatScope.

---

## Versioning Convention
ThreatScope follows **Semantic Versioning (SemVer 2.0.0)** format `MAJOR.MINOR.PATCH`:
* **MAJOR:** Incompatible API changes, major architectural redesigns, or breaking modifications to heuristic scoring formulas.
* **MINOR:** Backwards-compatible new features, additional heuristic checkpoints, new UI themes, or intelligence integrations.
* **PATCH:** Backwards-compatible bug fixes, security patches, performance optimizations, and documentation updates.

---

## Release History

```
+-------------------------------------------------------------------------------+
| Version      | Release Date   | Release Title / Milestone                     |
+-------------------------------------------------------------------------------+
| 2.0.0        | 2026-08-25     | 19-Rule Heuristic Engine & Complete Redesign  |
| 1.5.0        | 2026-08-22     | Outlook MSG Ingestion & Leaflet Mapping       |
| 1.0.0        | 2026-08-20     | Initial Production Release (Raw Headers & Geo)|
| 0.1.0-alpha  | 2026-08-15     | Initial Prototype & Proof of Concept          |
+-------------------------------------------------------------------------------+
```

---

## [2.0.0] - 2026-08-25

### Release Title
**ThreatScope 2.0: 19-Rule Deterministic Heuristic Engine, Full Forensics Suite & Cyber-Defense UI**

### Added
* **19-Rule Heuristic Security Engine:** Complete deterministic evaluation model across Checkpoints A (Identity), B (Content), C (Files), and D (Threat Intel).
* **MIME & OLE Deconstruction:** Recursive unpacking of multipart MIME structures (`email.message_from_bytes`) and Outlook `.msg` files (`extract-msg`).
* **Attachment Security Analysis:** Magic bytes binary signature matching, double extension detection (`.pdf.exe`), and ZIP/OOXML VBA macro scanning (`vbaProject.bin`).
* **Content Deception Checks:** Internationalized Domain Names (Punycode `xn--`), zero-width Unicode character stripping, and urgent financial BEC NLP scanning.
* **Algorithmic Threat Intelligence:** Shannon Entropy calculation for DGA detection, Levenshtein distance for brand typosquatting, and keyless DNSBL lookups.
* **UI/UX Design System:** Cyber-defense glassmorphism aesthetic with responsive sidebar, interactive LeafletJS map, chronological hop timeline, and IOC explorer tabs.
* **Appearance & Theme Customization:** Dark, Light, and System themes with 5 curated accent colors (`Cyber Cyan`, `Emerald Shield`, `Spectral Violet`, `Solar Amber`, `Crimson Sentinel`).
* **Documentation Suite:** Comprehensive 30-section SRS, PRD, Architecture document (C4 Model), UI/UX specification, Development guide, and Pytest QA suite.

### Changed
* Refactored backend from synchronous routing to fully asynchronous FastAPI endpoints.
* Updated threat scoring from binary safe/phish labels to a 0–100 bounded penalty point gauge.
* Upgraded Leaflet tile mapping to dynamically focus on originating public IP coordinates.
* Replaced temporary file creation with in-memory `io.BytesIO` streams.

### Fixed
* Fixed false positive warnings on internal/loopback RFC 1918 hops (`127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`).
* Fixed character encoding glitches when parsing UTF-8 and ISO-8859-1 encoded email subjects.
* Fixed timezone discrepancy parsing when MTAs use non-standard GMT offset notations.

### Removed
* Removed deprecated synchronous header parsing routes.
* Removed legacy prototype database schemas in favor of 100% in-memory stateless architecture.

### Deprecated
* Legacy raw text-only submission methods (superseded by unified `/api/analyze/raw` and `/api/analyze/file`).

### Security
* Implemented strict Content Security Policy (`CSP`) headers: `default-src 'self'`.
* Added global `Cache-Control: no-store, no-cache, must-revalidate` to enforce zero server-side caching.
* Implemented payload size ceiling guards (10MB for files, 5MB for text).
* Added 50MB uncompressed ceiling to prevent zip bomb decompression attacks during macro scanning.
* Enforced regex validation on domain and IP parameters to eliminate SSRF risks on RDAP lookups.
* Added HTML output escaping (`escapeHTML()`) across all frontend DOM injection points.

### Breaking Changes
* Analysis API responses now return the unified Checkpoints schema (`checkpoints.A`, `checkpoints.B`, `checkpoints.C`, `checkpoints.D`) replacing the legacy flat `rules` array.

### Migration Notes
* Clients migrating from v1.x should update their JSON parsing to read `data.checkpoints` and `data.score` directly.

### Known Issues
* S/MIME and PGP encrypted email messages cannot have their body content or attachments analyzed without prior decryption.

### Upcoming Changes
* Planned STIX/TAXII 2.1 IOC threat bundle export in v2.5.0.
* Planned SIEM webhook integration (Splunk, Microsoft Sentinel) in v3.0.0.

---

## [1.5.0] - 2026-08-22

### Added
* Support for Microsoft Outlook Compound Binary `.msg` files using `extract-msg`.
* Geolocation mapping using Leaflet.js and `ipwho.is`.
* Live cyber threat news feed aggregation from *The Hacker News* and *BleepingComputer*.
* Client-side history storage via `localStorage`.

### Changed
* Redesigned topbar and navigation layout.

### Fixed
* Fixed issue where malformed `Received` headers crashed the hop parser.

### Security
* Added input size limits to file upload endpoints.

---

## [1.0.0] - 2026-08-20

### Added
* Initial production release of ThreatScope.
* Raw RFC 5322 email header parser.
* SPF, DKIM, and DMARC status verification.
* Basic IP origin extraction and MX DNS resolution.
* REST API endpoints for header analysis.

---

## [0.1.0-alpha] - 2026-08-15

### Added
* Initial proof-of-concept Python script for parsing RFC 822 email headers.
