# EXP-GAP-32  OSCAL control-mapping four-eyes review

## Verification summary (GAP-32 resolved)
| Metric | Value | Status |
| ------ | ----- | ------ |
| Rule-keys (OPA canonical) | 46 | ✓ verified |
| Rule-keys (Python fallback) | 46 | ✓ matches OPA |
| OPA ↔ Python key drift | 0 | ✓ zero drift |
| OPA ↔ Python control-set drift | 0 keys | ✓ zero drift |
| Spurious control IDs | 0 | ✓ clean |
| Distinct NIST control IDs | 46 | ✓ verified |
| Control families | 15 | ✓ AC, AR, AU, CA, CM, IA, IR, MP, PL, PS, PT, RA, SA, SC, SI |
| Policy REQs with no mapping | 0 | ✓ fully mapped |
| Non-standard IDs removed | ZT-1 | → IA-5, IA-11 |
| New mappings added (REQ 13–25) | 5 | ✓ REQ 13,14,17,18,25 |

## Control families covered
| Family | Controls covered | Example rules |
| ------ | ---------------- | ------------- |
| AC | AC-12, AC-17, AC-2, AC-3, AC-4, AC-6 | Blocked User; Classification Elevated |
| AR | AR-1, AR-8 | CCPA; GDPR |
| AU | AU-10, AU-11, AU-12, AU-2, AU-3, AU-9 | HIPAA; PCI |
| CA | CA-3, CA-7 | Delegated; Escalated |
| CM | CM-3 | Requirement 13; schema_version |
| IA | IA-11, IA-2, IA-5, IA-8 | Expired Token; Invalid Token |
| IR | IR-2, IR-4, IR-6 | Delegated; Escalated |
| MP | MP-6 | PII Detected; Requirement 9 |
| PL | PL-8 | Critical PII |
| PS | PS-6 | Insufficient clearance; clearance |
| PT | PT-1, PT-2, PT-3, PT-5 | CCPA; GDPR |
| RA | RA-3 | Anomaly detected; Requirement 14 |
| SA | SA-11, SA-9 | Hallucination; Requirement 14 |
| SC | SC-16, SC-28, SC-5, SC-8 | Classification Elevated; Critical PII |
| SI | SI-10, SI-12, SI-17, SI-18, SI-19, SI-3, SI-4, SI-7 | Anomaly detected; Blocked User |

## Policy requirement → NIST mapping
| Requirement | Mapped controls | In OPA | In Python |
| ----------- | --------------- | ------ | --------- |
| Requirement 1 | IA-2, IA-5, IA-11 | ✓ | ✓ |
| Requirement 2 | AC-2, AC-3, AC-6 | ✓ | ✓ |
| Requirement 3 | AC-4, SC-8, SC-28, AR-8 | ✓ | ✓ |
| Requirement 4 | SC-5, SI-17 | ✓ | ✓ |
| Requirement 5 | AU-2, AU-3, AU-12 | ✓ | ✓ |
| Requirement 6 | SI-12, SI-19, SC-28 | ✓ | ✓ |
| Requirement 7 | SI-10, SI-12 | ✓ | ✓ |
| Requirement 10 | AU-10, SI-7 | ✓ | ✓ |
| Requirement 11 | SI-12, SI-18 | ✓ | ✓ |
| Requirement 12 | SI-10, SI-12 | ✓ | ✓ |
| Requirement 13 | SI-10, SC-28, AC-3, CM-3 | ✓ | ✓ |
| Requirement 14 | SI-10, SI-3, SA-11, RA-3 | ✓ | ✓ |
| Requirement 17 | PT-2, PT-3, AC-3 | ✓ | ✓ |
| Requirement 18 | PT-3, SI-12, AC-3 | ✓ | ✓ |
| Requirement 25 | AC-4, AR-8, SC-8 | ✓ | ✓ |

## Paper §5 gap disclosures
- GAP-32 RESOLVED: rule-key count verified at 46 (was 41 before REQ 13/14/17/18/25 added). OPA ↔ Python maps are in sync (zero drift). All 15 policy requirements have OSCAL mappings. Non-standard ZT-1 replaced by IA-5, IA-11.
