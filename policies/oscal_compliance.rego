package oscal_compliance

# oscal_compliance.rego
# ======================
# Maps NomosFlow OPA violation messages to NIST SP 800-53 rev 5 control IDs.
#
# This policy is a *companion* to config/policies/policy.rego — it does not
# re-evaluate access decisions.  Instead, it consumes the violations set
# produced by the main policy and annotates each violation with the NIST
# controls it demonstrates (or violates).
#
# The control_map below is the canonical OPA-side source of truth and is kept
# in sync with the Python-side CONTROL_MAP in src/validators/trestle_validator.py.
#
# Usage — query this package from the sidecar or from trestle AR generation:
#
#   POST /v1/data/oscal_compliance/controls_for_request
#   {
#     "input": {
#       "violations": ["Requirement 1: Missing Token", "PII Detected"],
#       "verdict": "DENIED"
#     }
#   }

import future.keywords.if
import future.keywords.in

# ──────────────────────────────────────────────────────────────────────────────
# Control map: rule-key substring → NIST SP 800-53 rev 5 control IDs
# ──────────────────────────────────────────────────────────────────────────────

control_map := {
    # Tier 1 — APL
    "Missing Token":          ["IA-2",  "IA-5",  "IA-8",  "AC-3"],
    "Invalid Token":          ["IA-2",  "IA-5",  "IA-8",  "AC-3"],
    "Expired Token":          ["IA-2",  "IA-11", "AC-12"],
    "Invalid Role":           ["AC-2",  "AC-3",  "AC-6"],
    "Invalid Action":         ["AC-3",  "AC-17"],
    "Blocked User":           ["AC-2",  "AC-6",  "SI-3"],

    # Tier 2 — CMF
    "PII Detected":           ["SI-12", "SI-19", "SC-28", "MP-6"],
    "Critical PII":           ["SI-12", "SI-19", "SC-28", "PL-8"],
    "Classification Elevated":["AC-4",  "SC-16"],

    # Tier 3 — OPA requirements
    # Req 1: Zero-Trust Identity (IA-11 = Re-Authentication; IA-5 = Authenticator Mgmt)
    "Requirement 1":          ["IA-2",  "IA-5",  "IA-11"],
    "Requirement 2":          ["AC-2",  "AC-3",  "AC-6"],
    "Requirement 3":          ["AC-4",  "SC-8",  "SC-28", "AR-8"],
    "Requirement 4":          ["SC-5",  "SI-17"],
    "Requirement 5":          ["AU-2",  "AU-3",  "AU-12"],
    "Requirement 6":          ["SI-12", "SI-19", "SC-28"],
    "Requirement 7":          ["SI-10", "SI-12"],
    "Requirement 8":          ["CA-3",  "SA-9"],
    "Requirement 9":          ["AC-3",  "MP-6",  "SI-3"],
    "Requirement 10":         ["AU-10", "SI-7"],
    "Requirement 11":         ["SI-12", "SI-18"],
    "Requirement 12":         ["SI-10", "SI-12"],
    # Req 13: Data-lake format/size/schema/PII/ACID controls
    # SI-10 = Input Validation, SC-28 = Protection at Rest,
    # AC-3 = Access Enforcement, CM-3 = Configuration Change Control
    "Requirement 13":         ["SI-10", "SC-28", "AC-3",  "CM-3"],
    # Req 14: AI hallucination / fabricated-identifier detection
    # SI-10 = Input Validation, SI-3 = Malicious Code Protection (adversarial input),
    # SA-11 = Developer Testing (adversarial content), RA-3 = Risk Assessment
    "Requirement 14":         ["SI-10", "SI-3",  "SA-11", "RA-3"],
    # Req 17: Consent verification (GDPR Art. 7, CCPA §1798.120)
    # PT-2 = Authority to Process PII, PT-3 = PII Retention/Disposal,
    # AC-3 = Access Enforcement
    "Requirement 17":         ["PT-2",  "PT-3",  "AC-3"],
    # Req 18: Right to Erasure / Right to be Forgotten (GDPR Art. 17, CCPA §1798.105)
    # PT-3 = PII Retention and Disposal, SI-12 = Information Mgmt and Retention,
    # AC-3 = Access Enforcement
    "Requirement 18":         ["PT-3",  "SI-12", "AC-3"],
    # Req 25: Cross-border data transfer (GDPR Art. 44-50, Schrems II)
    # AC-4 = Information Flow Enforcement, AR-8 = Accounting of Disclosures,
    # SC-8 = Transmission Confidentiality and Integrity
    "Requirement 25":         ["AC-4",  "AR-8",  "SC-8"],

    # Regulatory
    "GDPR":                   ["PT-1",  "PT-2",  "PT-3",  "AR-1"],
    "CCPA":                   ["PT-1",  "PT-5",  "AR-1"],
    "consent_obtained":       ["PT-2",  "PT-3"],
    "deletion_requested":     ["PT-3",  "SI-12"],
    "data_residency":         ["AC-4",  "AR-8"],
    "HIPAA":                  ["AU-2",  "AU-3",  "SC-28", "AC-3"],
    "SOX":                    ["AU-2",  "AU-9",  "AU-11"],
    "PCI":                    ["SC-28", "SC-8",  "AU-2",  "IA-2"],
    "retention":              ["AU-11", "SI-12"],

    # Data quality
    "quality_score":          ["SI-10"],
    "completeness_score":     ["SI-10"],
    "accuracy_score":         ["SI-10"],
    "schema_version":         ["CM-3",  "SI-10"],

    # Tier 4 — Stateful
    "Rate limit exceeded":    ["SC-5",  "SI-17"],
    "Anomaly detected":       ["SI-3",  "SI-4",  "RA-3"],

    # Tier 5 — LLM
    "Delegated":              ["CA-7",  "IR-6"],
    "Hallucination":          ["SI-3",  "SA-11"],
    "Escalated":              ["CA-7",  "IR-2",  "IR-4"],

    # Clearance
    "clearance":              ["AC-3",  "AC-6",  "PS-6"],
    "Insufficient clearance": ["AC-3",  "AC-6",  "PS-6"],
}

# ──────────────────────────────────────────────────────────────────────────────
# controls_for_violation: set of NIST control IDs for a single violation string
# ──────────────────────────────────────────────────────────────────────────────

controls_for_violation[ctrl] if {
    some violation in input.violations
    some rule_key, ctrl_list in control_map
    contains(violation, rule_key)
    some ctrl in ctrl_list
}

# ──────────────────────────────────────────────────────────────────────────────
# controls_for_request: deduplicated sorted array of all matched control IDs
# ──────────────────────────────────────────────────────────────────────────────

controls_for_request := sort(controls_for_violation)

# ──────────────────────────────────────────────────────────────────────────────
# annotations: full structured annotation for each violation
# ──────────────────────────────────────────────────────────────────────────────

annotations[obj] if {
    some violation in input.violations
    matched_controls := [ctrl |
        some rule_key, ctrl_list in control_map
        contains(violation, rule_key)
        some ctrl in ctrl_list
    ]
    count(matched_controls) > 0
    obj := {
        "violation":  violation,
        "controls":   sort(matched_controls),
        "verdict":    input.verdict,
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# oscal_response: top-level response shape consumed by TrestleAnnotator
# ──────────────────────────────────────────────────────────────────────────────

oscal_response := {
    "controls":     controls_for_request,
    "annotations":  annotations,
    "violation_count": count(input.violations),
    "control_count":   count(controls_for_request),
}
