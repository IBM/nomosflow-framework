# EXP-9 boundary-property verification

*Generated: 2026-08-14T05:23:44.191399+00:00*

## Static code audit — fetch_real_data call sites
| File | Call_site_line | Gated_by_APPROVED |
| ---- | -------------- | ----------------- |
| src/core/sidecar_optimized.py | 2046 | True |

## Data-path buffer-then-release audit
| File | Method | Uses_yield | Notes |
| ---- | ------ | ---------- | ----- |
| src/storage/data_lake_reader.py | read_parquet | False | no yield keyword in file |
| src/storage/data_lake_reader.py | read_avro | False | no yield keyword in file |
| src/storage/data_lake_reader.py | read_orc | False | no yield keyword in file |
| src/storage/data_lake_reader.py | read_delta | False | no yield keyword in file |
| src/storage/data_lake_reader.py | read_data_lake_file | False | no yield keyword in file |
| src/interceptors/compliance_proxy_server.py | return@135 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@224 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@232 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@244 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@252 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@259 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@269 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@350 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@360 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@367 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@377 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@403 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@461 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@475 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@486 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@495 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@502 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@512 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@541 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@606 | False | gated by APPROVED |
| src/interceptors/compliance_proxy_server.py | return@620 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@630 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@687 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@698 | False | gated by APPROVED |
| src/interceptors/compliance_proxy_server.py | return@711 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@721 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@769 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@779 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@811 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@852 | False | gated by APPROVED |
| src/interceptors/compliance_proxy_server.py | return@863 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@873 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@940 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@949 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@958 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@966 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@975 | False | not approval-gated in local context |
| src/interceptors/compliance_proxy_server.py | return@985 | False | not approval-gated in local context |

## Runtime verification
| Mode | Approved | Denied_with_data (must be 0) |
| ---- | -------- | ---------------------------- |
| live_opa | 36 | 0 |

## Paper §5 gap disclosures
- Per-chunk RB-stream (streaming enforcement) is not claimed and is future work (§7)
