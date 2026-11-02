# Findings to report upstream (draft)

**Status: draft, not yet filed.** These are findings about the source file, not about this project. They are written so that they can be posted as one issue on the [Mappings Explorer repository](https://github.com/center-for-threat-informed-defense/mappings-explorer/issues) after review.

**File:** `mappings/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.json`, commit `6bdc3ad`, SHA-256 `355ae97d309c00eb2428e5af07754ff4ca16cfe63928194081d0e883aed929c8`. Record numbers below are one-based positions in `mapping_objects`.

## 1. A Mobile technique in the Enterprise mapping

Record 637 maps SC-12 to T1521.003 SSL Pinning. T1521.003 is not an attack-pattern in ATT&CK Enterprise 16.1 (it is in the Mobile domain). The row also carries `attack_version` `[UNKNOWN_VERSION]`, the only row with that field.

## 2. Fifty duplicate rows

These control and technique pairs each appear in two identical rows (every field the same):

| Pair | Records |
| --- | --- |
| CM-02 T1021.001 | 3887 and 3896 |
| CM-02 T1021.005 | 3848 and 3900 |
| CM-02 T1053.002 | 1180 and 1217 |
| CM-02 T1053.005 | 1181 and 1218 |
| CM-02 T1059 | 1182 and 1219 |
| CM-02 T1068 | 3850 and 3926 |
| CM-02 T1176 | 1183 and 1238 |
| CM-02 T1204.003 | 3852 and 3970 |
| CM-02 T1210 | 3853 and 3972 |
| CM-02 T1211 | 3854 and 3973 |
| CM-02 T1212 | 3855 and 3974 |
| CM-02 T1213 | 1184 and 1242 |
| CM-02 T1213.001 | 1185 and 1243 |
| CM-02 T1213.002 | 1186 and 1244 |
| CM-02 T1484 | 1187 and 1250 |
| CM-02 T1505 | 3858 and 3994 |
| CM-02 T1505.001 | 3859 and 3995 |
| CM-02 T1505.002 | 3860 and 3996 |
| CM-02 T1505.004 | 3861 and 3997 |
| CM-02 T1525 | 3862 and 3999 |
| CM-02 T1528 | 1188 and 1254 |
| CM-02 T1530 | 1189 and 1255 |
| CM-02 T1542.004 | 3864 and 4000 |
| CM-02 T1542.005 | 3865 and 4001 |
| CM-02 T1543 | 1191 and 1257 |
| CM-02 T1548 | 1192 and 1263 |
| CM-02 T1548.002 | 3866 and 4013 |
| CM-02 T1550.001 | 1193 and 1265 |
| CM-02 T1552 | 1194 and 1266 |
| CM-02 T1552.001 | 1195 and 1267 |
| CM-02 T1552.004 | 1196 and 1268 |
| CM-02 T1552.006 | 3868 and 4017 |
| CM-02 T1553 | 1197 and 1269 |
| CM-02 T1554 | 1198 and 1270 |
| CM-02 T1558.004 | 3870 and 4030 |
| CM-02 T1562 | 1200 and 1276 |
| CM-02 T1563 | 1201 and 1279 |
| CM-02 T1574 | 3872 and 4054 |
| CM-02 T1574.001 | 1202 and 1286 |
| CM-02 T1574.005 | 3873 and 4056 |
| CM-02 T1574.007 | 3874 and 4057 |
| CM-02 T1574.008 | 3875 and 4058 |
| CM-02 T1574.009 | 3876 and 4059 |
| CM-02 T1574.010 | 3877 and 4060 |
| CM-02 T1601 | 3883 and 4065 |
| CM-02 T1601.001 | 3884 and 4066 |
| CM-02 T1601.002 | 3885 and 4067 |
| IA-09 T1036 | 461 and 462 |
| SC-08 T1562 | 937 and 938 |
| SI-12 T1070.008 | 3047 and 3048 |

## 3. Titles that differ from the SP 800-53 Rev. 5 OSCAL catalog (5.2.0)

| Item | Mapping | OSCAL catalog |
| --- | --- | --- |
| CA family | Security Assessment and Authorization | Assessment, Authorization, and Monitoring |
| SC-32 | Information System Partitioning | System Partitioning |
| IA-08 | Identification and Authentication (Non-Organizational Users) | Identification and Authentication (Non-organizational Users) |

## 4. Techniques with ATT&CK mitigations but no row

91 active ATT&CK Enterprise 16.1 techniques have no row in the file, of any status. 81 of them have no mitigation in ATT&CK, which agrees with the mapping definition ("the control can prevent the technique"). But the file is not consistent: other techniques with no ATT&CK mitigation have a `non_mappable` row with the comment "no mitigations in ATT&CK", and these 91 have nothing.

Eight of the 91 have substantive ATT&CK mitigations. They look like omissions:

| Technique | Tactics | ATT&CK mitigations (16.1) |
| --- | --- | --- |
| T1555.003 Credentials from Web Browsers | Credential Access | M1017 User Training; M1018 User Account Management; M1021 Restrict Web-Based Content; M1027 Password Policies; M1051 Update Software |
| T1484.001 Group Policy Modification | Defense Evasion, Privilege Escalation | M1018 User Account Management; M1047 Audit |
| T1484.002 Trust Modification | Defense Evasion, Privilege Escalation | M1018 User Account Management; M1026 Privileged Account Management |
| T1006 Direct Volume Access | Defense Evasion | M1018 User Account Management; M1040 Behavior Prevention on Endpoint |
| T1542.002 Component Firmware | Defense Evasion, Persistence | M1051 Update Software |
| T1564 Hide Artifacts | Defense Evasion | M1013 Application Developer Guidance; M1033 Limit Software Installation; M1049 Antivirus/Antimalware |
| T1027.006 HTML Smuggling | Defense Evasion | M1048 Application Isolation and Sandboxing |
| T1593 Search Open Websites/Domains | Reconnaissance | M1013 Application Developer Guidance; M1047 Audit |

Two more (T1480 Execution Guardrails and T1480.001 Environmental Keying) have only M1055 Do Not Mitigate. A `non_mappable` row would make the file consistent for those two and for the other 81.

## 5. Observation, not an error

ATT&CK lists a substantive mitigation for 3 of the 96 techniques marked non_mappable: T1566.004 and T1598.004 Spearphishing Voice (M1017 User Training) and T1656 Impersonation (M1017, M1019 Threat Intelligence Program). User training maps naturally to the SP 800-53 AT family, which is outside the mapping's scope. It may help readers if the scope note says so.

All five findings are reproducible with `python scripts/build_population.py` in [this repository](https://github.com/mmccalla/nist-attack-enterprise-ontology); see `data/source-checks.json` and competency questions CQ05, CQ08, CQ09, CQ12 and CQ13.
