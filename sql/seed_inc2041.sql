-- file: sql/seed_inc2041.sql
-- Seed data for Trustaira Customer Zero & Multiple Incidents

INSERT OR IGNORE INTO tenants (id, name, api_key, posture_score, sla_response_mins, retention_days)
VALUES ('tenant-trustaira', 'Trustaira Limited (Customer Zero)', 'trustaira-soc-key-2026', 78, 15, 90);

-- Connected Nodes Status
INSERT OR IGNORE INTO node_status (id, tenant_id, node_name, node_type, ip_address, status, eps, last_seen) VALUES
('node-1', 'tenant-trustaira', 'Elasticsearch SIEM Core', 'SIEM', '192.168.1.64', 'online', 420, datetime('now')),
('node-2', 'tenant-trustaira', 'Trend Micro Vision One', 'XDR', 'api.sg.xdr.trendmicro.com', 'online', 85, datetime('now')),
('node-3', 'tenant-trustaira', 'Wazuh AD & Endpoint Cluster', 'EDR/AD', '192.168.1.64', 'online', 190, datetime('now')),
('node-4', 'tenant-trustaira', 'Perimeter Firewall Gateway', 'Firewall', '192.168.1.1', 'online', 610, datetime('now')),
('node-5', 'tenant-trustaira', 'Corporate Email Gateway', 'Email', '192.168.1.25', 'online', 45, datetime('now')),
('node-6', 'tenant-trustaira', 'Multi-OSINT Threat Intel Feed', 'TI', '192.168.1.64', 'online', 12, datetime('now'));

-- Sample False-Positive Suppression Rules
INSERT OR IGNORE INTO fp_rules (id, tenant_id, rule_name, entity_pattern, suppressed_by, reason) VALUES
('fp-1', 'tenant-trustaira', 'SMB Scan Internal', '192.168.1.200', 'SOC-Lead', 'Authorized vulnerability scanner window'),
('fp-2', 'tenant-trustaira', 'High Outbound Traffic', 'SRV-BACKUP-01', 'AI-Baseline', 'Nightly encrypted offsite backup job');

-- =====================================================================
-- INCIDENT 1: INC-2041 (Spearphishing & Exfiltration)
-- =====================================================================
INSERT OR IGNORE INTO incidents (
    id, tenant_id, title, risk_score, severity, status, primary_entity, ai_story, recommended_action, action_approved
) VALUES (
    'INC-2041', 'tenant-trustaira',
    'Spearphishing Macro to Credential Dump & 2.3 GB Exfiltration',
    92, 'high', 'awaiting_approval', 'a.rahman',
    'At 09:14 today, user a.rahman received a spoofed payroll email (Salary_Q3.xlsm) that failed SPF verification. Opening the attachment triggered a malicious Excel macro that spawned PowerShell, dumped LSASS credentials at 09:21, and succeeded after 14 failed AD logins. The attacker then performed a first-time RDP lateral movement to SRV-FILE-02 at 09:41, scanned 6 internal SMB hosts, and exfiltrated 2.3 GB of data at 10:05 to an external IP (185.220.101.42) flagged by Threat Intelligence.',
    '1. Isolate host SRV-FILE-02 & workstation of a.rahman via Trend Vision One. 2. Revoke active AD Kerberos tickets for a.rahman. 3. Block destination IP 185.220.101.42 on Perimeter Firewall.',
    0
);

INSERT OR IGNORE INTO incident_steps (id, incident_id, tenant_id, stage_order, tactic, technique_group, technique_id, title, event_time, source, entity, severity, raw_log, pinned) VALUES
('step-1', 'INC-2041', 'tenant-trustaira', 1, 'Initial access', 'T1566', 'T1566.001', 'Malicious attachment delivered', '09:14', 'Email gateway', 'a.rahman', 'medium', 'from=hr-update@payr0ll-mail.com to=a.rahman@client.com attachment=Salary_Q3.xlsm verdict=suspicious spf=fail', 0),
('step-2', 'INC-2041', 'tenant-trustaira', 1, 'Initial access', 'T1566', 'T1566.001', 'Excel macro spawned PowerShell', '09:16', 'Trend Vision One', 'a.rahman', 'high', 'host=WS-RAHMAN-01 parent=EXCEL.EXE cmd="powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBP..." user=a.rahman', 0),
('step-3', 'INC-2041', 'tenant-trustaira', 2, 'Credential access', 'T1003', 'T1003.001', 'LSASS memory access', '09:21', 'Trend Vision One', 'a.rahman', 'high', 'host=WS-RAHMAN-01 source_image=rundll32.exe target_image=lsass.exe granted_access=0x1010', 0),
('step-4', 'INC-2041', 'tenant-trustaira', 2, 'Credential access', 'T1003', 'T1110.001', '14 failed logins, then success', '09:27', 'AD via Wazuh', 'a.rahman', 'medium', 'win.system.eventID=4625 failed_attempts=14 followed_by_eventID=4624 target_user=a.rahman src_ip=192.168.1.114', 0),
('step-5', 'INC-2041', 'tenant-trustaira', 3, 'Lateral movement', 'T1021', 'T1021.001', 'First-time RDP to SRV-FILE-02', '09:41', 'Wazuh', 'SRV-FILE-02', 'high', 'ueba_anomaly=first_time_rdp user=a.rahman src_host=WS-RAHMAN-01 dst_host=SRV-FILE-02', 0),
('step-6', 'INC-2041', 'tenant-trustaira', 3, 'Lateral movement', 'T1021', 'T1021.002', 'SMB spike to 6 internal hosts', '09:48', 'Firewall', 'SRV-FILE-02', 'medium', 'src_ip=192.168.1.52 dst_port=445 unique_hosts=6 bytes=48291040', 0),
('step-7', 'INC-2041', 'tenant-trustaira', 4, 'Exfiltration', 'T1041', 'T1041', '2.3 GB outbound to rare IP', '10:05', 'Firewall', 'SRV-FILE-02', 'high', 'src_ip=192.168.1.52 dst_ip=185.220.101.42 proto=HTTPS bytes_out=2469606195', 0),
('step-8', 'INC-2041', 'tenant-trustaira', 4, 'Exfiltration', 'T1041', 'T1041', 'Destination IP flagged by TI', '10:07', 'Threat intel', '185.220.101.42', 'high', 'ioc_ip=185.220.101.42 feed=AlienVault_OTX,VirusTotal category=C2_Exfiltration', 0);

-- =====================================================================
-- INCIDENT 2: INC-2042 (Cloud IAM Key Compromise & Crypto-Mining)
-- =====================================================================
INSERT OR IGNORE INTO incidents (
    id, tenant_id, title, risk_score, severity, status, primary_entity, ai_story, recommended_action, action_approved
) VALUES (
    'INC-2042', 'tenant-trustaira',
    'Compromised AWS IAM Access Key Spawning EC2 Crypto-Miners',
    85, 'high', 'open', 'dev-pipeline-role',
    'At 14:22, AWS CloudTrail recorded an IAM access key associated with dev-pipeline-role logging in from a known Tor exit node in Moldova. Within 4 minutes, 45 high-GPU c5.24xlarge EC2 instances were provisioned in an unused region (eu-west-3) running unauthorized mining containers.',
    '1. Revoke AWS IAM access key immediately. 2. Terminate unauthorized EC2 instances in eu-west-3. 3. Enforce AWS IAM condition keys and SCPs.',
    0
);

INSERT OR IGNORE INTO incident_steps (id, incident_id, tenant_id, stage_order, tactic, technique_group, technique_id, title, event_time, source, entity, severity, raw_log, pinned) VALUES
('step-201', 'INC-2042', 'tenant-trustaira', 1, 'Initial access', 'T1078', 'T1078.004', 'Cloud API login from Tor Node', '14:22', 'CloudTrail', 'dev-pipeline-role', 'high', 'event=AssumeRole src_ip=185.220.101.5 user_agent=Boto3/1.28.0 country=MD tor_exit=true', 0),
('step-202', 'INC-2042', 'tenant-trustaira', 2, 'Execution', 'T1204', 'T1204.002', 'Unauthorized EC2 Instance Launch', '14:26', 'AWS GuardDuty', 'eu-west-3', 'high', 'alert=CryptoCurrency:EC2/BitcoinMining.B!gen count=45 instance_type=c5.24xlarge', 0),
('step-203', 'INC-2042', 'tenant-trustaira', 3, 'Exfiltration', 'T1567', 'T1567.002', 'Staged mining pool outbound traffic', '14:35', 'VPC Flow Logs', '10.0.4.12', 'medium', 'dst_port=3333 proto=TCP bytes_out=12049021 status=active_pool_connection', 0);

-- =====================================================================
-- INCIDENT 3: INC-2043 (Ransomware Lateral Movement & Shadow Copy Deletion)
-- =====================================================================
INSERT OR IGNORE INTO incidents (
    id, tenant_id, title, risk_score, severity, status, primary_entity, ai_story, recommended_action, action_approved
) VALUES (
    'INC-2043', 'tenant-trustaira',
    'LockBit Ransomware Dropped via Domain Controller GPO Modification',
    98, 'critical', 'awaiting_approval', 'SRV-DC-01',
    'At 23:45, Domain Controller SRV-DC-01 executed a modified default domain policy executing vssadmin delete shadows /all /quiet followed by mass file renaming with .lockbit extension across 14 file servers.',
    '1. Disconnect SRV-DC-01 and affected file servers from network. 2. Restore Active Directory from last known good offline backup. 3. Initiate incident response retainer.',
    0
);

INSERT OR IGNORE INTO incident_steps (id, incident_id, tenant_id, stage_order, tactic, technique_group, technique_id, title, event_time, source, entity, severity, raw_log, pinned) VALUES
('step-301', 'INC-2043', 'tenant-trustaira', 1, 'Execution', 'T1490', 'T1490', 'Volume Shadow Copy Deletion', '23:45', 'Wazuh EDR', 'SRV-DC-01', 'critical', 'image=cmd.exe command="vssadmin.exe delete shadows /all /quiet" parent=services.exe', 0),
('step-302', 'INC-2043', 'tenant-trustaira', 2, 'Lateral movement', 'T1021', 'T1021.002', 'SMB Mass File Renaming (Ransomware)', '23:48', 'Elastic SIEM', '192.168.1.10', 'critical', 'event=FileModified rename_count=4200 extension_added=.lockbit user=SYSTEM', 0);