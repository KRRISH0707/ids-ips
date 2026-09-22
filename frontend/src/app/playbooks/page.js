'use client';

import { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import Sidebar from '@/components/Sidebar';
import BrandLogo from '@/components/BrandLogo';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState, Pagination } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import { exportToCSV, formatRelativeTime } from '@/lib/utils';

const MITRE_MAPPINGS = {
  'PB-01': { code: 'T1486', name: 'Data Encrypted for Impact (VSS Shadow Lock)', tactic: 'Impact' },
  'PB-02': { code: 'T1071', name: 'Application Layer Protocol / C2 Severance', tactic: 'Command & Control' },
  'PB-03': { code: 'T1110', name: 'Brute Force & Credential Stuffing Mitigation', tactic: 'Credential Access' },
  'PB-04': { code: 'T1046', name: 'Network Service Discovery & Port Tarpit', tactic: 'Reconnaissance' },
  'PB-05': { code: 'T1059', name: 'Command & Scripting Interpreter / High Entropy', tactic: 'Execution' },
  'PB-06': { code: 'T1498', name: 'Network Denial of Service (BGP Flowspec)', tactic: 'Impact' },
  'PB-07': { code: 'T1190', name: 'Exploit Public-Facing Application (RCE)', tactic: 'Initial Access' },
  'PB-08': { code: 'T1558', name: 'Kerberoasting & DCSync Privilege Escalation', tactic: 'Privilege Escalation' },
  'PB-09': { code: 'T1048', name: 'Exfiltration Over Alternative Protocol (DNS)', tactic: 'Exfiltration' },
  'PB-10': { code: 'T1611', name: 'Escape to Host / Container Cgroup Freeze', tactic: 'Privilege Escalation' },
  'PB-11': { code: 'T1550', name: 'Pass the Hash & Lateral Microsegmentation', tactic: 'Lateral Movement' },
  'PB-12': { code: 'T1200', name: 'Protocol Anomaly & Dynamic eBPF Discard', tactic: 'Defense Evasion' },
  'PB-13': { code: 'T1558.001', name: 'Golden Ticket Kerberos Forgery Purge', tactic: 'Privilege Escalation' },
  'PB-14': { code: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory Kill', tactic: 'Credential Access' },
  'PB-15': { code: 'T1210', name: 'Exploitation of Remote Services (ZeroLogon)', tactic: 'Lateral Movement' },
  'PB-16': { code: 'T1552.001', name: 'Credentials In Files / Cloud IAM Key Leak', tactic: 'Credential Access' },
  'PB-17': { code: 'T1530', name: 'Data from Cloud Storage S3 Bucket Leak', tactic: 'Collection' },
  'PB-18': { code: 'T1078.004', name: 'Cloud Accounts: AWS STS AssumeRole Abuse', tactic: 'Defense Evasion' },
  'PB-19': { code: 'T1078', name: 'Valid Accounts / Azure AD Impossible Travel', tactic: 'Initial Access' },
  'PB-20': { code: 'T1098', name: 'Account Manipulation: GCP Service Account', tactic: 'Persistence' },
  'PB-21': { code: 'T1610', name: 'Deploy Container: Privileged Pod Injection', tactic: 'Execution' },
  'PB-22': { code: 'T1496', name: 'Resource Hijacking: Container Cryptomining', tactic: 'Impact' },
  'PB-23': { code: 'T1098.003', name: 'Cluster Role Binding Backdoor Purge', tactic: 'Persistence' },
  'PB-24': { code: 'T1499', name: 'Endpoint Denial of Service: API Abuse WAF', tactic: 'Impact' },
  'PB-25': { code: 'T1557', name: 'Adversary-in-the-Middle: East-West Mesh', tactic: 'Credential Access' },
  'PB-26': { code: 'T1190', name: 'SQL Injection / Web Application Exploit', tactic: 'Initial Access' },
  'PB-27': { code: 'T1552.005', name: 'Cloud Instance Metadata API (SSRF IMDSv2)', tactic: 'Credential Access' },
  'PB-28': { code: 'T1539', name: 'Steal Web Session Cookie / BOLA & IDOR', tactic: 'Collection' },
  'PB-29': { code: 'T1499.004', name: 'Application Exhaustion: GraphQL Deep Flood', tactic: 'Impact' },
  'PB-30': { code: 'T1505.003', name: 'Server Software Component: Web Shell Purge', tactic: 'Persistence' },
  'PB-31': { code: 'T1567', name: 'Exfiltration Over Web Service / Cloud Sync', tactic: 'Exfiltration' },
  'PB-32': { code: 'T1052.001', name: 'Exfiltration over Physical Removable USB', tactic: 'Exfiltration' },
  'PB-33': { code: 'T1136.001', name: 'Create Account: Local Rogue Administrator', tactic: 'Persistence' },
  'PB-34': { code: 'T1530', name: 'Off-Hours Bulk SQL Database Extraction', tactic: 'Collection' },
  'PB-35': { code: 'T1213', name: 'Data from Information Repositories: Git Clone', tactic: 'Collection' },
  'PB-36': { code: 'T1114.003', name: 'Email Forwarding Rule (BEC Compromise)', tactic: 'Collection' },
  'PB-37': { code: 'T1566.002', name: 'Phishing: Spearphishing Link Domain Sinkhole', tactic: 'Initial Access' },
  'PB-38': { code: 'T1566.001', name: 'Phishing: Macro Attachment Quarantine', tactic: 'Initial Access' },
  'PB-39': { code: 'T1556', name: 'Modify Authentication Process (Evilginx AitM)', tactic: 'Credential Access' },
  'PB-40': { code: 'T1584.001', name: 'Compromise Infrastructure: Typosquat Domain', tactic: 'Resource Development' },
  'PB-41': { code: 'T1059.001', name: 'PowerShell / Encoded LotL Execution Kill', tactic: 'Execution' },
  'PB-42': { code: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactic: 'Defense Evasion' },
  'PB-43': { code: 'T1055.012', name: 'Process Injection: Process Hollowing', tactic: 'Defense Evasion' },
  'PB-44': { code: 'T1053.005', name: 'Scheduled Task / Cron Backdoor Removal', tactic: 'Persistence' },
  'PB-45': { code: 'T1014', name: 'Rootkit / Kernel Module Tamper eBPF Lock', tactic: 'Defense Evasion' },
  'PB-46': { code: 'T1552', name: 'Unsecured Credentials in CI/CD Pipeline', tactic: 'Credential Access' },
  'PB-47': { code: 'T1195.001', name: 'Compromise Dependencies: Dependency Confusion', tactic: 'Initial Access' },
  'PB-48': { code: 'T1195.002', name: 'Compromise CI/CD Runner / Actions Tamper', tactic: 'Initial Access' },
  'PB-49': { code: 'T1552.007', name: 'Credentials In Terraform State File Exposure', tactic: 'Credential Access' },
  'PB-50': { code: 'T1525', name: 'Implant Internal Image: Poisoned Dockerfile', tactic: 'Persistence' },
  'PB-51': { code: 'T0855', name: 'Unauthorized Command Message (SCADA/Modbus)', tactic: 'Impact' },
  'PB-52': { code: 'T0831', name: 'Manipulation of Control (Siemens S7 / OT)', tactic: 'Impact' },
  'PB-53': { code: 'T1584.005', name: 'Botnet Propagation: IoT Mirai/Mozi Sweep', tactic: 'Resource Development' },
  'PB-54': { code: 'T1059', name: 'Command & Scripting: LLM Prompt Injection', tactic: 'Execution' },
  'PB-55': { code: 'T1567.002', name: 'Exfiltration to Cloud: AI Model Weight Theft', tactic: 'Exfiltration' },
};

import { useTimeRange } from '@/context/TimeRangeContext';

export default function PlaybooksPage() {
  const { days, dateSpanText } = useTimeRange();
  const [mounted, setMounted] = useState(false);
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('PLAYBOOKS'); // 'PLAYBOOKS' | 'HISTORY'
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [targetHost, setTargetHost] = useState('');
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState(null);
  const [playbookPage, setPlaybookPage] = useState(1);
  const [playbookPageSize, setPlaybookPageSize] = useState(12);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize, setHistoryPageSize] = useState(25);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Reset pagination to page 1 on timeframe or tab change
  useEffect(() => {
    setHistoryPage(1);
  }, [days, activeTab, historyPageSize]);

  // Reset playbook pagination to page 1 on filter or search change
  useEffect(() => {
    setPlaybookPage(1);
  }, [severityFilter, searchQuery, playbookPageSize]);

  const fetchData = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const [pbRes, execRes] = await Promise.all([
        api.getPlaybooks(),
        api.getPlaybookExecutions({ days: days || undefined, limit: 500 }),
      ]);
      setPlaybooks(pbRes?.items || []);
      setExecutions(execRes?.items || []);
    } catch (err) {
      console.error('Failed to load SOAR data:', err);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    fetchData(true);
  }, [fetchData]);

  // Paginated execution history
  const paginatedExecutions = executions.slice(
    (historyPage - 1) * historyPageSize,
    historyPage * historyPageSize
  );

  // Real-time synchronization: refresh SOAR playbook execution history on any threat mitigation or playbook trigger
  useOnLiveEvent(() => {
    fetchData(false);
  });

  const handleOpenRunModal = (pb) => {
    setSelectedPlaybook(pb);
    setExecResult(null);
    setTargetHost('192.168.1.150');
  };

  const handleRunPlaybook = async (e) => {
    e.preventDefault();
    if (!selectedPlaybook) return;

    try {
      setExecuting(true);
      const res = await api.executePlaybook(selectedPlaybook.id, { target: targetHost || '192.168.1.150' });
      setExecResult(res);
      await fetchData(false);
    } catch (err) {
      alert(`Playbook execution failed: ${err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  const filteredPlaybooks = playbooks.filter((pb) => {
    const matchesSev = severityFilter === 'ALL' || pb.severity_threshold === severityFilter;
    const q = searchQuery.toLowerCase().trim();
    if (!q) return matchesSev;
    const matchesQuery =
      pb.name?.toLowerCase().includes(q) ||
      pb.description?.toLowerCase().includes(q) ||
      pb.trigger_event?.toLowerCase().includes(q) ||
      (pb.actions || []).some((a) => a.toLowerCase().includes(q));
    return matchesSev && matchesQuery;
  });

  const criticalCount = playbooks.filter((p) => p.severity_threshold === 'CRITICAL').length;
  const highCount = playbooks.filter((p) => p.severity_threshold === 'HIGH').length;
  const mediumCount = playbooks.filter((p) => p.severity_threshold === 'MEDIUM').length;

  const paginatedPlaybooks = filteredPlaybooks.slice(
    (playbookPage - 1) * playbookPageSize,
    playbookPage * playbookPageSize
  );

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>AUTONOMOUS SOAR MATRIX</span>
          </div>
          <h1 className="page-title glow-text" style={{ margin: 0 }}>SOAR Automated Incident Response</h1>
          <p className="page-subtitle" style={{ marginTop: 4 }}>
            Zero-touch security orchestration & containment playbooks mapped to MITRE ATT&CK for instant adversarial mitigation
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className={`btn btn-sm ${activeTab === 'PLAYBOOKS' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveTab('PLAYBOOKS')}
          >
            Playbooks Library ({playbooks.length})
          </button>
          <button
            className={`btn btn-sm ${activeTab === 'HISTORY' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setActiveTab('HISTORY')}
          >
            Execution Audit ({executions.length})
          </button>
        </div>
      </div>

      <div className="page-body">
        {/* SOAR Metrics Overview Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(0, 212, 255, 0.15)', border: '1px solid rgba(0, 212, 255, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00d4ff' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)' }}>{playbooks.length}</div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Active Production Playbooks</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ef4444' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ef4444' }}>{criticalCount} Critical</div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Ransomware / C2 / DDoS / AD</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10b981' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                <polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#10b981' }}>{executions.length} Total</div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Automated Executions Logged</div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '16px 20px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 42, height: 42, borderRadius: 8, background: 'rgba(139, 92, 246, 0.15)', border: '1px solid rgba(139, 92, 246, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#a78bfa' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <polyline points="12 6 12 12 16 14"/>
              </svg>
            </div>
            <div>
              <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#a78bfa' }}>&lt; 0.35s</div>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Mean Time to Contain (MTTC)</div>
            </div>
          </div>
        </div>

        {activeTab === 'PLAYBOOKS' && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14, marginBottom: 20 }}>
            {/* Search filter */}
            <div style={{ flex: '1', minWidth: 260, maxWidth: 440 }}>
              <input
                type="text"
                className="input"
                placeholder="Search playbooks by name, attack vector, or action..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ fontSize: '0.85rem' }}
              />
            </div>

            {/* Severity filter pills */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`btn btn-sm ${severityFilter === sev ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ fontSize: '0.75rem', padding: '6px 14px' }}
                >
                  {sev === 'ALL'
                    ? `All Severity (${playbooks.length})`
                    : sev === 'CRITICAL'
                    ? `Critical (${criticalCount})`
                    : sev === 'HIGH'
                    ? `High (${highCount})`
                    : `Medium (${mediumCount})`}
                </button>
              ))}
            </div>
          </div>
        )}

        {loading ? (
          <Spinner />
        ) : activeTab === 'PLAYBOOKS' ? (
          filteredPlaybooks.length === 0 ? (
            <EmptyState message="No playbooks match your current filter criteria." />
          ) : (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 18 }}>
                {paginatedPlaybooks.map((pb) => {
                const pbPrefix = pb.name?.substring(0, 5);
                const mitre = MITRE_MAPPINGS[pbPrefix] || { code: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Defense' };

                return (
                  <div
                    key={pb.id}
                    className="glass-card"
                    style={{
                      padding: 22,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      borderTop: pb.severity_threshold === 'CRITICAL' ? '3px solid #ef4444' : '3px solid #f59e0b',
                      position: 'relative',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span
                            style={{
                              fontFamily: 'JetBrains Mono, monospace',
                              fontSize: '0.72rem',
                              fontWeight: 700,
                              padding: '2px 7px',
                              borderRadius: 4,
                              background: 'rgba(0, 212, 255, 0.12)',
                              border: '1px solid rgba(0, 212, 255, 0.3)',
                              color: 'var(--accent-cyan)'
                            }}
                          >
                            {pbPrefix}
                          </span>
                          <SeverityBadge severity={pb.severity_threshold} />
                        </div>
                        <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span className="live-dot" style={{ width: 5, height: 5 }} /> Armed
                        </span>
                      </div>

                      <h3 style={{ margin: '0 0 8px', fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                        {pb.name}
                      </h3>

                      <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.45, margin: '0 0 14px' }}>
                        {pb.description}
                      </p>

                      {/* MITRE ATT&CK Mapping */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, padding: '6px 10px', borderRadius: 6, background: 'rgba(2, 6, 23, 0.6)', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                        <span style={{ fontSize: '0.68rem', fontWeight: 700, color: '#a78bfa', fontFamily: 'JetBrains Mono, monospace' }}>
                          MITRE {mitre.code}
                        </span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {mitre.name}
                        </span>
                      </div>

                      <div style={{ marginBottom: 16 }}>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                          Orchestrated Containment Steps
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                          {(pb.actions || []).map((action, idx) => (
                            <span
                              key={idx}
                              style={{
                                fontSize: '0.68rem',
                                padding: '3px 8px',
                                borderRadius: 4,
                                background: 'rgba(99, 102, 241, 0.12)',
                                border: '1px solid rgba(99, 102, 241, 0.25)',
                                color: '#c7d2fe',
                                fontFamily: 'JetBrains Mono, monospace',
                              }}
                            >
                              {action}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        Trigger: <b style={{ color: 'var(--accent-cyan)' }}>{pb.trigger_event}</b>
                      </div>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleOpenRunModal(pb)}
                        style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px' }}
                      >
                        ▶ Run Playbook
                      </button>
                    </div>

                    {/* Per-playbook drill-down stats */}
                    {(() => {
                      const pbExecs = executions.filter(e => e.playbook_name === pb.name || e.playbook_id === pb.id);
                      const successCount = pbExecs.filter(e => e.status === 'COMPLETED' || e.status === 'SUCCESS').length;
                      const successRate = pbExecs.length > 0 ? Math.round((successCount / pbExecs.length) * 100) : null;
                      const lastRun = pbExecs[0]?.executed_at;
                      if (pbExecs.length === 0) return null;
                      return (
                        <div style={{ marginTop: 12, padding: '8px 12px', background: 'rgba(0,0,0,0.25)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.05)', display: 'flex', gap: 20 }}>
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '1rem', fontWeight: 800, color: '#00d4ff' }}>{pbExecs.length}</div>
                            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Executions</div>
                          </div>
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '1rem', fontWeight: 800, color: successRate >= 80 ? '#10b981' : '#f59e0b' }}>{successRate}%</div>
                            <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Success Rate</div>
                          </div>
                          {lastRun && (
                            <div style={{ textAlign: 'center' }}>
                              {(() => { const { relative, absolute } = formatRelativeTime(lastRun); return (
                                <div title={absolute}>
                                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)' }}>{relative}</div>
                                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Last Run</div>
                                </div>
                              ); })()}
                            </div>
                          )}
                      );
                    })()}
                  </div>
                );
              })}
            </div>
            <div style={{ marginTop: 24 }}>
              <Pagination
                page={playbookPage}
                totalPages={Math.ceil(filteredPlaybooks.length / playbookPageSize)}
                onPageChange={setPlaybookPage}
                totalItems={filteredPlaybooks.length}
                pageSize={playbookPageSize}
                onPageSizeChange={(newSize) => {
                  setPlaybookPageSize(newSize);
                  setPlaybookPage(1);
                }}
                pageSizeOptions={[12, 24, 48, 100]}
              />
            </div>
          </>
        )
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            {executions.length === 0 ? (
              <EmptyState message="No playbook executions recorded yet. Run a playbook or launch a simulation attack to generate audit trails." />
            ) : (
              <>
                <div style={{ padding: '10px 16px', display: 'flex', justifyContent: 'flex-end', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <button
                    className="btn-export"
                    onClick={() => exportToCSV(
                      executions,
                      ['playbook_name','target','status','triggered_by','executed_at'],
                      ['Playbook','Target','Status','Triggered By','Executed At'],
                      `soar_executions_${new Date().toISOString().slice(0,10)}.csv`
                    )}
                  >
                    ⬇ Export CSV
                  </button>
                </div>
              <div className="table-wrapper">
                <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 940 }}>
                  <colgroup>
                    <col style={{ width: '28%' }} />
                    <col style={{ width: '16%' }} />
                    <col style={{ width: '12%' }} />
                    <col style={{ width: '16%' }} />
                    <col style={{ width: '14%' }} />
                    <col style={{ width: '14%' }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th>Playbook Name</th>
                      <th>Target Scope</th>
                      <th>Status</th>
                      <th>Actions Enforced</th>
                      <th>Triggered By</th>
                      <th>Executed At</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedExecutions.map((ex) => (
                      <tr key={ex.id}>
                        <td>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ex.playbook_name}>
                            {ex.playbook_name}
                          </div>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.82rem', color: 'var(--accent-cyan)', whiteSpace: 'nowrap' }}>
                            {ex.target || 'N/A'}
                          </span>
                        </td>
                        <td>
                          <StatusBadge status={ex.status} />
                        </td>
                        <td>
                          <span style={{ color: '#34d399', fontWeight: 600, fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                            {(ex.actions_taken || []).length} Actions Executed
                          </span>
                        </td>
                        <td>
                          <span style={{ padding: '2px 6px', borderRadius: 4, background: 'rgba(255, 255, 255, 0.05)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', whiteSpace: 'nowrap' }}>
                            {ex.triggered_by}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {(() => { const { relative, absolute } = formatRelativeTime(ex.executed_at); return <span className="rel-time" title={absolute}>{relative}</span>; })()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              <Pagination
                currentPage={historyPage}
                pageSize={historyPageSize}
                totalItems={executions.length}
                label="playbook executions"
                loading={loading}
                onPageChange={(p) => setHistoryPage(p)}
                onPageSizeChange={(newSize) => {
                  setHistoryPageSize(newSize);
                  setHistoryPage(1);
                }}
              />
            </>)}
          </div>
        )}
      </div>

      {/* Execution Modal (Mounted directly to body via React Portal, Dead-Center Viewport) */}
      {selectedPlaybook && mounted && typeof document !== 'undefined' && createPortal(
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(2, 4, 8, 0.85)',
            backdropFilter: 'blur(12px)',
            WebkitBackdropFilter: 'blur(12px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999999,
            padding: 24,
            overflowY: 'auto',
            margin: 0
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setSelectedPlaybook(null);
          }}
        >
          {/* Ambient glow like login page */}
          <div style={{
            position: 'fixed',
            top: '35%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 550,
            height: 350,
            background: 'radial-gradient(ellipse, rgba(0,212,255,0.09) 0%, transparent 70%)',
            pointerEvents: 'none',
            zIndex: 0,
          }}/>

          <div
            className="hud-card fade-in"
            style={{
              width: '100%',
              maxWidth: 500,
              padding: '36px 32px',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 212, 255, 0.15)',
              position: 'relative',
              zIndex: 1,
              maxHeight: '92vh',
              overflowY: 'auto'
            }}
          >
            {/* Close Button */}
            <button
              onClick={() => setSelectedPlaybook(null)}
              type="button"
              style={{
                position: 'absolute',
                top: 16,
                right: 16,
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: 6,
                width: 30,
                height: 30,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '1rem',
                transition: 'all 0.2s',
                zIndex: 2,
              }}
              title="Close"
            >
              ✕
            </button>

            {/* Header styled like Login Page */}
            <div style={{ textAlign: 'center', marginBottom: 20 }}>
              <BrandLogo size={52} style={{ margin: '0 auto 12px' }} />
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
                <span className="live-dot" style={{ width: 6, height: 6 }} />
                <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>SOAR ORCHESTRATION ENGINE</span>
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 900, letterSpacing: '0.04em', margin: 0 }}>
                <span className="glow-gradient">{selectedPlaybook.name}</span>
              </h2>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4, letterSpacing: '0.02em', lineHeight: 1.4 }}>
                {selectedPlaybook.description}
              </p>
            </div>

            <form onSubmit={handleRunPlaybook}>
              <div style={{ marginBottom: 18 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
                  TARGET ENDPOINT / HOSTNAME OR IP
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. 192.168.1.150 or corp-srv-app01"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.9rem' }}
                  required
                />
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 6 }}>
                  Trigger Condition: <strong style={{ color: 'var(--accent-cyan)' }}>{selectedPlaybook.trigger_event}</strong> | Threshold: <strong style={{ color: selectedPlaybook.severity_threshold === 'CRITICAL' ? '#ef4444' : '#f59e0b' }}>{selectedPlaybook.severity_threshold}</strong>
                </div>
              </div>

              {execResult && (
                <div
                  style={{
                    marginBottom: 20,
                    padding: 14,
                    borderRadius: 8,
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid #10b981',
                    fontSize: '0.78rem',
                  }}
                >
                  <div style={{ fontWeight: 700, color: '#34d399', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>✓</span> Playbook Executed & Orchestrated Successfully!
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 150, overflowY: 'auto' }}>
                    {(execResult.actions_taken || []).map((a, i) => (
                      <div key={i} style={{ color: 'var(--text-secondary)', fontSize: '0.74rem' }}>
                        • <b style={{ color: '#c7d2fe', fontFamily: 'JetBrains Mono, monospace' }}>{a.action}</b>: {a.detail}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setSelectedPlaybook(null)}
                  style={{ padding: '10px 18px' }}
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={executing}
                  className="btn btn-primary"
                  style={{ padding: '10px 20px' }}
                >
                  {executing ? 'Enforcing Playbook...' : 'Confirm & Execute'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </PageLayout>
  );
}
