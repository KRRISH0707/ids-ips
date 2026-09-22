'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { createPortal } from 'react-dom';
import Sidebar from '@/components/Sidebar';
import BrandLogo from '@/components/BrandLogo';
import { PageLayout, Spinner, StatCard, SeverityBadge, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import { getTechniqueDetails } from '@/lib/mitreData';

export default function MitreTechniqueDetailPage() {
  const params = useParams();
  const router = useRouter();
  const techniqueId = (params?.id || 'T1190').toUpperCase();

  const [staticData, setStaticData] = useState(() => getTechniqueDetails(techniqueId));
  const [liveData, setLiveData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'adversary' | 'detection' | 'mitigations' | 'alerts'
  const [copiedKey, setCopiedKey] = useState(null);

  // Playbook execution modal state
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [targetHost, setTargetHost] = useState('192.168.1.150');
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Update static data when route params change
  useEffect(() => {
    setStaticData(getTechniqueDetails(techniqueId));
  }, [techniqueId]);

  // Fetch live correlated telemetry from backend API
  const fetchTechniqueTelemetry = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getMitreTechnique(techniqueId);
      setLiveData(res);
      if (res?.recommended_playbooks?.length > 0 && !selectedPlaybook) {
        setSelectedPlaybook(res.recommended_playbooks[0]);
      }
    } catch (err) {
      console.warn('Live MITRE API fetch note:', err.message);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [techniqueId, selectedPlaybook]);

  useEffect(() => {
    fetchTechniqueTelemetry(true);
  }, [fetchTechniqueTelemetry]);

  // Real-time synchronization: refresh live detections when live threats occur
  useOnLiveEvent(() => {
    fetchTechniqueTelemetry(false);
  });

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2500);
  };

  const handleOpenPlaybookModal = (playbook) => {
    setSelectedPlaybook(playbook || staticData?.recommendedPlaybook);
    setExecResult(null);
    if (liveData?.correlated_alerts?.[0]?.src_ip) {
      setTargetHost(liveData.correlated_alerts[0].src_ip);
    } else {
      setTargetHost('192.168.1.150');
    }
    setShowPlaybookModal(true);
  };

  const handleExecutePlaybook = async (e) => {
    e.preventDefault();
    const pb = selectedPlaybook || staticData?.recommendedPlaybook;
    if (!pb) return;

    try {
      setExecuting(true);
      // Playbook ID could be pb.id or PB-01
      const pid = pb.id || 'PB-01';
      const res = await api.executePlaybook(pid, { target: targetHost || '192.168.1.150' });
      setExecResult(res);
      await fetchTechniqueTelemetry(false);
    } catch (err) {
      alert(`Playbook execution failed: ${err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  const hitCount = liveData?.hit_count ?? 0;
  const recentAlerts = liveData?.correlated_alerts || [];
  const uniqueHosts = liveData?.unique_affected_hosts || [];

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Header & Breadcrumbs */}
      <div className="page-header" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          {/* Breadcrumbs */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 8 }}>
            <Link href="/mitre" style={{ color: 'var(--accent-cyan)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <span>← Back to MITRE Matrix</span>
            </Link>
            <span>/</span>
            <span>Techniques</span>
            <span>/</span>
            <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>{techniqueId}</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: '1rem',
                fontWeight: 800,
                padding: '4px 12px',
                borderRadius: 6,
                background: 'rgba(0, 212, 255, 0.12)',
                border: '1px solid var(--accent-cyan)',
                color: 'var(--accent-cyan)',
                letterSpacing: '0.05em'
              }}
            >
              {techniqueId}
            </span>
            <h1 className="page-title glow-text" style={{ margin: 0, fontSize: '1.65rem' }}>
              {staticData.name}
            </h1>
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '4px 10px',
                borderRadius: 4,
                background: 'rgba(124, 58, 237, 0.2)',
                border: '1px solid rgba(124, 58, 237, 0.5)',
                color: '#c4b5fd',
              }}
            >
              {staticData.tactic} ({staticData.tacticId})
            </span>
            <SeverityBadge severity={staticData.severity} />
          </div>
          <p className="page-subtitle" style={{ marginTop: 6, maxWidth: 900 }}>
            {staticData.shortDesc}
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn btn-primary"
            onClick={() => handleOpenPlaybookModal(staticData.recommendedPlaybook)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              boxShadow: '0 0 20px rgba(0, 212, 255, 0.3)',
            }}
          >
            <span>⚡ Run Containment Playbook</span>
          </button>
          <button
            className="btn btn-ghost"
            onClick={() => fetchTechniqueTelemetry(true)}
            title="Refresh live detections"
          >
            ⟳ Sync Telemetry
          </button>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <StatCard
          label="CVSS THREAT SCORE"
          value={staticData.cvssBase}
          color={staticData.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'}
          delta="Adversary Ingress Impact"
        />
        <StatCard
          label="TACTIC STAGE"
          value={staticData.tactic}
          color="var(--accent-cyan)"
          delta={`MITRE ID: ${staticData.tacticId}`}
        />
        <StatCard
          label="CORRELATED LIVE HITS"
          value={hitCount}
          color={hitCount > 0 ? '#ef4444' : '#10b981'}
          delta={hitCount > 0 ? 'Active telemetry detections' : 'No active alerts in DB'}
        />
        <StatCard
          label="AFFECTED HOSTS"
          value={uniqueHosts.length}
          color="#a855f7"
          delta={uniqueHosts.length > 0 ? `${uniqueHosts.slice(0, 2).join(', ')}...` : 'Zero endpoints compromised'}
        />
      </div>

      {/* Navigation Sub-Tabs */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          borderBottom: '1px solid var(--border-subtle)',
          marginBottom: 20,
          overflowX: 'auto',
          paddingBottom: 2,
        }}
      >
        {[
          { id: 'overview', label: '📖 Deep Technical Overview', count: null },
          { id: 'adversary', label: '🥷 Adversary Threat Groups', count: staticData.adversaryGroups?.length },
          { id: 'detection', label: '🛡️ Detection Rules (Suricata/Sigma)', count: null },
          { id: 'mitigations', label: '🔒 Official MITRE Mitigations', count: staticData.mitreMitigations?.length },
          { id: 'alerts', label: '🚨 Correlated Alerts in DB', count: hitCount },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '10px 18px',
                borderRadius: '8px 8px 0 0',
                background: isActive ? 'rgba(0, 212, 255, 0.12)' : 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                color: isActive ? '#fff' : 'var(--text-muted)',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.84rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                transition: 'all 0.15s ease',
                whiteSpace: 'nowrap',
              }}
            >
              <span>{tab.label}</span>
              {tab.count !== null && tab.count !== undefined && (
                <span
                  style={{
                    fontSize: '0.7rem',
                    padding: '2px 7px',
                    borderRadius: 10,
                    background: isActive ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.1)',
                    color: isActive ? '#000' : 'var(--text-secondary)',
                    fontWeight: 800,
                  }}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Deep Technical Overview */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Executive Narrative */}
          <div className="glass-card" style={{ padding: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
              <span style={{ fontSize: '1.2rem' }}>🔍</span>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                Executive Threat Analysis & Attack Vector
              </h3>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.7, whiteSpace: 'pre-line' }}>
              {staticData.overview}
            </div>
          </div>

          {/* Kill Chain / Attack Mechanics */}
          {staticData.attackMechanism?.length > 0 && (
            <div className="glass-card" style={{ padding: 24 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
                <span style={{ fontSize: '1.2rem' }}>⚙️</span>
                <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                  Kill Chain Progression & Attack Phases
                </h3>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
                {staticData.attackMechanism.map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      padding: 16,
                      borderRadius: 8,
                      background: 'rgba(15, 23, 42, 0.65)',
                      border: '1px solid rgba(0, 212, 255, 0.15)',
                      position: 'relative',
                    }}
                  >
                    <div
                      style={{
                        fontSize: '0.78rem',
                        fontWeight: 800,
                        color: 'var(--accent-cyan)',
                        marginBottom: 8,
                        letterSpacing: '0.04em',
                      }}
                    >
                      {step.phase}
                    </div>
                    <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                      {step.detail}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Systems, Protocols & CVEs Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 18 }}>
            {/* Target Platforms */}
            <div className="glass-card" style={{ padding: 20 }}>
              <div style={{ fontSize: '0.76rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 10 }}>
                Target Platforms & Environments
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {(staticData.platforms || []).map((p, i) => (
                  <span
                    key={i}
                    style={{
                      fontSize: '0.76rem',
                      fontWeight: 600,
                      padding: '4px 10px',
                      borderRadius: 6,
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    💻 {p}
                  </span>
                ))}
              </div>
            </div>

            {/* Targeted Protocols */}
            <div className="glass-card" style={{ padding: 20 }}>
              <div style={{ fontSize: '0.76rem', fontWeight: 700, color: '#f59e0b', textTransform: 'uppercase', marginBottom: 10 }}>
                Affected Protocols & Transport Layers
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {(staticData.protocols || []).map((proto, i) => (
                  <span
                    key={i}
                    style={{
                      fontSize: '0.76rem',
                      fontWeight: 600,
                      padding: '4px 10px',
                      borderRadius: 6,
                      background: 'rgba(245, 158, 11, 0.1)',
                      border: '1px solid rgba(245, 158, 11, 0.25)',
                      color: '#fbbf24',
                    }}
                  >
                    🌐 {proto}
                  </span>
                ))}
              </div>
            </div>

            {/* Real-World CVE References */}
            <div className="glass-card" style={{ padding: 20, gridColumn: '1 / -1' }}>
              <div style={{ fontSize: '0.76rem', fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', marginBottom: 10 }}>
                Historical & Real-World CVE References
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 10 }}>
                {(staticData.cveExamples || []).map((cve, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '10px 14px',
                      borderRadius: 6,
                      background: 'rgba(239, 68, 68, 0.08)',
                      border: '1px solid rgba(239, 68, 68, 0.25)',
                      fontSize: '0.8rem',
                      color: '#fca5a5',
                      fontFamily: 'JetBrains Mono, monospace',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                    }}
                  >
                    <span>⚠️</span>
                    <span>{cve}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Adversary Threat Groups */}
      {activeTab === 'adversary' && (
        <div className="glass-card" style={{ padding: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                Known Adversary Threat Groups & APTs
              </h3>
              <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Documented threat actors and cybercriminal syndicates observed actively weaponizing {techniqueId}.
              </p>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 14 }}>
            {(staticData.adversaryGroups || []).map((group, i) => (
              <div
                key={i}
                style={{
                  padding: 18,
                  borderRadius: 8,
                  background: 'rgba(15, 23, 42, 0.75)',
                  border: '1px solid rgba(124, 58, 237, 0.25)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.95rem', fontWeight: 800, color: '#e0e7ff' }}>
                    {group.name}
                  </span>
                  <span
                    style={{
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 4,
                      background: group.origin.includes('State') ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      border: group.origin.includes('State') ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(59, 130, 246, 0.4)',
                      color: group.origin.includes('State') ? '#fca5a5' : '#93c5fd',
                    }}
                  >
                    {group.origin}
                  </span>
                </div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
                  {group.notes}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Detection Engineering & Signatures */}
      {activeTab === 'detection' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* DPI Heuristics */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 8 }}>
              Neural Deep Packet Inspection (DPI) & Heuristics
            </div>
            <p style={{ margin: 0, fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
              {staticData.detectionLogic?.dpiAnalysis}
            </p>
          </div>

          {/* Suricata / Snort Rule */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: '1rem' }}>🛡️</span>
                <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>Suricata / Snort Signature Rule</span>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => handleCopy(staticData.detectionLogic?.suricataRule, 'suricata')}
                style={{ fontSize: '0.75rem' }}
              >
                {copiedKey === 'suricata' ? '✓ Copied!' : '📋 Copy Rule'}
              </button>
            </div>
            <pre
              style={{
                padding: 16,
                borderRadius: 6,
                background: '#090d16',
                border: '1px solid rgba(0, 212, 255, 0.2)',
                color: '#38bdf8',
                fontSize: '0.78rem',
                fontFamily: 'JetBrains Mono, monospace',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                margin: 0,
              }}
            >
              {staticData.detectionLogic?.suricataRule}
            </pre>
          </div>

          {/* Sigma Rule */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: '1rem' }}>📊</span>
                <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>Sigma SIEM Detection Rule</span>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => handleCopy(staticData.detectionLogic?.sigmaRule, 'sigma')}
                style={{ fontSize: '0.75rem' }}
              >
                {copiedKey === 'sigma' ? '✓ Copied!' : '📋 Copy Sigma'}
              </button>
            </div>
            <pre
              style={{
                padding: 16,
                borderRadius: 6,
                background: '#090d16',
                border: '1px solid rgba(124, 58, 237, 0.25)',
                color: '#c4b5fd',
                fontSize: '0.78rem',
                fontFamily: 'JetBrains Mono, monospace',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                margin: 0,
              }}
            >
              {staticData.detectionLogic?.sigmaRule}
            </pre>
          </div>

          {/* eBPF Kernel Probe */}
          {staticData.detectionLogic?.ebpfHook && (
            <div className="glass-card" style={{ padding: 22 }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#10b981', textTransform: 'uppercase', marginBottom: 8 }}>
                eBPF Kernel Ring Probe Hook
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                {staticData.detectionLogic.ebpfHook}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Official MITRE Mitigations */}
      {activeTab === 'mitigations' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="glass-card" style={{ padding: 24 }}>
            <h3 style={{ margin: '0 0 6px', fontSize: '1.05rem', fontWeight: 700 }}>
              Enterprise Hardening & Defensive Architecture
            </h3>
            <p style={{ margin: '0 0 18px', fontSize: '0.82rem', color: 'var(--text-muted)' }}>
              Standard NIST / MITRE mitigations that neutralize or substantially attenuate risks associated with {techniqueId}.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 14 }}>
              {(staticData.mitreMitigations || []).map((m, i) => (
                <div
                  key={i}
                  style={{
                    padding: 18,
                    borderRadius: 8,
                    background: 'rgba(15, 23, 42, 0.7)',
                    border: '1px solid rgba(16, 185, 129, 0.25)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span
                      style={{
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.75rem',
                        fontWeight: 800,
                        color: '#34d399',
                        padding: '2px 8px',
                        borderRadius: 4,
                        background: 'rgba(16, 185, 129, 0.15)',
                      }}
                    >
                      {m.id}
                    </span>
                    <span style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f1f5f9' }}>
                      {m.name}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {m.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* SOC Playbook Action Box */}
          <div
            className="hud-card"
            style={{
              padding: 24,
              borderLeft: '4px solid var(--accent-cyan)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 16,
            }}
          >
            <div>
              <div style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>
                RECOMMENDED SOAR PLAYBOOK
              </div>
              <h4 style={{ margin: '4px 0', fontSize: '1.1rem', fontWeight: 800 }}>
                {staticData.recommendedPlaybook?.name || 'PB-01: Ingress Quarantine'}
              </h4>
              <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                {staticData.recommendedPlaybook?.description}
              </p>
            </div>
            <button
              className="btn btn-primary"
              onClick={() => handleOpenPlaybookModal(staticData.recommendedPlaybook)}
              style={{ padding: '10px 24px' }}
            >
              ⚡ Launch Containment
            </button>
          </div>
        </div>
      )}

      {/* Tab 5: Correlated Alerts in Database */}
      {activeTab === 'alerts' && (
        <div className="glass-card" style={{ padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 700 }}>
                Live Correlated Detections in Database
              </h3>
              <p style={{ margin: '4px 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Telemetry events in PostgreSQL tagged with MITRE ATT&CK {techniqueId}.
              </p>
            </div>
            <span
              style={{
                fontSize: '0.78rem',
                fontWeight: 700,
                color: hitCount > 0 ? '#ef4444' : 'var(--text-muted)',
              }}
            >
              Total Mapped Hits: <b>{hitCount}</b>
            </span>
          </div>

          {loading ? (
            <Spinner />
          ) : recentAlerts.length === 0 ? (
            <EmptyState
              message={`No active security alerts recorded for technique ${techniqueId} in current database session.`}
            />
          ) : (
            <div className="table-wrapper">
              <table className="data-table" style={{ width: '100%', tableLayout: 'fixed', minWidth: '880px' }}>
                <thead>
                  <tr>
                    <th style={{ width: '15%', minWidth: 120 }}>Timestamp</th>
                    <th style={{ width: '45%', minWidth: 260 }}>Alert Signature</th>
                    <th style={{ width: '15%', minWidth: 130 }}>Source IP</th>
                    <th style={{ width: '12%', minWidth: 110 }}>Destination IP</th>
                    <th style={{ width: '10%', minWidth: 90 }}>Severity</th>
                    <th style={{ width: '10%', minWidth: 90, textAlign: 'center' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((alert, idx) => (
                    <tr key={idx}>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {new Date(alert.timestamp).toLocaleString()}
                      </td>
                      <td style={{ maxWidth: 360 }}>
                        <div
                          style={{
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            fontSize: '0.82rem',
                          }}
                          title={alert.signature}
                        >
                          {alert.signature}
                        </div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: '#38bdf8' }}>
                          {alert.src_ip}
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          {alert.dest_ip || '—'}
                        </span>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <SeverityBadge severity={alert.severity || 'HIGH'} />
                      </td>
                      <td style={{ whiteSpace: 'nowrap', textAlign: 'center' }}>
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => {
                            setTargetHost(alert.src_ip);
                            handleOpenPlaybookModal(staticData.recommendedPlaybook);
                          }}
                          style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)' }}
                        >
                          ⚡ Isolate IP
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* 1-Click SOAR Playbook Execution Modal (Centered via Portal) */}
      {showPlaybookModal && mounted && createPortal(
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 9999,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'rgba(5, 8, 16, 0.85)',
            backdropFilter: 'blur(12px)',
            padding: 20,
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setShowPlaybookModal(false);
          }}
        >
          {/* Ambient Glow */}
          <div
            style={{
              position: 'fixed',
              top: '35%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              width: 550,
              height: 350,
              background: 'radial-gradient(ellipse, rgba(0,212,255,0.09) 0%, transparent 70%)',
              pointerEvents: 'none',
              zIndex: 0,
            }}
          />

          <div
            className="hud-card fade-in"
            style={{
              width: '100%',
              maxWidth: 520,
              padding: '36px 32px',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 212, 255, 0.15)',
              position: 'relative',
              zIndex: 1,
              maxHeight: '92vh',
              overflowY: 'auto',
            }}
          >
            {/* Close Button */}
            <button
              onClick={() => setShowPlaybookModal(false)}
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
                <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>MITRE ATT&CK SOAR CONTAINMENT</span>
              </div>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 900, letterSpacing: '0.04em', margin: 0 }}>
                <span className="glow-gradient">{selectedPlaybook?.name || 'Mitigation Playbook'}</span>
              </h2>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4, letterSpacing: '0.02em', lineHeight: 1.4 }}>
                {selectedPlaybook?.description || 'Automated incident containment orchestration'}
              </p>
            </div>

            <form onSubmit={handleExecutePlaybook}>
              <div style={{ marginBottom: 18 }}>
                <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
                  TARGET ADVERSARY IP / ENDPOINT
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. 192.168.1.150 or 203.0.113.42"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                  style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.9rem' }}
                  required
                />
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 6 }}>
                  Technique Context: <strong style={{ color: 'var(--accent-cyan)' }}>{techniqueId}</strong> | Trigger: <strong style={{ color: '#ef4444' }}>{selectedPlaybook?.trigger_event || 'INCIDENT_RESPONSE'}</strong>
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
                    <span>✓</span> Containment Playbook Executed Successfully!
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
                  onClick={() => setShowPlaybookModal(false)}
                  disabled={executing}
                >
                  Close
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={executing}
                  style={{ minWidth: 140 }}
                >
                  {executing ? 'Executing...' : '⚡ Confirm & Fire'}
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
