'use client';

import { useState, useEffect } from 'react';
import Sidebar from '@/components/Sidebar';
import AIPredictorCard from '@/components/AIPredictorCard';
import ThreatPostureGauge from '@/components/ThreatPostureGauge';
import CyberKillChain from '@/components/CyberKillChain';
import GeoThreatRadar from '@/components/GeoThreatRadar';
import AttackLabPanel from '@/components/AttackLabPanel';
import { PageLayout, StatCard, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useLiveFeed } from '@/lib/useLiveFeed';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from 'recharts';

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981',
};

const DASHBOARD_FEATURES = [
  { id: 'ALL',                    label: 'All Info (Scroll)',  icon: '📜' },
  { id: 'section-attack-lab',     label: 'Attack Lab',         icon: '🧪' },
  { id: 'section-posture-gauge',  label: 'Posture Gauge',      icon: '🛡️' },
  { id: 'section-kill-chain',     label: 'Kill Chain',         icon: '⛓️' },
  { id: 'section-geo-radar',      label: 'Geo Radar',          icon: '📡' },
  { id: 'section-ai-engine',      label: 'AI Threat Engine',   icon: '⚡' },
  { id: 'section-charts-and-feed',label: 'Live Telemetry',     icon: '🚨' },
  { id: 'section-recent-alerts',  label: 'Alerts Table',       icon: '📋' },
];

export default function DashboardPage() {
  const [alertStats, setAlertStats] = useState(null);
  const [incidentStats, setIncidentStats] = useState(null);
  const [ipsStats, setIPSStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const { messages: liveMessages, isConnected } = useLiveFeed(20);
  const [activeKillChainStage, setActiveKillChainStage] = useState(null);
  const [simulatedThreatScore, setSimulatedThreatScore] = useState(null);

  // Feature selection and view mode state
  const [selectedFeature, setSelectedFeature] = useState('ALL');
  const [viewMode, setViewMode] = useState('ALL'); // 'ALL' or 'FOCUS'

  const handleAttackTriggered = async (attack) => {
    setActiveKillChainStage(attack.killChainStage);
    setSimulatedThreatScore(attack.threatScore);

    try {
      await api.simulateAttack({ scenario: attack.key });
      const [as, ip, ra] = await Promise.all([
        api.getAlertsSummary(),
        api.getIPSStats(),
        api.getAlerts({ limit: 8, status: 'OPEN' }),
      ]);
      setAlertStats(as);
      setIPSStats(ip);
      setRecentAlerts(ra?.items || []);
    } catch (err) {
      console.warn('Real-time attack simulation trigger note:', err);
    }
  };

  const handleResetBaseline = () => {
    setActiveKillChainStage(null);
    setSimulatedThreatScore(null);
  };

  const handleFeatureSelect = (id) => {
    if (id === 'ALL') {
      setViewMode('ALL');
      setSelectedFeature('ALL');
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    setSelectedFeature(id);
    if (viewMode === 'ALL') {
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        el.classList.add('feature-highlight');
        setTimeout(() => el.classList.remove('feature-highlight'), 2200);
      }
    }
  };

  useEffect(() => {
    async function load() {
      try {
        const [as, is, ip, ra] = await Promise.all([
          api.getAlertsSummary(),
          api.getIncidentsSummary(),
          api.getIPSStats(),
          api.getAlerts({ limit: 8, status: 'OPEN' }),
        ]);
        setAlertStats(as);
        setIncidentStats(is);
        setIPSStats(ip);
        setRecentAlerts(ra?.items || []);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    }
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  // Compute dynamic threat score (0-100)
  const threatScore = Math.min(
    100,
    Math.max(
      32,
      (alertStats?.critical_total || 0) * 12 +
        (incidentStats?.critical_count || 0) * 18 +
        (alertStats?.high_total || 0) * 4 +
        (alertStats?.open_total || 0) * 2
    )
  );

  // Build pie data from alert stats
  const piData = alertStats ? [
    { name: 'Critical', value: alertStats.critical_total || 0, color: '#ef4444' },
    { name: 'High',     value: alertStats.high_total || 0,     color: '#f97316' },
    { name: 'Medium',   value: alertStats.medium_total || 0,   color: '#f59e0b' },
    { name: 'Low',      value: alertStats.low_total || 0,      color: '#10b981' },
  ].filter(d => d.value > 0) : [];

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Header */}
      <div className="page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
            <span style={{ fontSize: '1.2rem', fontWeight: 900, letterSpacing: '0.05em' }} className="glow-gradient">APEX SENTINEL</span>
            <span style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', background: 'rgba(0, 212, 255, 0.1)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(0, 212, 255, 0.3)', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
              PRODUCTION SOC
            </span>
          </div>
          <h1 className="page-title glow-text" style={{ fontSize: '1.5rem', fontWeight: 800 }}>Autonomous Threat Command Center</h1>
          <p className="page-subtitle">Real-time threat posture, multi-vector kill chain & autonomous neural IPS mitigation</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '4px 12px', borderRadius: 20,
            background: isConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(100, 116, 139, 0.1)',
            border: `1px solid ${isConnected ? 'rgba(16, 185, 129, 0.3)' : 'rgba(100, 116, 139, 0.3)'}`,
          }}>
            <div className={isConnected ? 'live-dot' : ''} style={!isConnected ? { width: 8, height: 8, borderRadius: '50%', background: 'var(--text-muted)' } : {}}/>
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: isConnected ? 'var(--accent-green)' : 'var(--text-muted)' }}>
              {isConnected ? 'LIVE TELEMETRY STREAM' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      <div className="page-body">
        {/* Interactive Feature Selector & Quick Jump Bar */}
        <div className="feature-quick-bar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginRight: 6 }}>
              Select Feature:
            </span>
            {DASHBOARD_FEATURES.map((feat) => {
              const isSelected = selectedFeature === feat.id;
              return (
                <button
                  key={feat.id}
                  onClick={() => handleFeatureSelect(feat.id)}
                  className={`feature-chip ${isSelected ? 'active' : ''}`}
                >
                  <span>{feat.icon}</span>
                  <span>{feat.label}</span>
                </button>
              );
            })}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>View Mode:</span>
            <div style={{ display: 'flex', background: 'rgba(0,0,0,0.4)', borderRadius: 6, padding: 2, border: '1px solid rgba(255,255,255,0.08)' }}>
              <button
                onClick={() => setViewMode('ALL')}
                style={{
                  padding: '3px 8px',
                  fontSize: '0.68rem',
                  fontWeight: 600,
                  borderRadius: 4,
                  border: 'none',
                  background: viewMode === 'ALL' ? 'var(--accent-cyan)' : 'transparent',
                  color: viewMode === 'ALL' ? '#000' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                📜 Scroll All Info
              </button>
              <button
                onClick={() => {
                  setViewMode('FOCUS');
                  if (selectedFeature === 'ALL') setSelectedFeature('section-attack-lab');
                }}
                style={{
                  padding: '3px 8px',
                  fontSize: '0.68rem',
                  fontWeight: 600,
                  borderRadius: 4,
                  border: 'none',
                  background: viewMode === 'FOCUS' ? 'var(--accent-cyan)' : 'transparent',
                  color: viewMode === 'FOCUS' ? '#000' : 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                🎯 Focus Feature
              </button>
            </div>
          </div>
        </div>

        {/* Focused View Banner */}
        {viewMode === 'FOCUS' && selectedFeature !== 'ALL' && (
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '10px 16px', marginBottom: 20, borderRadius: 8,
            background: 'rgba(0, 212, 255, 0.1)', border: '1px solid var(--accent-cyan)',
          }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>🎯</span>
              <span>Currently in <b>Focused Mode</b> showing only the selected feature.</span>
            </div>
            <button
              onClick={() => {
                setViewMode('ALL');
                setSelectedFeature('ALL');
              }}
              className="btn btn-sm"
              style={{ fontSize: '0.72rem', padding: '4px 10px', background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.2)' }}
            >
              📜 Show All Features (Scrollable)
            </button>
          </div>
        )}

        {loading ? <Spinner /> : (
          <>
            {/* KPI row */}
            {(viewMode === 'ALL' || selectedFeature === 'section-kpis') && (
              <div id="section-kpis" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 24 }}>
                <StatCard
                  label="Open Threats"
                  value={alertStats?.open_total ?? 0}
                  color="var(--sev-critical)"
                  delta={`${alertStats?.last_24h ?? 0} in last 24h`}
                />
                <StatCard
                  label="Active Incidents"
                  value={incidentStats?.investigating_count ?? 0}
                  color="var(--sev-high)"
                  delta={`${incidentStats?.critical_count ?? 0} critical`}
                />
                <StatCard
                  label="Critical Detections"
                  value={alertStats?.critical_total ?? 0}
                  color="#ef4444"
                  delta={`${alertStats?.last_hour ?? 0} in last hour`}
                />
                <StatCard
                  label="Quarantined Attackers"
                  value={ipsStats?.active_blocks ?? 0}
                  color="var(--accent-purple)"
                  delta={`${ipsStats?.last_24h ?? 0} blocked today`}
                />
              </div>
            )}

            {/* Tactical Attack Simulation Laboratory & Autonomous Resolution Pipeline */}
            {(viewMode === 'ALL' || selectedFeature === 'section-attack-lab') && (
              <div id="section-attack-lab" style={{ marginBottom: 24 }}>
                <AttackLabPanel
                  onAttackTriggered={handleAttackTriggered}
                  onResetBaseline={handleResetBaseline}
                />
              </div>
            )}

            {/* Graphical Widget 1: Threat Posture Radial Gauge */}
            {(viewMode === 'ALL' || selectedFeature === 'section-posture-gauge') && (
              <div id="section-posture-gauge" style={{ marginBottom: 24 }}>
                <ThreatPostureGauge
                  score={simulatedThreatScore ?? threatScore}
                  threatLevel={(simulatedThreatScore ?? threatScore) > 80 ? 'CRITICAL POSTURE' : (simulatedThreatScore ?? threatScore) > 60 ? 'ELEVATED RISK' : 'GUARDED DEFENSE'}
                  mttc="1.2s"
                  blockedCount={ipsStats?.active_blocks ?? 14}
                />
              </div>
            )}

            {/* Graphical Widget 2: MITRE Cyber Kill Chain Pipeline */}
            {(viewMode === 'ALL' || selectedFeature === 'section-kill-chain') && (
              <div id="section-kill-chain" style={{ marginBottom: 24 }}>
                <CyberKillChain activeStageIndex={activeKillChainStage} />
              </div>
            )}

            {/* Graphical Widget 3: Geo Threat Origin & Asset Targeting Radar */}
            {(viewMode === 'ALL' || selectedFeature === 'section-geo-radar') && (
              <div id="section-geo-radar" style={{ marginBottom: 24 }}>
                <GeoThreatRadar />
              </div>
            )}

            {/* AI/ML Predictive Defense Engine Card */}
            {(viewMode === 'ALL' || selectedFeature === 'section-ai-engine') && (
              <div id="section-ai-engine" style={{ marginBottom: 24 }}>
                <AIPredictorCard />
              </div>
            )}

            {/* Charts row */}
            {(viewMode === 'ALL' || selectedFeature === 'section-charts-and-feed') && (
              <div id="section-charts-and-feed" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 16, marginBottom: 24 }}>
                {/* Severity pie */}
                <div className="glass-card" style={{ padding: 24, minWidth: 0, overflow: 'hidden' }}>
                  <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 20, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Alert Severity Distribution
                  </h3>
                  {piData.length > 0 ? (
                    <div style={{ width: '100%', height: 240, minWidth: 0 }}>
                      <ResponsiveContainer width="100%" height={240} debounce={50}>
                        <PieChart>
                          <Pie data={piData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                            {piData.map((entry, i) => <Cell key={i} fill={entry.color} stroke="transparent" />)}
                          </Pie>
                          <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 8, color: 'var(--text-primary)', fontSize: '0.82rem' }} />
                          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <EmptyState message="No alert data" />
                  )}
                </div>

                {/* Live feed */}
                <div className="glass-card" style={{ padding: 20, display: 'flex', flexDirection: 'column', maxHeight: 360 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                    <div className="live-dot" />
                    <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                      Live Feed (WebSocket Stream)
                    </h3>
                  </div>
                  <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {liveMessages.length === 0 ? (
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem', textAlign: 'center', paddingTop: 32 }}>
                        Waiting for events…
                      </div>
                    ) : liveMessages.map((msg, i) => (
                      <div key={i} className="slide-in" style={{
                        padding: '8px 12px',
                        background: 'rgba(0,212,255,0.04)',
                        borderRadius: 8,
                        borderLeft: `3px solid ${SEVERITY_COLORS[msg.severity] || 'var(--border-normal)'}`,
                        fontSize: '0.78rem',
                      }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>
                          {msg.signature || msg.title || 'Event'}
                        </div>
                        <div style={{ color: 'var(--text-muted)' }}>
                          {msg.src_ip || msg.status || ''}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Recent open alerts table */}
            {(viewMode === 'ALL' || selectedFeature === 'section-recent-alerts') && (
              <div id="section-recent-alerts" className="glass-card" style={{ marginBottom: 24 }}>
                <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Recent Open Threat Detections
                  </h3>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    Scroll horizontally if needed on smaller displays
                  </span>
                </div>
                {recentAlerts.length === 0 ? (
                  <EmptyState message="No open alerts — all clear!" />
                ) : (
                  <div style={{ overflowX: 'auto', width: '100%', WebkitOverflowScrolling: 'touch' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Signature</th>
                          <th>Src IP</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Category</th>
                          <th>Time</th>
                        </tr>
                      </thead>
                      <tbody>
                        {recentAlerts.map((a) => (
                          <tr key={a.id}>
                            <td style={{ fontWeight: 500, maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {a.signature}
                            </td>
                            <td className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                              {a.src_ip || '—'}
                            </td>
                            <td><SeverityBadge severity={a.severity} /></td>
                            <td><StatusBadge status={a.status} /></td>
                            <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{a.category}</td>
                            <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                              {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </PageLayout>
  );
}
