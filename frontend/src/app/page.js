'use client';

import { useState, useEffect } from 'react';
import Sidebar from '@/components/Sidebar';
import AIPredictorCard from '@/components/AIPredictorCard';
import ThreatPostureGauge from '@/components/ThreatPostureGauge';
import CyberKillChain from '@/components/CyberKillChain';
import GeoThreatRadar from '@/components/GeoThreatRadar';
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

export default function DashboardPage() {
  const [alertStats, setAlertStats] = useState(null);
  const [incidentStats, setIncidentStats] = useState(null);
  const [ipsStats, setIPSStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const { messages: liveMessages, isConnected } = useLiveFeed(20);

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
            <span style={{ fontSize: '1.2rem', fontWeight: 900 }} className="glow-gradient">AEGIS-X</span>
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
        {loading ? <Spinner /> : (
          <>
            {/* KPI row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
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

            {/* Graphical Widget 1: Threat Posture Radial Gauge */}
            <div style={{ marginBottom: 24 }}>
              <ThreatPostureGauge
                score={threatScore}
                threatLevel={threatScore > 80 ? 'CRITICAL POSTURE' : threatScore > 60 ? 'ELEVATED RISK' : 'GUARDED DEFENSE'}
                mttc="1.2s"
                blockedCount={ipsStats?.active_blocks ?? 14}
              />
            </div>

            {/* Graphical Widget 2: MITRE Cyber Kill Chain Pipeline */}
            <div style={{ marginBottom: 24 }}>
              <CyberKillChain />
            </div>

            {/* Graphical Widget 3: Geo Threat Origin & Asset Targeting Radar */}
            <div style={{ marginBottom: 24 }}>
              <GeoThreatRadar />
            </div>

            {/* AI/ML Predictive Defense Engine Card */}
            <div style={{ marginBottom: 24 }}>
              <AIPredictorCard />
            </div>

            {/* Charts row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, marginBottom: 24 }}>
              {/* Severity pie */}
              <div className="glass-card" style={{ padding: 24, minWidth: 0, overflow: 'hidden' }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 20, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Alert Severity Distribution
                </h3>
                {piData.length > 0 ? (
                  <div style={{ width: '100%', height: 220, minWidth: 0 }}>
                    <ResponsiveContainer width="100%" height={220} debounce={50}>
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
              <div className="glass-card" style={{ padding: 20, display: 'flex', flexDirection: 'column' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
                  <div className="live-dot" />
                  <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    Live Feed
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

            {/* Recent open alerts table */}
            <div className="glass-card">
              <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border-subtle)' }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Recent Open Alerts
                </h3>
              </div>
              {recentAlerts.length === 0 ? (
                <EmptyState message="No open alerts — all clear!" />
              ) : (
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
              )}
            </div>
          </>
        )}
      </div>
    </PageLayout>
  );
}
