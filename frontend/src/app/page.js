'use client';

import { useState, useEffect } from 'react';
import Sidebar from '@/components/Sidebar';
import AIPredictorCard from '@/components/AIPredictorCard';
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
          <h1 className="page-title glow-text">Security Dashboard</h1>
          <p className="page-subtitle">Real-time threat visibility & operations overview</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className={isConnected ? 'live-dot' : ''} style={!isConnected ? { width: 8, height: 8, borderRadius: '50%', background: 'var(--text-muted)' } : {}}/>
          <span style={{ fontSize: '0.78rem', color: isConnected ? 'var(--accent-green)' : 'var(--text-muted)' }}>
            {isConnected ? 'LIVE' : 'OFFLINE'}
          </span>
        </div>
      </div>

      <div className="page-body">
        {loading ? <Spinner /> : (
          <>
            {/* KPI row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 24 }}>
              <StatCard
                label="Open Alerts"
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
                label="Critical Alerts"
                value={alertStats?.critical_total ?? 0}
                color="#ef4444"
                delta={`${alertStats?.last_hour ?? 0} in last hour`}
              />
              <StatCard
                label="Blocked IPs"
                value={ipsStats?.active_blocks ?? 0}
                color="var(--accent-purple)"
                delta={`${ipsStats?.last_24h ?? 0} blocked today`}
              />
            </div>

            {/* AI/ML Predictive Defense Engine Card */}
            <div style={{ marginBottom: 24 }}>
              <AIPredictorCard />
            </div>

            {/* Charts row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16, marginBottom: 24 }}>
              {/* Severity pie */}
              <div className="glass-card" style={{ padding: 24 }}>
                <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 20, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Alert Severity Distribution
                </h3>
                {piData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={piData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                        {piData.map((entry, i) => <Cell key={i} fill={entry.color} stroke="transparent" />)}
                      </Pie>
                      <Tooltip contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 8, color: 'var(--text-primary)', fontSize: '0.82rem' }} />
                      <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }} />
                    </PieChart>
                  </ResponsiveContainer>
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
