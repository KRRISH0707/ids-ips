'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import PCAPViewerModal from '@/components/PCAPViewerModal';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

const STATUSES = ['', 'OPEN', 'AUTO_BLOCKED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [batchResolving, setBatchResolving] = useState(false);
  const [severity, setSeverity] = useState('');
  const [alertStatus, setAlertStatus] = useState('');
  const [selectedAlertForPCAP, setSelectedAlertForPCAP] = useState(null);
  const [skip, setSkip] = useState(0);
  const limit = 25;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = { limit, skip };
      if (severity) params.severity = severity;
      if (alertStatus) params.status = alertStatus;
      const data = await api.getAlerts(params);
      setAlerts(data?.items || []);
      setTotal(data?.total || 0);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [severity, alertStatus, skip]);

  useEffect(() => { load(); }, [load]);

  const handleStatusChange = async (id, newStatus) => {
    try {
      await api.updateAlertStatus(id, newStatus);
      load();
    } catch (e) {
      alert(e.message);
    }
  };

  const handleBatchResolve = async (flag) => {
    try {
      setBatchResolving(true);
      const payload = flag === 'OPEN' ? { resolve_all_open: true } : { resolve_all_blocked: true };
      await api.batchResolveAlerts(payload);
      load();
    } catch (e) {
      alert(e.message);
    } finally {
      setBatchResolving(false);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">{total} total alerts</p>
        </div>
      </div>
      <div className="page-body">
        {/* Filters & Actions */}
        <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <select id="filter-severity" className="select" style={{ width: 160 }} value={severity} onChange={e => { setSeverity(e.target.value); setSkip(0); }}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
          </select>
          <select id="filter-status" className="select" style={{ width: 180 }} value={alertStatus} onChange={e => { setAlertStatus(e.target.value); setSkip(0); }}>
            {STATUSES.map(s => <option key={s} value={s}>{s ? s.replace(/_/g, ' ') : 'All Statuses'}</option>)}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={() => { setSeverity(''); setAlertStatus(''); setSkip(0); }}>
            Reset
          </button>

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginLeft: 'auto' }}>
            <button
              className="btn btn-sm"
              disabled={batchResolving}
              style={{
                background: 'rgba(16, 185, 129, 0.12)',
                color: 'var(--accent-green)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                fontSize: '0.75rem',
                padding: '5px 12px',
              }}
              onClick={() => handleBatchResolve('OPEN')}
              title="Batch resolve all OPEN alerts"
            >
              ✓ Resolve All Open
            </button>
            <button
              className="btn btn-sm"
              disabled={batchResolving}
              style={{
                background: 'rgba(124, 58, 237, 0.12)',
                color: 'var(--accent-purple)',
                border: '1px solid rgba(124, 58, 237, 0.3)',
                fontSize: '0.75rem',
                padding: '5px 12px',
              }}
              onClick={() => handleBatchResolve('BLOCKED')}
              title="Batch resolve all AUTO_BLOCKED threats"
            >
              🛡️ Resolve All Quarantined
            </button>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 8 }}>
              Showing {total === 0 ? 0 : skip + 1}–{Math.min(skip + limit, total)} of {total}
            </span>
          </div>
        </div>

        {/* Table */}
        <div className="glass-card">
          {loading ? <Spinner /> : alerts.length === 0 ? <EmptyState message="No alerts match your filters" /> : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Signature</th>
                  <th>Src → Dst</th>
                  <th>Proto</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id}>
                    <td style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 500 }}>
                      {a.signature}
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {a.src_ip || '?'}:{a.src_port || '*'} → {a.dst_ip || '?'}:{a.dst_port || '*'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{a.protocol || '—'}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td><StatusBadge status={a.status} /></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 40, height: 4, borderRadius: 2, background: 'var(--bg-highlight)', overflow: 'hidden' }}>
                          <div style={{ width: `${a.risk_score}%`, height: '100%', background: a.risk_score > 75 ? '#ef4444' : a.risk_score > 50 ? '#f97316' : '#f59e0b' }} />
                        </div>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{a.risk_score}</span>
                      </div>
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {a.timestamp ? new Date(a.timestamp).toLocaleString() : '—'}
                    </td>
                    <td style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <button
                        className="btn btn-ghost btn-sm"
                        style={{ fontSize: '0.72rem', padding: '4px 8px', border: '1px solid var(--border-subtle)' }}
                        title="Deep Packet Inspection & PCAP Trace"
                        onClick={() => setSelectedAlertForPCAP(a.id)}
                      >
                        📦 DPI
                      </button>
                      {a.status !== 'RESOLVED' && (
                        <button
                          className="btn btn-sm"
                          style={{
                            fontSize: '0.7rem',
                            padding: '4px 8px',
                            background: 'rgba(16, 185, 129, 0.12)',
                            color: 'var(--accent-green)',
                            border: '1px solid rgba(16, 185, 129, 0.3)',
                          }}
                          title="Mark alert as Resolved"
                          onClick={() => handleStatusChange(a.id, 'RESOLVED')}
                        >
                          ✓ Resolve
                        </button>
                      )}
                      <select
                        className="select"
                        style={{ width: 140, padding: '4px 8px', fontSize: '0.75rem' }}
                        value={a.status}
                        onChange={e => handleStatusChange(a.id, e.target.value)}
                      >
                        {['OPEN', 'AUTO_BLOCKED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(s =>
                          <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
                        )}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
          <button className="btn btn-ghost btn-sm" disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - limit))}>
            ← Prev
          </button>
          <button className="btn btn-ghost btn-sm" disabled={skip + limit >= total} onClick={() => setSkip(skip + limit)}>
            Next →
          </button>
        </div>
      </div>

      {/* PCAP / DPI Forensics Modal */}
      {selectedAlertForPCAP && (
        <PCAPViewerModal
          alertId={selectedAlertForPCAP}
          onClose={() => setSelectedAlertForPCAP(null)}
        />
      )}
    </PageLayout>
  );
}
