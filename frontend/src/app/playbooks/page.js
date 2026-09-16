'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('PLAYBOOKS'); // 'PLAYBOOKS' | 'HISTORY'
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [targetHost, setTargetHost] = useState('');
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [pbRes, execRes] = await Promise.all([
        api.getPlaybooks(),
        api.getPlaybookExecutions({ limit: 20 }),
      ]);
      setPlaybooks(pbRes?.items || []);
      setExecutions(execRes?.items || []);
    } catch (err) {
      console.error('Failed to load SOAR data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRunPlaybook = async (e) => {
    e.preventDefault();
    if (!selectedPlaybook) return;

    try {
      setExecuting(true);
      const res = await api.executePlaybook(selectedPlaybook.id, { target: targetHost || '192.168.1.150' });
      setExecResult(res);
      await fetchData();
    } catch (err) {
      alert(`Playbook execution failed: ${err.message}`);
    } finally {
      setExecuting(false);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">SOAR Automated Incident Response</h1>
          <p className="page-subtitle">Security Orchestration, Automation & Response playbooks for rapid threat containment</p>
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
        {loading ? (
          <Spinner />
        ) : activeTab === 'PLAYBOOKS' ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 18 }}>
            {playbooks.map((pb) => (
              <div
                key={pb.id}
                className="glass-card"
                style={{
                  padding: 22,
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between',
                  borderTop: '3px solid var(--accent-primary)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {pb.name}
                    </h3>
                    <SeverityBadge severity={pb.severity_threshold} />
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.4, margin: '8px 0 14px' }}>
                    {pb.description}
                  </p>

                  <div style={{ marginBottom: 14 }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Automated Actions
                    </span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
                      {(pb.actions || []).map((action, idx) => (
                        <span
                          key={idx}
                          style={{
                            fontSize: '0.7rem',
                            padding: '2px 8px',
                            borderRadius: 4,
                            background: 'rgba(99, 102, 241, 0.15)',
                            border: '1px solid rgba(99, 102, 241, 0.3)',
                            color: '#c7d2fe',
                            fontFamily: 'monospace',
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
                    Trigger: <b style={{ color: 'var(--text-secondary)' }}>{pb.trigger_event}</b>
                  </div>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => {
                      setSelectedPlaybook(pb);
                      setExecResult(null);
                    }}
                  >
                    ▶ Run Playbook
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="glass-card">
            {executions.length === 0 ? (
              <EmptyState message="No playbook executions recorded" />
            ) : (
              <table className="data-table">
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
                  {executions.map((ex) => (
                    <tr key={ex.id}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{ex.playbook_name}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>{ex.target || 'N/A'}</td>
                      <td>
                        <StatusBadge status={ex.status} />
                      </td>
                      <td style={{ fontSize: '0.8rem' }}>
                        <span style={{ color: '#34d399', fontWeight: 600 }}>
                          {(ex.actions_taken || []).length} Actions Executed
                        </span>
                      </td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{ex.triggered_by}</td>
                      <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {new Date(ex.executed_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>

      {/* Execution Modal */}
      {selectedPlaybook && (
        <div
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
          }}
          onClick={() => setSelectedPlaybook(null)}
        >
          <div
            className="glass-card"
            onClick={(e) => e.stopPropagation()}
            style={{ width: '100%', maxWidth: 500, padding: 24 }}
          >
            <h3 style={{ marginTop: 0, marginBottom: 8, fontSize: '1.1rem' }}>
              Execute {selectedPlaybook.name}
            </h3>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 16 }}>
              {selectedPlaybook.description}
            </p>

            <form onSubmit={handleRunPlaybook}>
              <div style={{ marginBottom: 16 }}>
                <label className="label">Target Endpoint / Hostname or IP</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. 192.168.1.150 or sensor-edge-01"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                />
              </div>

              {execResult && (
                <div
                  style={{
                    marginBottom: 16,
                    padding: 12,
                    borderRadius: 6,
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid #10b981',
                    fontSize: '0.78rem',
                  }}
                >
                  <div style={{ fontWeight: 700, color: '#34d399', marginBottom: 6 }}>
                    ✓ Playbook Executed Successfully!
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {(execResult.actions_taken || []).map((a, i) => (
                      <div key={i} style={{ color: 'var(--text-secondary)' }}>
                        • <b>{a.action}</b>: {a.detail}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button
                  type="button"
                  className="btn btn-ghost"
                  onClick={() => setSelectedPlaybook(null)}
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={executing}
                  className="btn btn-primary"
                  style={{ background: 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)', border: 'none' }}
                >
                  {executing ? 'Executing...' : 'Confirm & Execute'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
