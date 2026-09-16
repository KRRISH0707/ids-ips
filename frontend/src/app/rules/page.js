'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    severity: 'HIGH',
    action: 'BLOCK',
    category: 'Authentication',
    condition: { type: 'suricata', sid: 1000004 }
  });

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getRules();
      setRules(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch rules');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules();
  }, [fetchRules]);

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await api.createRule(formData);
      setShowModal(false);
      fetchRules();
    } catch (err) {
      alert(`Failed to create rule: ${err.message}`);
    }
  };

  const handleToggleActive = async (id) => {
    try {
      await api.toggleRule(id);
      fetchRules();
    } catch (err) {
      alert(`Failed to toggle rule state: ${err.message}`);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Detection Rules</h1>
          <p className="page-subtitle">Suricata, YARA, and Sigma rules deployed to detection engine nodes</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowModal(true)}>
          + Create Rule
        </button>
      </div>

      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : rules.length === 0 ? (
          <EmptyState message="No detection rules configured" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>Toggle</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</td>
                    <td>
                      <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-cyan)' }}>
                        {rule.category || 'General'}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td style={{ fontSize: '0.85rem' }}>{rule.action}</td>
                    <td>
                      <StatusBadge status={rule.enabled ? 'ACTIVE' : 'INACTIVE'} />
                    </td>
                    <td>
                      <button
                        className={`btn btn-sm ${rule.enabled ? 'btn-danger' : 'btn-primary'}`}
                        onClick={() => handleToggleActive(rule.id)}
                        style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                      >
                        {rule.enabled ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal for Creating Rule */}
      {showModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999
        }} onClick={() => setShowModal(false)}>
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 500, padding: 24 }}>
            <h3 style={{ marginTop: 0, marginBottom: 16 }}>Create Detection Rule</h3>
            <form onSubmit={handleCreate}>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Rule Name</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. Cobalt Strike Beaconing Pattern"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Description</label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. Detects abnormal C2 outbound requests"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
                <div>
                  <label className="label">Severity</label>
                  <select
                    className="select"
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="label">Action</label>
                  <select
                    className="select"
                    value={formData.action}
                    onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                  >
                    <option value="ALERT">Alert</option>
                    <option value="BLOCK">Block</option>
                    <option value="LOG">Log</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 20 }}>
                <button type="button" className="btn btn-ghost" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Create Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
