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
    rule_type: 'suricata',
    severity: 'high',
    signature: 'alert ip any any -> any any (msg:"Custom Rule Match"; sid:1000001; rev:1;)',
    is_active: true
  });

  const fetchRules = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getRules();
      setRules(res.data || []);
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

  const handleToggleActive = async (rule) => {
    try {
      await api.updateRule(rule.id, { is_active: !rule.is_active });
      fetchRules();
    } catch (err) {
      alert(`Failed to update rule state: ${err.message}`);
    }
  };

  return (
    <Sidebar>
      <PageLayout
        title="Detection Rules"
        subtitle="Suricata, YARA, and Sigma rules deployed to detection engine nodes"
        actions={
          <button className="btn btn-primary btn-sm" onClick={() => setShowModal(true)}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12h14" />
            </svg>
            Create Rule
          </button>
        }
      >
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="card" style={{ borderColor: 'var(--color-danger-border)', color: 'var(--color-danger)' }}>
            {error}
          </div>
        ) : rules.length === 0 ? (
          <EmptyState
            title="No Rules Configured"
            description="Create custom Suricata or YARA signatures to expand threat detection capabilities."
          />
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Severity</th>
                  <th>Signature / Pattern</th>
                  <th>Status</th>
                  <th>Toggle</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      #{rule.id}
                    </td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rule.name}</td>
                    <td>
                      <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.1)', color: 'var(--accent-cyan)' }}>
                        {rule.rule_type.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {rule.signature}
                    </td>
                    <td>
                      <StatusBadge status={rule.is_active ? 'active' : 'inactive'} />
                    </td>
                    <td>
                      <button
                        className={`btn btn-sm ${rule.is_active ? 'btn-danger' : 'btn-primary'}`}
                        onClick={() => handleToggleActive(rule)}
                        style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                      >
                        {rule.is_active ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Modal for Creating Rule */}
        {showModal && (
          <div className="modal-backdrop" onClick={() => setShowModal(false)}>
            <div className="modal-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 560 }}>
              <h3 style={{ marginTop: 0, marginBottom: 16 }}>Create Detection Rule</h3>
              <form onSubmit={handleCreate}>
                <div className="form-group">
                  <label className="form-label">Rule Name</label>
                  <input
                    type="text"
                    className="form-input"
                    required
                    placeholder="e.g. Cobalt Strike Beaconing Pattern"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div className="form-group">
                    <label className="form-label">Rule Type</label>
                    <select
                      className="form-select"
                      value={formData.rule_type}
                      onChange={(e) => setFormData({ ...formData, rule_type: e.target.value })}
                    >
                      <option value="suricata">Suricata NIDS</option>
                      <option value="yara">YARA</option>
                      <option value="sigma">Sigma</option>
                      <option value="custom">Custom Anomaly</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Severity Level</label>
                    <select
                      className="form-select"
                      value={formData.severity}
                      onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    >
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
                <div className="form-group">
                  <label className="form-label">Signature Definition</label>
                  <textarea
                    className="form-input"
                    rows="4"
                    required
                    style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
                    value={formData.signature}
                    onChange={(e) => setFormData({ ...formData, signature: e.target.value })}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 24 }}>
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
    </Sidebar>
  );
}
