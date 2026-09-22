'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    severity: 'HIGH',
    action: 'BLOCK',
    category: 'Authentication',
    condition: { type: 'suricata', sid: 1000004 }
  });

  const fetchRules = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getRules();
      setRules(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      if (showSpinner) setError(err.message || 'Failed to fetch rules');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRules(true);
  }, [fetchRules]);

  // Real-time synchronization
  useOnLiveEvent(() => {
    fetchRules(false);
  });

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await api.createRule(formData);
      setShowModal(false);
      setFormData({
        name: '',
        description: '',
        severity: 'HIGH',
        action: 'BLOCK',
        category: 'Authentication',
        condition: { type: 'suricata', sid: 1000004 }
      });
      fetchRules();
    } catch (err) {
      alert(`Failed to create rule: ${err.message}`);
    }
  };

  const handleToggleActive = async (id) => {
    try {
      await api.toggleRule(id);
      fetchRules(false);
    } catch (err) {
      alert(`Failed to toggle rule state: ${err.message}`);
    }
  };

  // Metrics
  const totalRules = rules.length;
  const activeRules = rules.filter(r => r.enabled).length;
  const blockRules = rules.filter(r => r.action === 'BLOCK').length;
  const criticalRules = rules.filter(r => r.severity === 'CRITICAL').length;

  const filteredRules = useMemo(() => {
    return rules.filter(r => {
      if (categoryFilter !== 'ALL' && (r.category || 'General') !== categoryFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const n = (r.name || '').toLowerCase();
        const d = (r.description || '').toLowerCase();
        const c = (r.category || '').toLowerCase();
        if (!n.includes(q) && !d.includes(q) && !c.includes(q)) return false;
      }
      return true;
    });
  }, [rules, categoryFilter, searchQuery]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>Detection Rules</h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                fontSize: '0.72rem',
                fontWeight: 700,
                color: '#10b981',
                background: 'rgba(16,185,129,0.12)',
                padding: '4px 10px',
                borderRadius: 20,
                border: '1px solid rgba(16,185,129,0.3)',
                letterSpacing: '0.04em'
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
              DPI KERNEL SYNCED
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Suricata, YARA, and Sigma signature rules compiled to real-time DPI inspection engine
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-secondary btn-sm" onClick={() => fetchRules(true)}>
            🔄 Refresh
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowModal(true)}>
            + Create Rule
          </button>
        </div>
      </div>

      {/* Enterprise Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div className="metric-card-enterprise">
          <div className="metric-label">Compiled Signatures</div>
          <div className="metric-value" style={{ color: 'var(--text-primary)' }}>
            {totalRules}
          </div>
          <div className="metric-subtext">Active Suricata SID & Sigma rulesets</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Active Enforcing</div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            {activeRules}
          </div>
          <div className="metric-subtext">Armed in memory on DPI sensor nodes</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Kernel Drops / Blocks</div>
          <div className="metric-value" style={{ color: '#ef4444' }}>
            {blockRules}
          </div>
          <div className="metric-subtext">Signatures with autonomous BLOCK verdict</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Critical Tier</div>
          <div className="metric-value" style={{ color: '#f59e0b' }}>
            {criticalRules}
          </div>
          <div className="metric-subtext">Zero-day and weaponized exploit signatures</div>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="input"
          placeholder="Search detection rules by name or pattern..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{ width: 320, fontSize: '0.82rem', padding: '6px 12px' }}
        />

        <div className="workspace-nav-bar" style={{ margin: 0, padding: 3 }}>
          {['ALL', 'Authentication', 'Malware', 'Exploitation', 'Network'].map((cat) => (
            <button
              key={cat}
              className={`workspace-tab-btn ${categoryFilter === cat ? 'active' : ''}`}
              onClick={() => setCategoryFilter(cat)}
              style={{ padding: '5px 12px', fontSize: '0.78rem' }}
            >
              {cat}
            </button>
          ))}
        </div>

        {(categoryFilter !== 'ALL' || searchQuery) && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setCategoryFilter('ALL'); setSearchQuery(''); }}>
            Reset
          </button>
        )}

        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          Showing {filteredRules.length} of {totalRules} detection rules
        </span>
      </div>

      {/* Table with Guaranteed Text Bounding */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : filteredRules.length === 0 ? (
          <EmptyState message="No detection rules match your criteria" />
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrapper">
              <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 920 }}>
                <colgroup>
                  <col style={{ width: '38%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '14%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Rule Signature & Pattern</th>
                    <th>Category</th>
                    <th>Severity</th>
                    <th>Action</th>
                    <th>Engine Status</th>
                    <th>Arm / Disarm</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                          <div
                            style={{
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                              fontSize: '0.85rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                            title={rule.name}
                          >
                            {rule.name}
                          </div>
                          {rule.description && (
                            <div
                              style={{
                                fontSize: '0.75rem',
                                color: 'var(--text-muted)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              title={rule.description}
                            >
                              {rule.description}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.12)', color: 'var(--accent-cyan)', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                          {rule.category || 'General'}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={rule.severity} />
                      </td>
                      <td>
                        <span style={{
                          fontFamily: 'monospace',
                          fontSize: '0.74rem',
                          fontWeight: 700,
                          background: rule.action === 'BLOCK' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                          color: rule.action === 'BLOCK' ? '#f87171' : '#34d399',
                          padding: '2px 6px',
                          borderRadius: 4,
                          whiteSpace: 'nowrap'
                        }}>
                          {rule.action}
                        </span>
                      </td>
                      <td>
                        <StatusBadge status={rule.enabled ? 'ACTIVE' : 'INACTIVE'} />
                      </td>
                      <td>
                        <button
                          className={`btn btn-sm ${rule.enabled ? 'btn-danger' : 'btn-primary'}`}
                          onClick={() => handleToggleActive(rule.id)}
                          style={{ padding: '3px 10px', fontSize: '0.74rem', whiteSpace: 'nowrap' }}
                        >
                          {rule.enabled ? 'Disarm Rule' : 'Arm Rule'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Centered Modal for Creating Rule */}
      {showModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20
          }}
          onClick={() => setShowModal(false)}
        >
          <div
            className="glass-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 520,
              padding: 28,
              border: '1px solid var(--border-glow)',
              boxShadow: '0 24px 60px rgba(0,0,0,0.8)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Create Detection Rule
                </h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Deploy custom Suricata / DPI inspection signature
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowModal(false)}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreate}>
              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Rule Name
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. Cobalt Strike Malleable C2 Beaconing"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Description / Behavior
                </label>
                <input
                  type="text"
                  className="input"
                  placeholder="e.g. Detects abnormal HTTP POST heartbeats with base64 payloads"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 20 }}>
                <div>
                  <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Severity
                  </label>
                  <select
                    className="select"
                    value={formData.severity}
                    onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                    style={{ width: '100%', fontSize: '0.86rem' }}
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                    Mitigation Action
                  </label>
                  <select
                    className="select"
                    value={formData.action}
                    onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                    style={{ width: '100%', fontSize: '0.86rem' }}
                  >
                    <option value="BLOCK">Block (Kernel Drop)</option>
                    <option value="ALERT">Alert Only</option>
                    <option value="LOG">Log Telemetry</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary btn-sm" style={{ padding: '6px 16px' }}>
                  Deploy Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
