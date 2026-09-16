'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';

export default function ThreatIntelPage() {
  const [intel, setIntel] = useState([]);
  const [breakdown, setBreakdown] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookingUp, setLookingUp] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIOC, setNewIOC] = useState({ ioc_type: 'IP', value: '', threat_type: '', confidence: 90, source: 'SOC Analyst' });

  const fetchIntel = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getThreatIntel();
      setIntel(res?.items || []);
      setBreakdown(res?.breakdown || {});
    } catch (err) {
      console.error('Failed to load threat intel:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntel();
  }, [fetchIntel]);

  const handleLookup = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    try {
      setLookingUp(true);
      const res = await api.lookupThreatIndicator({ value: searchQuery.trim() });
      setLookupResult(res);
    } catch (err) {
      alert(`Lookup failed: ${err.message}`);
    } finally {
      setLookingUp(false);
    }
  };

  const handleAddIOC = async (e) => {
    e.preventDefault();
    try {
      await api.addThreatIndicator(newIOC);
      setShowAddModal(false);
      setNewIOC({ ioc_type: 'IP', value: '', threat_type: '', confidence: 90, source: 'SOC Analyst' });
      await fetchIntel();
    } catch (err) {
      alert(`Failed to add indicator: ${err.message}`);
    }
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">Threat Intelligence Hub</h1>
          <p className="page-subtitle">Real-time Indicators of Compromise (IOC) matching & global reputation scoring</p>
        </div>
        <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
          + Ingest IOC
        </button>
      </div>

      {/* Quick Lookup Bar */}
      <div className="glass-card" style={{ padding: '18px 24px', marginBottom: 20 }}>
        <form onSubmit={handleLookup} style={{ display: 'flex', gap: 12 }}>
          <input
            type="text"
            className="input"
            style={{ flex: 1 }}
            placeholder="Search or lookup reputation for any IP, Domain, or File Hash (e.g. 45.33.32.156, update-service-cdn-telemetry.org)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          <button
            type="submit"
            disabled={lookingUp}
            className="btn btn-primary"
            style={{ padding: '0 24px' }}
          >
            {lookingUp ? 'Checking...' : 'Check Reputation'}
          </button>
        </form>

        {/* Lookup Result Card */}
        {lookupResult && (
          <div
            style={{
              marginTop: 16,
              padding: 16,
              borderRadius: 8,
              background: lookupResult.reputation_level === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${lookupResult.reputation_level === 'MALICIOUS' ? '#ef4444' : '#10b981'}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: '1.2rem' }}>
                  {lookupResult.reputation_level === 'MALICIOUS' ? '🚨' : '🛡️'}
                </span>
                <span style={{ fontWeight: 700, fontSize: '1rem', color: lookupResult.reputation_level === 'MALICIOUS' ? '#f87171' : '#34d399' }}>
                  {lookupResult.reputation_level}: {lookupResult.threat_family}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Query: <b style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{lookupResult.query}</b> | Source: {lookupResult.source}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Confidence</div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: lookupResult.reputation_score > 80 ? '#f87171' : '#60a5fa' }}>
                {lookupResult.reputation_score}%
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Feed Breakdown Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid var(--accent-cyan)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Active IOCs</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: 2 }}>{intel.length}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #ef4444' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Malicious IPs</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f87171', marginTop: 2 }}>{breakdown['IP'] || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #f59e0b' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Hostile Domains</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fbbf24', marginTop: 2 }}>{breakdown['DOMAIN'] || 0}</div>
        </div>
        <div className="glass-card" style={{ padding: '12px 18px', borderLeft: '4px solid #8b5cf6' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Malware Hashes</div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#c084fc', marginTop: 2 }}>{breakdown['HASH'] || 0}</div>
        </div>
      </div>

      {/* Table */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : intel.length === 0 ? (
          <EmptyState message="No threat intelligence indicators found" />
        ) : (
          <div className="glass-card">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Indicator Value</th>
                  <th>Threat Classification</th>
                  <th>Confidence</th>
                  <th>Intel Source</th>
                  <th>Tags</th>
                  <th>Ingested At</th>
                </tr>
              </thead>
              <tbody>
                {intel.map((row) => (
                  <tr key={row.id}>
                    <td>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          fontWeight: 800,
                          padding: '2px 6px',
                          borderRadius: 4,
                          background: row.ioc_type === 'IP' ? 'rgba(59, 130, 246, 0.2)' : row.ioc_type === 'DOMAIN' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(139, 92, 246, 0.2)',
                          color: row.ioc_type === 'IP' ? '#60a5fa' : row.ioc_type === 'DOMAIN' ? '#fbbf24' : '#c084fc',
                        }}
                      >
                        {row.ioc_type}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                      {row.value}
                    </td>
                    <td style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f87171' }}>
                      {row.threat_type}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 45, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.1)', overflow: 'hidden' }}>
                          <div style={{ width: `${row.confidence}%`, height: '100%', background: '#ef4444' }} />
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700 }}>{row.confidence}%</span>
                      </div>
                    </td>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{row.source}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {(row.tags || []).map((t, i) => (
                          <span
                            key={i}
                            style={{
                              fontSize: '0.65rem',
                              padding: '1px 5px',
                              borderRadius: 3,
                              background: 'rgba(255,255,255,0.05)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {new Date(row.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add IOC Modal */}
      {showAddModal && (
        <div
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
            background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
          }}
          onClick={() => setShowAddModal(false)}
        >
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 440, padding: 24 }}>
            <h3 style={{ marginTop: 0, marginBottom: 16 }}>Add Threat Indicator</h3>
            <form onSubmit={handleAddIOC}>
              <div style={{ marginBottom: 12 }}>
                <label className="label">Indicator Type</label>
                <select
                  className="input"
                  value={newIOC.ioc_type}
                  onChange={(e) => setNewIOC({ ...newIOC, ioc_type: e.target.value })}
                >
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain Name</option>
                  <option value="HASH">SHA256 Hash</option>
                  <option value="URL">URL</option>
                </select>
              </div>

              <div style={{ marginBottom: 12 }}>
                <label className="label">Indicator Value</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. 198.51.100.44 or malware-c2.net"
                  value={newIOC.value}
                  onChange={(e) => setNewIOC({ ...newIOC, value: e.target.value })}
                />
              </div>

              <div style={{ marginBottom: 12 }}>
                <label className="label">Threat Classification</label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. COBALT_STRIKE_BEACON"
                  value={newIOC.threat_type}
                  onChange={(e) => setNewIOC({ ...newIOC, threat_type: e.target.value })}
                />
              </div>

              <div style={{ marginBottom: 16 }}>
                <label className="label">Confidence Score (1-100)</label>
                <input
                  type="number"
                  className="input"
                  min="1"
                  max="100"
                  value={newIOC.confidence}
                  onChange={(e) => setNewIOC({ ...newIOC, confidence: parseInt(e.target.value, 10) })}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-ghost" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
