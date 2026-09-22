'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';

export default function MitrePage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  const fetchMatrix = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getMitreMatrix();
      setData(res);
    } catch (err) {
      console.error('Failed to load MITRE ATT&CK matrix:', err);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMatrix(true);
  }, [fetchMatrix]);

  // Real-time synchronization: automatically re-score MITRE tactic & technique heatmaps upon any threat detection
  useOnLiveEvent(() => {
    fetchMatrix(false);
  });

  const tactics = data?.tactics || [];

  const getIntensityStyle = (intensity) => {
    if (intensity >= 3) {
      return {
        background: 'rgba(239, 68, 68, 0.25)',
        border: '1px solid #ef4444',
        boxShadow: '0 0 12px rgba(239, 68, 68, 0.25)',
        color: '#fca5a5',
      };
    }
    if (intensity >= 2) {
      return {
        background: 'rgba(249, 115, 22, 0.2)',
        border: '1px solid #f97316',
        color: '#fdba74',
      };
    }
    if (intensity >= 1) {
      return {
        background: 'rgba(59, 130, 246, 0.2)',
        border: '1px solid #3b82f6',
        color: '#93c5fd',
      };
    }
    return {
      background: 'rgba(255, 255, 255, 0.02)',
      border: '1px solid rgba(255, 255, 255, 0.05)',
      color: 'var(--text-muted)',
    };
  };

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">MITRE ATT&CK® Enterprise Matrix</h1>
          <p className="page-subtitle">Real-time threat coverage heatmap mapping adversary tactics and techniques</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Mapped Detections: <b style={{ color: 'var(--accent-cyan)' }}>{data?.total_mapped_detections || 0}</b>
          </span>
          <button className="btn btn-ghost btn-sm" onClick={fetchMatrix}>
            ⟳ Sync Matrix
          </button>
        </div>
      </div>

      {/* Top Threat Techniques Bar */}
      {data?.top_techniques?.length > 0 && (
        <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 16 }}>
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Top Active Vectors:
          </span>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {data.top_techniques.map((t) => (
              <Link
                key={t.id}
                href={`/mitre/${t.id}`}
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  padding: '3px 10px',
                  borderRadius: 4,
                  background: 'rgba(239, 68, 68, 0.15)',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  color: '#fca5a5',
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                  transition: 'all 0.15s ease',
                }}
                title={`Open descriptive dossier for ${t.id}`}
              >
                <span>{t.id} ({t.hits} hits)</span>
                <span>↗</span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Matrix Grid */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: selectedTechnique ? '1fr 340px' : '1fr', gap: 18 }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: 12,
                alignItems: 'start',
              }}
            >
              {tactics.map((tactic) => (
                <div
                  key={tactic.id}
                  className="glass-card"
                  style={{ padding: 12, background: 'rgba(15, 23, 42, 0.6)' }}
                >
                  {/* Tactic Header */}
                  <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: 8, marginBottom: 10 }}>
                    <div style={{ fontSize: '0.68rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                      {tactic.id}
                    </div>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: 2 }}>
                      {tactic.name}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 2 }}>
                      {tactic.total_hits} detection{tactic.total_hits === 1 ? '' : 's'}
                    </div>
                  </div>

                  {/* Techniques Tiles */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {tactic.techniques.map((tech) => {
                      const style = getIntensityStyle(tech.intensity);
                      const isSelected = selectedTechnique?.id === tech.id;
                      return (
                        <div
                          key={tech.id}
                          onClick={() => setSelectedTechnique(tech)}
                          style={{
                            padding: '8px 10px',
                            borderRadius: 6,
                            cursor: 'pointer',
                            transition: 'all 0.2s ease',
                            border: isSelected ? '1px solid #fff' : style.border,
                            background: style.background,
                            boxShadow: isSelected ? '0 0 10px rgba(255,255,255,0.3)' : style.boxShadow,
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 700, color: style.color }}>
                              {tech.id}
                            </span>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                              {tech.hit_count > 0 && (
                                <span
                                  style={{
                                    fontSize: '0.65rem',
                                    fontWeight: 800,
                                    background: tech.hit_count > 2 ? '#ef4444' : '#3b82f6',
                                    color: '#fff',
                                    padding: '1px 5px',
                                    borderRadius: 8,
                                  }}
                                >
                                  {tech.hit_count}
                                </span>
                              )}
                              <Link
                                href={`/mitre/${tech.id}`}
                                onClick={(e) => e.stopPropagation()}
                                style={{
                                  fontSize: '0.65rem',
                                  fontWeight: 700,
                                  color: 'var(--accent-cyan)',
                                  background: 'rgba(0, 212, 255, 0.08)',
                                  border: '1px solid rgba(0, 212, 255, 0.3)',
                                  borderRadius: 4,
                                  padding: '1px 6px',
                                  textDecoration: 'none',
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 2,
                                  transition: 'all 0.15s ease',
                                }}
                                title={`Open full descriptive details for ${tech.id}`}
                              >
                                Dossier ↗
                              </Link>
                            </div>
                          </div>
                          <div style={{ fontSize: '0.75rem', fontWeight: 600, marginTop: 4, color: 'var(--text-secondary)' }}>
                            {tech.name}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            {/* Technique Detail Drawer */}
            {selectedTechnique && (
              <div className="glass-card" style={{ padding: 20 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                      {selectedTechnique.id}
                    </span>
                    <h3 style={{ margin: '2px 0 0', fontSize: '0.95rem', fontWeight: 700 }}>
                      {selectedTechnique.name}
                    </h3>
                  </div>
                  <button
                    onClick={() => setSelectedTechnique(null)}
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                  >
                    ✕
                  </button>
                </div>

                {/* Prominent Deep Technical Dossier Button */}
                <Link
                  href={`/mitre/${selectedTechnique.id}`}
                  className="btn btn-primary"
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: 8,
                    textDecoration: 'none',
                    marginBottom: 14,
                    padding: '10px 14px',
                    fontSize: '0.84rem',
                    fontWeight: 700,
                    boxShadow: '0 0 16px rgba(0, 212, 255, 0.25)',
                  }}
                >
                  <span>🔍 Open Full Descriptive Dossier</span>
                  <span>→</span>
                </Link>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 16 }}>
                  Total Correlated Hits: <b style={{ color: '#fff' }}>{selectedTechnique.hit_count}</b>
                </div>

                <div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Matching Trigger Alerts
                  </span>

                  {selectedTechnique.recent_alerts?.length === 0 ? (
                    <div style={{ marginTop: 8, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      No live alerts matching this technique yet.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
                      {selectedTechnique.recent_alerts.map((a, i) => (
                        <div
                          key={i}
                          style={{
                            padding: 10,
                            borderRadius: 6,
                            background: 'rgba(255, 255, 255, 0.03)',
                            border: '1px solid rgba(255, 255, 255, 0.05)',
                            fontSize: '0.78rem',
                          }}
                        >
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 3 }}>
                            {a.signature}
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                            <span>Src: <b style={{ fontFamily: 'monospace' }}>{a.src_ip}</b></span>
                            <span>{new Date(a.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
