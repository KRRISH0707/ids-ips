'use client';

import { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';

export default function AIPredictorCard() {
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const fetchForecast = useCallback(async () => {
    try {
      setLoading(true);
      const data = await api.getAIForecast();
      setForecast(data);
    } catch (err) {
      console.error('Failed to load AI threat forecast:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchForecast();
    const interval = setInterval(fetchForecast, 8000);
    return () => clearInterval(interval);
  }, [fetchForecast]);

  const handleTestPrediction = async () => {
    try {
      setEvaluating(true);
      const sampleAttack = {
        src_ip: '198.51.100.42',
        dst_ip: '10.0.1.5',
        dst_port: 445,
        protocol: 'TCP',
        signature: 'ET MALWARE Cobalt Strike Beacon Malleable C2 Detected',
        category: 'trojan-activity',
        severity: 'CRITICAL',
        risk_score: 95,
      };
      const res = await api.predictThreat(sampleAttack);
      setTestResult(res);
      await fetchForecast();
    } catch (err) {
      alert(`AI Inference failed: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  const threatLevel = forecast?.global_ai_threat_level || 'NORMAL';
  const anomalyScore = forecast?.average_anomaly_score ?? 0.18;
  const isElevated = threatLevel === 'ELEVATED' || anomalyScore >= 0.5;

  return (
    <div
      className="glass-card"
      style={{
        position: 'relative',
        overflow: 'hidden',
        border: isElevated ? '1px solid rgba(239, 68, 68, 0.4)' : '1px solid rgba(59, 130, 246, 0.25)',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.5) 100%)',
        boxShadow: isElevated ? '0 0 25px rgba(239, 68, 68, 0.15)' : '0 0 20px rgba(59, 130, 246, 0.1)',
      }}
    >
      {/* Background neon ambient pulse */}
      <div
        style={{
          position: 'absolute',
          top: -40,
          right: -40,
          width: 140,
          height: 140,
          borderRadius: '50%',
          background: isElevated ? 'radial-gradient(circle, rgba(239, 68, 68, 0.25) 0%, transparent 70%)' : 'radial-gradient(circle, rgba(59, 130, 246, 0.2) 0%, transparent 70%)',
          filter: 'blur(20px)',
          pointerEvents: 'none',
        }}
      />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '1.2rem' }}>⚡</span>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              AI/ML Predictive Defense Engine
            </h3>
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 800,
                padding: '2px 6px',
                borderRadius: 4,
                background: 'rgba(139, 92, 246, 0.2)',
                border: '1px solid #8b5cf6',
                color: '#c4b5fd',
                letterSpacing: '0.08em',
              }}
            >
              MULTI-VECTOR NEURAL v2.4
            </span>
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Real-time trajectory forecasting, anomaly scoring & automated endpoint containment
          </p>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={fetchForecast}
            disabled={loading}
            className="btn btn-ghost btn-sm"
            style={{ fontSize: '0.75rem', padding: '4px 8px' }}
            title="Refresh AI Inferences"
          >
            {loading ? '⟳ Refreshing...' : '⟳ Sync'}
          </button>
          <button
            onClick={handleTestPrediction}
            disabled={evaluating}
            className="btn btn-primary btn-sm"
            style={{
              fontSize: '0.75rem',
              padding: '4px 10px',
              background: 'linear-gradient(135deg, #6366f1 0%, #a855f7 100%)',
              border: 'none',
              boxShadow: '0 0 12px rgba(139, 92, 246, 0.4)',
            }}
          >
            {evaluating ? 'Analyzing...' : 'Simulate AI Ingest'}
          </button>
        </div>
      </div>

      {/* Gauges & Summary Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, marginBottom: 18 }}>
        {/* Threat Level */}
        <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Level Forecast</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: '50%',
                background: isElevated ? '#ef4444' : '#10b981',
                display: 'inline-block',
                boxShadow: isElevated ? '0 0 8px #ef4444' : '0 0 8px #10b981',
              }}
            />
            <span style={{ fontSize: '1.2rem', fontWeight: 800, color: isElevated ? '#f87171' : '#34d399' }}>
              {threatLevel}
            </span>
          </div>
        </div>

        {/* Anomaly Score Bar */}
        <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            <span>Network Anomaly Index</span>
            <span style={{ fontWeight: 700, color: anomalyScore > 0.6 ? '#f87171' : '#60a5fa' }}>{Math.round(anomalyScore * 100)}%</span>
          </div>
          <div style={{ marginTop: 8, height: 8, borderRadius: 4, background: 'rgba(255,255,255,0.08)', overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${Math.min(100, Math.max(8, anomalyScore * 100))}%`,
                borderRadius: 4,
                background: anomalyScore > 0.6
                  ? 'linear-gradient(90deg, #f59e0b 0%, #ef4444 100%)'
                  : 'linear-gradient(90deg, #3b82f6 0%, #8b5cf6 100%)',
                transition: 'width 0.4s ease',
              }}
            />
          </div>
        </div>

        {/* Quarantined / High-Risk Machines */}
        <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Compromised Endpoints</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 4 }}>
            <span style={{ fontSize: '1.2rem', fontWeight: 800, color: (forecast?.isolated_machines_count || 0) > 0 ? '#f87171' : 'var(--text-primary)' }}>
              {forecast?.isolated_machines_count || 0}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Isolated ({forecast?.high_risk_hosts?.length || 0} High Risk)
            </span>
          </div>
        </div>

        {/* AI Action Status */}
        <div style={{ background: 'rgba(0, 0, 0, 0.3)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Containment Protocol</div>
          <div style={{ marginTop: 4, fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8' }}>
            Automated IPS Isolation: ON
          </div>
        </div>
      </div>

      {/* Trajectory & Recommendations */}
      {forecast?.recommendation && (
        <div
          style={{
            padding: '10px 14px',
            marginBottom: 16,
            borderRadius: 6,
            background: isElevated ? 'rgba(239, 68, 68, 0.12)' : 'rgba(59, 130, 246, 0.1)',
            borderLeft: `4px solid ${isElevated ? 'var(--sev-critical)' : 'var(--accent-primary)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.9rem' }}>🛡️</span>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              {forecast.recommendation}
            </span>
          </div>
          {forecast?.high_risk_hosts?.length > 0 && (
            <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#f87171' }}>
              Target: {forecast.high_risk_hosts.join(', ')}
            </span>
          )}
        </div>
      )}

      {/* Latest AI Neural Predictions Stream */}
      {forecast?.latest_predictions?.length > 0 && (
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.05em' }}>
            Live Neural Threat Classifications & Next-Stage Forecast
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {forecast.latest_predictions.map((p, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '8px 12px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  borderRadius: 6,
                  border: '1px solid rgba(255, 255, 255, 0.04)',
                  fontSize: '0.8rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span
                    style={{
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: 4,
                      background: p.anomaly_score > 0.8 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(59, 130, 246, 0.2)',
                      color: p.anomaly_score > 0.8 ? '#f87171' : '#60a5fa',
                      fontSize: '0.7rem',
                    }}
                  >
                    {p.attack_family}
                  </span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {p.compromised_host_ip}
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                    Next Phase: <b style={{ color: '#fbbf24' }}>{p.predicted_next_stage}</b>
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Confidence: <b>{Math.round(p.confidence * 100)}%</b>
                  </span>
                  {p.auto_isolation_required ? (
                    <span style={{ color: '#f87171', fontWeight: 700, fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }}></span>
                      ISOLATION TRIGGERED
                    </span>
                  ) : (
                    <span style={{ color: '#34d399', fontSize: '0.7rem' }}>MONITORED</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manual interactive simulation preview if triggered */}
      {testResult && (
        <div
          style={{
            marginTop: 14,
            padding: 12,
            background: 'rgba(99, 102, 241, 0.1)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            borderRadius: 6,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#c7d2fe' }}>
              ✦ Instant AI Neural Inference Output:
            </span>
            <button
              onClick={() => setTestResult(null)}
              style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.8rem' }}
            >
              ✕
            </button>
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 8 }}>
            <div>Family: <b style={{ color: '#f87171' }}>{testResult.attack_family}</b></div>
            <div>Anomaly Score: <b>{testResult.anomaly_score}</b></div>
            <div>Forecast: <b style={{ color: '#fbbf24' }}>{testResult.predicted_next_stage}</b></div>
            <div>Recommended Action: <b>{testResult.recommended_action}</b></div>
          </div>
        </div>
      )}
    </div>
  );
}
