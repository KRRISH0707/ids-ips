'use client';

import React, { useState, useEffect, useMemo, useRef } from 'react';

/**
 * Web Audio Synthesizer for Tactical SOC Audio Feedback
 * Synthesizes clean, high-tech interface sounds without external audio assets.
 */
function playTactileSound(type = 'click') {
  if (typeof window === 'undefined') return;
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    if (ctx.state === 'suspended') {
      ctx.resume();
    }
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    const now = ctx.currentTime;
    if (type === 'click') {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === 'mode') {
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(300, now);
      osc.frequency.exponentialRampToValueAtTime(900, now + 0.12);
      gain.gain.setValueAtTime(0.12, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.12);
      osc.start(now);
      osc.stop(now + 0.12);
    } else if (type === 'scan') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(1200, now);
      osc.frequency.linearRampToValueAtTime(1600, now + 0.03);
      gain.gain.setValueAtTime(0.04, now);
      gain.gain.linearRampToValueAtTime(0.001, now + 0.03);
      osc.start(now);
      osc.stop(now + 0.03);
    }
  } catch (e) {
    // Ignore audio context block if user hasn't interacted yet
  }
}

/**
 * NeuralThreatMeshGraphic Component
 * Next-Gen realistic Cyber Neural Mesh & Threat Topology visualizer.
 * Features Web Audio feedback, live HTML5 oscilloscope waveform canvas,
 * CRT scanline HUD toggle, realistic metric jitter, and vector dissection.
 */
export default function NeuralThreatMeshGraphic({
  alertStats = {},
  ipsStats = {},
  recentAlerts = [],
}) {
  const [selectedVector, setSelectedVector] = useState('web');
  const [defenseMode, setDefenseMode] = useState('zero-trust'); // 'zero-trust', 'adaptive-ai', 'honeypot'
  const [streamVelocity, setStreamVelocity] = useState(50); // 10 to 100
  const [activePulse, setActivePulse] = useState(0);
  const [soundMuted, setSoundMuted] = useState(false);
  const [hudFilterActive, setHudFilterActive] = useState(true);

  // Live Jitter Metrics for Ultra-Realism
  const [liveMetrics, setLiveMetrics] = useState({
    throughput: 48520,
    latency: 0.42,
    packetLoss: 0.00,
    entropyAvg: 4.82,
  });

  const canvasRef = useRef(null);

  // Trigger sound effect helper
  const triggerSound = (type) => {
    if (!soundMuted) playTactileSound(type);
  };

  // Animate pulse frequency based on streamVelocity
  useEffect(() => {
    const intervalTime = Math.max(15, Math.floor(1200 / streamVelocity));
    const interval = setInterval(() => {
      setActivePulse((prev) => (prev + 1) % 360);
    }, intervalTime);
    return () => clearInterval(interval);
  }, [streamVelocity]);

  // Live Metric Jitter Effect (Simulates real high-throughput packet arrivals)
  useEffect(() => {
    const interval = setInterval(() => {
      setLiveMetrics((prev) => ({
        throughput: Math.floor(48000 + Math.random() * 1200 + streamVelocity * 20),
        latency: +(0.38 + Math.random() * 0.08).toFixed(2),
        packetLoss: +(Math.random() * 0.002).toFixed(4),
        entropyAvg: +(4.75 + Math.random() * 0.25).toFixed(2),
      }));
    }, 1500);
    return () => clearInterval(interval);
  }, [streamVelocity]);

  // Threat Vector Nodes configuration around central core
  const vectors = useMemo(() => [
    {
      id: 'web',
      name: 'Web & API Security',
      count: alertStats?.cat_web || 42,
      severity: 'HIGH',
      color: '#00d4ff',
      angle: 0,
      icon: '🌐',
      threats: ['SQL Injection', 'Cross-Site Scripting', 'SSRF Payload', 'Command Injection'],
    },
    {
      id: 'network',
      name: 'Network & Flood',
      count: alertStats?.cat_network || 28,
      severity: 'CRITICAL',
      color: '#f59e0b',
      angle: 60,
      icon: '⚡',
      threats: ['SYN Flood', 'UDP Amplification', 'DNS Spoofing', 'ARP Poisoning'],
    },
    {
      id: 'malware',
      name: 'Malware & Ransomware',
      count: alertStats?.cat_malware || 19,
      severity: 'CRITICAL',
      color: '#ef4444',
      angle: 120,
      icon: '☣️',
      threats: ['Trojan Downloader', 'LockBit Encryptor', 'RAT C2 Beacon', 'Infostealer'],
    },
    {
      id: 'credential',
      name: 'Credential Security',
      count: alertStats?.cat_credential || 34,
      severity: 'MEDIUM',
      color: '#a855f7',
      angle: 180,
      icon: '🔑',
      threats: ['Brute Force', 'Password Spraying', 'Kerberoasting', 'Pass-the-Hash'],
    },
    {
      id: 'exploit',
      name: 'System Exploitation',
      count: alertStats?.cat_exploit || 15,
      severity: 'HIGH',
      color: '#ec4899',
      angle: 240,
      icon: '💥',
      threats: ['Buffer Overflow', 'Kernel PrivEsc', 'Log4j RCE', 'Zero-Day Heap Spray'],
    },
    {
      id: 'postcomp',
      name: 'Post-Compromise',
      count: alertStats?.cat_post_comp || 9,
      severity: 'LOW',
      color: '#10b981',
      angle: 300,
      icon: '🎯',
      threats: ['Lateral Movement', 'Lolbas Execution', 'DNS Exfiltration', 'Persistence Hook'],
    },
  ], [alertStats]);

  const activeVectorData = useMemo(() => {
    return vectors.find((v) => v.id === selectedVector) || vectors[0];
  }, [selectedVector, vectors]);

  // Color theme dynamically tied to active defense mode
  const modeTheme = {
    'zero-trust': { color: '#00d4ff', label: 'ZERO-TRUST SHIELDING', desc: 'Strict Sub-50ms Kernel Drop & Session Termination' },
    'adaptive-ai': { color: '#a855f7', label: 'ADAPTIVE AI BASELINE', desc: 'Shannon Entropy & Statistical Z-Score Anomaly Scoring' },
    'honeypot': { color: '#f59e0b', label: 'DECEPTION & HONEYPOT', desc: 'Isolated Sandbox Trapping & Forensic Telemetry Capture' },
  }[defenseMode];

  // Render HTML5 Oscilloscope Waveform Canvas
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let step = 0;

    const renderWaveform = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const width = canvas.width;
      const height = canvas.height;
      const centerY = height / 2;

      // Grid background
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 20) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 15) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Draw Main Sine/Noise Waveform
      ctx.beginPath();
      ctx.strokeStyle = activeVectorData.color;
      ctx.lineWidth = 2;
      ctx.shadowBlur = 10;
      ctx.shadowColor = activeVectorData.color;

      for (let x = 0; x < width; x += 2) {
        const freq = (x + step * 4) * 0.04;
        const noise = (Math.random() - 0.5) * 8;
        const amplitude = 18 * Math.sin(freq) + noise;
        const y = centerY + amplitude;
        if (x === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      step++;
      animationFrameId = requestAnimationFrame(renderWaveform);
    };

    renderWaveform();
    return () => cancelAnimationFrame(animationFrameId);
  }, [activeVectorData]);

  return (
    <div
      className="glass-card"
      style={{
        position: 'relative',
        padding: '24px',
        borderRadius: 16,
        background: 'radial-gradient(circle at 50% 50%, rgba(8, 15, 30, 0.98), rgba(3, 6, 14, 0.99))',
        border: `1px solid ${modeTheme.color}55`,
        boxShadow: `0 20px 60px rgba(0, 0, 0, 0.9), 0 0 40px ${modeTheme.color}20`,
        overflow: 'hidden',
        color: '#f8fafc',
        fontFamily: 'Inter, system-ui, sans-serif',
      }}
    >
      {/* CRT Scanline Filter Overlay for Authentic SOC Monitor Realism */}
      {hudFilterActive && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            backgroundImage:
              'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.03), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.03))',
            backgroundSize: '100% 3px, 6px 100%',
            pointerEvents: 'none',
            zIndex: 30,
            opacity: 0.75,
          }}
        />
      )}

      {/* Cyber Corner HUD Reticles */}
      <div style={{ position: 'absolute', top: 12, left: 12, fontSize: '0.65rem', color: modeTheme.color, opacity: 0.6, fontFamily: 'monospace' }}>┌ SYS.ID // APEX-SOC-CORE ┐</div>
      <div style={{ position: 'absolute', top: 12, right: 12, fontSize: '0.65rem', color: modeTheme.color, opacity: 0.6, fontFamily: 'monospace' }}>└ SEC.LEVEL // MAX-RESTRICTED ┘</div>

      {/* Header & Controls Toolbar */}
      <div
        style={{
          display: 'flex',
          justify: 'space-between',
          alignItems: 'center',
          marginBottom: 20,
          position: 'relative',
          zIndex: 10,
          flexWrap: 'wrap',
          gap: 16,
        }}
      >
        <div>
          <div style={{ fontSize: '1.05rem', fontWeight: 900, letterSpacing: '0.04em', color: '#ffffff', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: '1.3rem' }}>🌌</span>
            NEURAL THREAT MESH & DEFENSE TOPOLOGY
          </div>
          <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: 2 }}>
            Interactive Multivector Telemetry Matrix · Tactile Sound & Waveform Dissection Enabled
          </div>
        </div>

        {/* Top Control Buttons: Audio Toggle & CRT HUD Filter Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {/* Sound Toggle */}
          <button
            onClick={() => {
              setSoundMuted(!soundMuted);
              triggerSound('click');
            }}
            style={{
              padding: '6px 10px',
              borderRadius: 8,
              background: soundMuted ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              border: `1px solid ${soundMuted ? '#ef4444' : '#10b981'}`,
              color: soundMuted ? '#f87171' : '#10b981',
              fontSize: '0.72rem',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 4,
            }}
            title="Toggle Tactile SOC Interface Sound Effects"
          >
            <span>{soundMuted ? '🔇 Muted' : '🔊 Cyber Audio'}</span>
          </button>

          {/* HUD Filter Toggle */}
          <button
            onClick={() => {
              setHudFilterActive(!hudFilterActive);
              triggerSound('scan');
            }}
            style={{
              padding: '6px 10px',
              borderRadius: 8,
              background: hudFilterActive ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${hudFilterActive ? '#00d4ff' : 'rgba(255,255,255,0.2)'}`,
              color: hudFilterActive ? '#00d4ff' : '#94a3b8',
              fontSize: '0.72rem',
              fontWeight: 800,
              cursor: 'pointer',
            }}
            title="Toggle Futuristic CRT Scanline Overlay"
          >
            <span>{hudFilterActive ? '📺 HUD CRT ON' : '📺 HUD CRT OFF'}</span>
          </button>

          {/* Interactive Defense Mode Switcher */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'rgba(6, 13, 24, 0.9)', padding: '4px', borderRadius: 10, border: '1px solid rgba(255, 255, 255, 0.1)' }}>
            {[
              { id: 'zero-trust', label: '🛡️ Zero-Trust', color: '#00d4ff' },
              { id: 'adaptive-ai', label: '🧠 Neural AI', color: '#a855f7' },
              { id: 'honeypot', label: '🍯 Deception', color: '#f59e0b' },
            ].map((m) => (
              <button
                key={m.id}
                onClick={() => {
                  setDefenseMode(m.id);
                  triggerSound('mode');
                }}
                style={{
                  padding: '6px 12px',
                  borderRadius: 7,
                  border: 'none',
                  background: defenseMode === m.id ? m.color : 'transparent',
                  color: defenseMode === m.id ? '#000000' : '#94a3b8',
                  fontSize: '0.72rem',
                  fontWeight: 800,
                  cursor: 'pointer',
                  transition: 'all 0.2s ease',
                }}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Interactive Neural Graphic Area */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 24, position: 'relative', zIndex: 10, alignItems: 'center' }}>
        
        {/* Left Side: Circular Neural Mesh Canvas Diagram */}
        <div style={{ position: 'relative', height: 340, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          
          {/* Connecting SVG Rays & Orbital Rings */}
          <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
            <defs>
              <filter id="meshGlow">
                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Concentric Defense Shield Rings */}
            <circle cx="50%" cy="50%" r="60" stroke={modeTheme.color} strokeWidth="1.5" strokeDasharray="4 4" fill="none" opacity="0.4" />
            <circle cx="50%" cy="50%" r="120" stroke={modeTheme.color} strokeWidth="1" strokeDasharray="8 6" fill="none" opacity="0.25" />

            {/* Connecting Neural Lines from Center Core to Nodes */}
            {vectors.map((v) => {
              const rad = (v.angle * Math.PI) / 180;
              const isSelected = v.id === selectedVector;
              const cx = 50 + 38 * Math.cos(rad);
              const cy = 50 + 38 * Math.sin(rad);

              return (
                <g key={v.id}>
                  <line
                    x1="50%"
                    y1="50%"
                    x2={`${cx}%`}
                    y2={`${cy}%`}
                    stroke={isSelected ? v.color : `${v.color}44`}
                    strokeWidth={isSelected ? 3 : 1.5}
                    filter={isSelected ? 'url(#meshGlow)' : 'none'}
                  />
                  {/* Pulse Packet travelling along ray */}
                  <circle
                    r={isSelected ? 4 : 2.5}
                    fill={v.color}
                    filter="url(#meshGlow)"
                  >
                    <animateMotion
                      path={`M 200 170 L ${cx * 4} ${cy * 3.4}`}
                      dur={`${2 / (streamVelocity / 30)}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                </g>
              );
            })}
          </svg>

          {/* Central Holographic Apex Core Node */}
          <div
            onClick={() => triggerSound('click')}
            style={{
              position: 'relative',
              width: 110,
              height: 110,
              borderRadius: '50%',
              background: `radial-gradient(circle, ${modeTheme.color}33 0%, rgba(6, 13, 24, 0.95) 75%)`,
              border: `2px solid ${modeTheme.color}`,
              boxShadow: `0 0 40px ${modeTheme.color}66, inset 0 0 20px ${modeTheme.color}33`,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 10,
              cursor: 'pointer',
            }}
          >
            {/* Spinning Shield Halo */}
            <div
              style={{
                position: 'absolute',
                inset: -8,
                borderRadius: '50%',
                border: `1.5px dashed ${modeTheme.color}`,
                transform: `rotate(${activePulse * 2}deg)`,
                pointerEvents: 'none',
              }}
            />
            <span style={{ fontSize: '1.4rem' }}>🛡️</span>
            <div style={{ fontSize: '0.65rem', fontWeight: 900, color: '#ffffff', letterSpacing: '0.06em', marginTop: 2 }}>
              APEX CORE
            </div>
            <div style={{ fontSize: '0.55rem', fontWeight: 700, color: modeTheme.color }}>
              {modeTheme.label.split(' ')[0]}
            </div>
          </div>

          {/* Outer Vector Nodes Orbiting Around Center */}
          {vectors.map((v) => {
            const rad = (v.angle * Math.PI) / 180;
            const radiusPercent = 38; // Distance from center
            const isSelected = v.id === selectedVector;

            const top = 50 + radiusPercent * Math.sin(rad);
            const left = 50 + radiusPercent * Math.cos(rad);

            return (
              <div
                key={v.id}
                onClick={() => {
                  setSelectedVector(v.id);
                  triggerSound('click');
                }}
                style={{
                  position: 'absolute',
                  top: `${top}%`,
                  left: `${left}%`,
                  transform: 'translate(-50%, -50%)',
                  zIndex: 20,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 12px',
                  borderRadius: 10,
                  background: isSelected ? 'rgba(6, 13, 24, 0.98)' : 'rgba(6, 13, 24, 0.75)',
                  border: isSelected ? `2px solid ${v.color}` : `1px solid ${v.color}55`,
                  boxShadow: isSelected ? `0 0 25px ${v.color}66` : '0 4px 15px rgba(0,0,0,0.5)',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                }}
              >
                <span style={{ fontSize: '1rem' }}>{v.icon}</span>
                <div>
                  <div style={{ fontSize: '0.68rem', fontWeight: 800, color: isSelected ? v.color : '#ffffff', whiteSpace: 'nowrap' }}>
                    {v.name}
                  </div>
                  <div style={{ fontSize: '0.6rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                    {v.count} Events Logged
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Side: Interactive Live Waveform & Telemetry Panel */}
        <div
          style={{
            background: 'rgba(6, 13, 24, 0.85)',
            border: `1px solid ${activeVectorData.color}44`,
            borderRadius: 14,
            padding: '18px',
            boxShadow: '0 10px 30px rgba(0,0,0,0.6)',
          }}
        >
          {/* Vector Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: '1.3rem' }}>{activeVectorData.icon}</span>
              <div>
                <div style={{ fontSize: '0.88rem', fontWeight: 900, color: activeVectorData.color }}>
                  {activeVectorData.name}
                </div>
                <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>Real-Time Payload Oscilloscope</div>
              </div>
            </div>
            <span
              style={{
                fontSize: '0.62rem',
                fontWeight: 800,
                padding: '2px 8px',
                borderRadius: 4,
                background: `${activeVectorData.color}22`,
                color: activeVectorData.color,
                border: `1px solid ${activeVectorData.color}`,
              }}
            >
              {activeVectorData.severity} RISK
            </span>
          </div>

          {/* HTML5 Canvas Waveform Visualizer */}
          <div style={{ position: 'relative', marginBottom: 12, borderRadius: 8, overflow: 'hidden', border: `1px solid ${activeVectorData.color}33`, background: '#020610' }}>
            <canvas ref={canvasRef} width={300} height={60} style={{ display: 'block', width: '100%', height: 60 }} />
            <div style={{ position: 'absolute', bottom: 4, right: 8, fontSize: '0.58rem', color: activeVectorData.color, fontFamily: 'monospace', opacity: 0.8 }}>
              ENTROPY: H(X)={liveMetrics.entropyAvg}
            </div>
          </div>

          {/* Live Realistic Jitter Metrics Bar */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 14, background: 'rgba(255,255,255,0.02)', padding: '8px 10px', borderRadius: 8 }}>
            <div>
              <div style={{ fontSize: '0.6rem', color: '#94a3b8' }}>THROUGHPUT</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 900, color: '#00d4ff', fontFamily: 'monospace' }}>
                {liveMetrics.throughput.toLocaleString()} pps
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.6rem', color: '#94a3b8' }}>KERNEL LATENCY</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 900, color: '#10b981', fontFamily: 'monospace' }}>
                {liveMetrics.latency} ms
              </div>
            </div>
          </div>

          {/* Sample Signatures List */}
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: '0.68rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 6 }}>
              Monitored Attack Signatures ({activeVectorData.threats.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {activeVectorData.threats.map((t, idx) => (
                <span
                  key={idx}
                  style={{
                    fontSize: '0.65rem',
                    padding: '3px 8px',
                    borderRadius: 4,
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    color: '#e2e8f0',
                    fontFamily: 'monospace',
                  }}
                >
                  ⚡ {t}
                </span>
              ))}
            </div>
          </div>

          {/* Interactive Velocity Speed Controller Slider */}
          <div style={{ paddingTop: 10, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ fontSize: '0.68rem', fontWeight: 700, color: '#94a3b8' }}>PACKET SAMPLING VELOCITY</span>
              <span style={{ fontSize: '0.75rem', fontWeight: 900, color: modeTheme.color, fontFamily: 'monospace' }}>
                {streamVelocity * 1000} req/sec
              </span>
            </div>
            <input
              type="range"
              min="10"
              max="100"
              value={streamVelocity}
              onChange={(e) => {
                setStreamVelocity(Number(e.target.value));
                triggerSound('scan');
              }}
              style={{
                width: '100%',
                accentColor: modeTheme.color,
                cursor: 'pointer',
              }}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
