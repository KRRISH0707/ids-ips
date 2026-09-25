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
    // Ignore audio context block
  }
}

/**
 * NeuralThreatMeshGraphic Component
 * Next-Gen realistic Cyber Neural Mesh & Threat Topology visualizer.
 * Supports fullScreen mode fitting 100vh viewports with expanded canvas,
 * Web Audio feedback, live HTML5 oscilloscope waveform canvas, and CRT scanlines.
 */
export default function NeuralThreatMeshGraphic({
  alertStats = {},
  ipsStats = {},
  recentAlerts = [],
  fullScreen = false,
}) {
  const [selectedVector, setSelectedVector] = useState('web');
  const [defenseMode, setDefenseMode] = useState('zero-trust');
  const [streamVelocity, setStreamVelocity] = useState(65);
  const [activePulse, setActivePulse] = useState(0);
  const [soundMuted, setSoundMuted] = useState(false);
  const [hudFilterActive, setHudFilterActive] = useState(true);

  // Live Jitter Metrics for Ultra-Realism
  const [liveMetrics, setLiveMetrics] = useState({
    throughput: 52400,
    latency: 0.38,
    packetLoss: 0.0001,
    entropyAvg: 5.12,
  });

  const canvasRef = useRef(null);

  const triggerSound = (type) => {
    if (!soundMuted) playTactileSound(type);
  };

  useEffect(() => {
    const intervalTime = Math.max(15, Math.floor(1200 / streamVelocity));
    const interval = setInterval(() => {
      setActivePulse((prev) => (prev + 1) % 360);
    }, intervalTime);
    return () => clearInterval(interval);
  }, [streamVelocity]);

  useEffect(() => {
    const interval = setInterval(() => {
      setLiveMetrics({
        throughput: Math.floor(51000 + Math.random() * 2500 + streamVelocity * 25),
        latency: +(0.32 + Math.random() * 0.09).toFixed(2),
        packetLoss: +(Math.random() * 0.0015).toFixed(4),
        entropyAvg: +(5.05 + Math.random() * 0.35).toFixed(2),
      });
    }, 1200);
    return () => clearInterval(interval);
  }, [streamVelocity]);

  const vectors = useMemo(() => [
    {
      id: 'web',
      name: 'Web & API Security',
      count: alertStats?.cat_web || 42,
      severity: 'HIGH',
      color: '#00d4ff',
      angle: 0,
      icon: '🌐',
      threats: ['SQL Injection', 'Cross-Site Scripting', 'SSRF Payload', 'Command Injection', 'GraphQL Abuse'],
    },
    {
      id: 'network',
      name: 'Network & Flood',
      count: alertStats?.cat_network || 28,
      severity: 'CRITICAL',
      color: '#f59e0b',
      angle: 60,
      icon: '⚡',
      threats: ['SYN Flood', 'UDP Amplification', 'DNS Spoofing', 'ARP Poisoning', 'ICMP Smurf'],
    },
    {
      id: 'malware',
      name: 'Malware & Ransomware',
      count: alertStats?.cat_malware || 19,
      severity: 'CRITICAL',
      color: '#ef4444',
      angle: 120,
      icon: '☣️',
      threats: ['Trojan Downloader', 'LockBit Encryptor', 'RAT C2 Beacon', 'Infostealer', 'Rootkit Hook'],
    },
    {
      id: 'credential',
      name: 'Credential Security',
      count: alertStats?.cat_credential || 34,
      severity: 'MEDIUM',
      color: '#a855f7',
      angle: 180,
      icon: '🔑',
      threats: ['Brute Force', 'Password Spraying', 'Kerberoasting', 'Pass-the-Hash', 'Golden Ticket'],
    },
    {
      id: 'exploit',
      name: 'System Exploitation',
      count: alertStats?.cat_exploit || 15,
      severity: 'HIGH',
      color: '#ec4899',
      angle: 240,
      icon: '💥',
      threats: ['Buffer Overflow', 'Kernel PrivEsc', 'Log4j RCE', 'Zero-Day Heap Spray', 'DLL Hijack'],
    },
    {
      id: 'postcomp',
      name: 'Post-Compromise',
      count: alertStats?.cat_post_comp || 9,
      severity: 'LOW',
      color: '#10b981',
      angle: 300,
      icon: '🎯',
      threats: ['Lateral Movement', 'Lolbas Execution', 'DNS Exfiltration', 'Persistence Hook', 'Steganography'],
    },
  ], [alertStats]);

  const activeVectorData = useMemo(() => {
    return vectors.find((v) => v.id === selectedVector) || vectors[0];
  }, [selectedVector, vectors]);

  const modeTheme = {
    'zero-trust': { color: '#00d4ff', label: 'ZERO-TRUST SHIELDING', desc: 'Strict Sub-50ms Kernel Drop & Session Termination' },
    'adaptive-ai': { color: '#a855f7', label: 'ADAPTIVE AI BASELINE', desc: 'Shannon Entropy & Statistical Z-Score Anomaly Scoring' },
    'honeypot': { color: '#f59e0b', label: 'DECEPTION & HONEYPOT', desc: 'Isolated Sandbox Trapping & Forensic Telemetry Capture' },
  }[defenseMode];

  // Render Waveform Canvas
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

      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 25) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 20) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.strokeStyle = activeVectorData.color;
      ctx.lineWidth = 2.5;
      ctx.shadowBlur = 12;
      ctx.shadowColor = activeVectorData.color;

      for (let x = 0; x < width; x += 2) {
        const freq = (x + step * 4) * 0.035;
        const noise = (Math.random() - 0.5) * (fullScreen ? 14 : 8);
        const amp = (fullScreen ? 32 : 18) * Math.sin(freq) + noise;
        const y = centerY + amp;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      step++;
      animationFrameId = requestAnimationFrame(renderWaveform);
    };

    renderWaveform();
    return () => cancelAnimationFrame(animationFrameId);
  }, [activeVectorData, fullScreen]);

  return (
    <div
      className="glass-card"
      style={{
        position: 'relative',
        padding: fullScreen ? '32px' : '24px',
        minHeight: fullScreen ? 'calc(100vh - 130px)' : 'auto',
        borderRadius: 16,
        background: 'radial-gradient(circle at 50% 50%, rgba(6, 14, 28, 0.99), rgba(2, 5, 12, 1.0))',
        border: `1px solid ${modeTheme.color}55`,
        boxShadow: `0 20px 70px rgba(0, 0, 0, 0.95), 0 0 50px ${modeTheme.color}25`,
        overflow: 'hidden',
        color: '#f8fafc',
        fontFamily: 'Inter, system-ui, sans-serif',
        display: 'flex',
        flexDirection: 'column',
        justify: 'space-between',
      }}
    >
      {/* CRT Scanline Filter Overlay */}
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

      {/* Cyber Corner Reticles */}
      <div style={{ position: 'absolute', top: 12, left: 16, fontSize: '0.7rem', color: modeTheme.color, opacity: 0.7, fontFamily: 'monospace', fontWeight: 700 }}>
        ┌ SYS.NODE // APEX-FULLSCREEN-MATRIX ┐
      </div>
      <div style={{ position: 'absolute', top: 12, right: 16, fontSize: '0.7rem', color: modeTheme.color, opacity: 0.7, fontFamily: 'monospace', fontWeight: 700 }}>
        └ SECURITY STATUS // DEFENSE ACTIVE ┘
      </div>

      {/* Header Bar */}
      <div
        style={{
          display: 'flex',
          justify: 'space-between',
          alignItems: 'center',
          marginBottom: fullScreen ? 28 : 20,
          position: 'relative',
          zIndex: 10,
          flexWrap: 'wrap',
          gap: 16,
        }}
      >
        <div>
          <div style={{ fontSize: fullScreen ? '1.35rem' : '1.05rem', fontWeight: 900, letterSpacing: '0.04em', color: '#ffffff', display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: fullScreen ? '1.8rem' : '1.3rem' }}>🌌</span>
            NEURAL THREAT TOPOLOGY & DEFENSE MATRIX
            <span style={{ fontSize: '0.65rem', padding: '3px 10px', borderRadius: 4, background: `${modeTheme.color}25`, color: modeTheme.color, border: `1px solid ${modeTheme.color}` }}>
              FULLSCREEN COMMAND VIEW
            </span>
          </div>
          <div style={{ fontSize: fullScreen ? '0.82rem' : '0.74rem', color: '#94a3b8', marginTop: 4 }}>
            Sub-Second Multi-Vector Correlation Mesh · Live Waveform Oscilloscope & Web Audio Enabled
          </div>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={() => {
              setSoundMuted(!soundMuted);
              triggerSound('click');
            }}
            style={{
              padding: '8px 14px',
              borderRadius: 8,
              background: soundMuted ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              border: `1px solid ${soundMuted ? '#ef4444' : '#10b981'}`,
              color: soundMuted ? '#f87171' : '#10b981',
              fontSize: '0.78rem',
              fontWeight: 800,
              cursor: 'pointer',
            }}
          >
            {soundMuted ? '🔇 Muted' : '🔊 Cyber Audio'}
          </button>

          <button
            onClick={() => {
              setHudFilterActive(!hudFilterActive);
              triggerSound('scan');
            }}
            style={{
              padding: '8px 14px',
              borderRadius: 8,
              background: hudFilterActive ? 'rgba(0, 212, 255, 0.15)' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${hudFilterActive ? '#00d4ff' : 'rgba(255,255,255,0.2)'}`,
              color: hudFilterActive ? '#00d4ff' : '#94a3b8',
              fontSize: '0.78rem',
              fontWeight: 800,
              cursor: 'pointer',
            }}
          >
            {hudFilterActive ? '📺 HUD CRT ON' : '📺 HUD CRT OFF'}
          </button>

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
                  padding: '7px 14px',
                  borderRadius: 7,
                  border: 'none',
                  background: defenseMode === m.id ? m.color : 'transparent',
                  color: defenseMode === m.id ? '#000000' : '#94a3b8',
                  fontSize: '0.75rem',
                  fontWeight: 800,
                  cursor: 'pointer',
                }}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Grid View */}
      <div style={{ display: 'grid', gridTemplateColumns: fullScreen ? '1.4fr 0.8fr' : '1.2fr 0.8fr', gap: fullScreen ? 36 : 24, position: 'relative', zIndex: 10, flex: 1, alignItems: 'center' }}>
        
        {/* Canvas Diagram View */}
        <div style={{ position: 'relative', height: fullScreen ? 480 : 340, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          
          <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
            <defs>
              <filter id="meshGlowFS">
                <feGaussianBlur stdDeviation="4" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            <circle cx="50%" cy="50%" r={fullScreen ? 90 : 60} stroke={modeTheme.color} strokeWidth="1.5" strokeDasharray="4 4" fill="none" opacity="0.4" />
            <circle cx="50%" cy="50%" r={fullScreen ? 180 : 120} stroke={modeTheme.color} strokeWidth="1" strokeDasharray="8 6" fill="none" opacity="0.25" />

            {vectors.map((v) => {
              const rad = (v.angle * Math.PI) / 180;
              const isSelected = v.id === selectedVector;
              const radiusPercent = fullScreen ? 38 : 38;
              const cx = 50 + radiusPercent * Math.cos(rad);
              const cy = 50 + radiusPercent * Math.sin(rad);

              return (
                <g key={v.id}>
                  <line
                    x1="50%"
                    y1="50%"
                    x2={`${cx}%`}
                    y2={`${cy}%`}
                    stroke={isSelected ? v.color : `${v.color}44`}
                    strokeWidth={isSelected ? 4 : 1.5}
                    filter={isSelected ? 'url(#meshGlowFS)' : 'none'}
                  />
                  <circle r={isSelected ? 5 : 3} fill={v.color} filter="url(#meshGlowFS)">
                    <animateMotion
                      path={`M 300 240 L ${cx * 6} ${cy * 4.8}`}
                      dur={`${2 / (streamVelocity / 30)}s`}
                      repeatCount="indefinite"
                    />
                  </circle>
                </g>
              );
            })}
          </svg>

          {/* Central Apex Core Node */}
          <div
            onClick={() => triggerSound('click')}
            style={{
              position: 'relative',
              width: fullScreen ? 150 : 110,
              height: fullScreen ? 150 : 110,
              borderRadius: '50%',
              background: `radial-gradient(circle, ${modeTheme.color}44 0%, rgba(6, 13, 24, 0.98) 75%)`,
              border: `3px solid ${modeTheme.color}`,
              boxShadow: `0 0 50px ${modeTheme.color}88, inset 0 0 30px ${modeTheme.color}44`,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 10,
              cursor: 'pointer',
            }}
          >
            <div
              style={{
                position: 'absolute',
                inset: -12,
                borderRadius: '50%',
                border: `2px dashed ${modeTheme.color}`,
                transform: `rotate(${activePulse * 2}deg)`,
                pointerEvents: 'none',
              }}
            />
            <span style={{ fontSize: fullScreen ? '2rem' : '1.4rem' }}>🛡️</span>
            <div style={{ fontSize: fullScreen ? '0.82rem' : '0.65rem', fontWeight: 900, color: '#ffffff', letterSpacing: '0.06em', marginTop: 4 }}>
              APEX CORE
            </div>
            <div style={{ fontSize: fullScreen ? '0.65rem' : '0.55rem', fontWeight: 800, color: modeTheme.color }}>
              {modeTheme.label.split(' ')[0]}
            </div>
          </div>

          {/* Orbiting Vector Nodes */}
          {vectors.map((v) => {
            const rad = (v.angle * Math.PI) / 180;
            const radiusPercent = 38;
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
                  gap: 10,
                  padding: fullScreen ? '10px 16px' : '6px 12px',
                  borderRadius: 12,
                  background: isSelected ? 'rgba(6, 13, 24, 0.98)' : 'rgba(6, 13, 24, 0.8)',
                  border: isSelected ? `2.5px solid ${v.color}` : `1px solid ${v.color}55`,
                  boxShadow: isSelected ? `0 0 35px ${v.color}88` : '0 4px 18px rgba(0,0,0,0.6)',
                  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                }}
              >
                <span style={{ fontSize: fullScreen ? '1.3rem' : '1rem' }}>{v.icon}</span>
                <div>
                  <div style={{ fontSize: fullScreen ? '0.82rem' : '0.68rem', fontWeight: 900, color: isSelected ? v.color : '#ffffff', whiteSpace: 'nowrap' }}>
                    {v.name}
                  </div>
                  <div style={{ fontSize: fullScreen ? '0.7rem' : '0.6rem', color: '#94a3b8', fontFamily: 'monospace' }}>
                    {v.count} Events Logged
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Side: Oscilloscope & Telemetry Dissection Panel */}
        <div
          style={{
            background: 'rgba(6, 13, 24, 0.9)',
            border: `1px solid ${activeVectorData.color}55`,
            borderRadius: 14,
            padding: fullScreen ? '24px' : '18px',
            boxShadow: '0 15px 40px rgba(0,0,0,0.8)',
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.5rem' }}>{activeVectorData.icon}</span>
              <div>
                <div style={{ fontSize: '1rem', fontWeight: 900, color: activeVectorData.color }}>
                  {activeVectorData.name}
                </div>
                <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Real-Time Oscilloscope Telemetry</div>
              </div>
            </div>
            <span
              style={{
                fontSize: '0.7rem',
                fontWeight: 900,
                padding: '3px 10px',
                borderRadius: 4,
                background: `${activeVectorData.color}25`,
                color: activeVectorData.color,
                border: `1px solid ${activeVectorData.color}`,
              }}
            >
              {activeVectorData.severity} RISK
            </span>
          </div>

          {/* Expanded Waveform Canvas */}
          <div style={{ position: 'relative', borderRadius: 10, overflow: 'hidden', border: `1px solid ${activeVectorData.color}44`, background: '#020610' }}>
            <canvas ref={canvasRef} width={450} height={fullScreen ? 110 : 60} style={{ display: 'block', width: '100%', height: fullScreen ? 110 : 60 }} />
            <div style={{ position: 'absolute', bottom: 6, right: 10, fontSize: '0.65rem', color: activeVectorData.color, fontFamily: 'monospace', fontWeight: 700 }}>
              ENTROPY WAVEFORM: H(X)={liveMetrics.entropyAvg}
            </div>
          </div>

          {/* Live Metric Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, background: 'rgba(255,255,255,0.03)', padding: '10px 14px', borderRadius: 8 }}>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#94a3b8', fontWeight: 700 }}>THROUGHPUT</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 900, color: '#00d4ff', fontFamily: 'monospace' }}>
                {liveMetrics.throughput.toLocaleString()} pps
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#94a3b8', fontWeight: 700 }}>KERNEL LATENCY</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 900, color: '#10b981', fontFamily: 'monospace' }}>
                {liveMetrics.latency} ms
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.65rem', color: '#94a3b8', fontWeight: 700 }}>PACKET LOSS</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 900, color: '#a855f7', fontFamily: 'monospace' }}>
                {liveMetrics.packetLoss}%
              </div>
            </div>
          </div>

          {/* Monitored Signatures */}
          <div>
            <div style={{ fontSize: '0.72rem', fontWeight: 800, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 8 }}>
              Active Vector Attack Signatures ({activeVectorData.threats.length})
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {activeVectorData.threats.map((t, idx) => (
                <span
                  key={idx}
                  style={{
                    fontSize: '0.72rem',
                    padding: '4px 10px',
                    borderRadius: 6,
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.12)',
                    color: '#e2e8f0',
                    fontFamily: 'monospace',
                  }}
                >
                  ⚡ {t}
                </span>
              ))}
            </div>
          </div>

          {/* Velocity Controller Slider */}
          <div style={{ paddingTop: 12, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#94a3b8' }}>PACKET SAMPLING VELOCITY</span>
              <span style={{ fontSize: '0.85rem', fontWeight: 900, color: modeTheme.color, fontFamily: 'monospace' }}>
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
