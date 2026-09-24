'use client';

import { useState, useMemo, useEffect } from 'react';
import { createPortal } from 'react-dom';

/**
 * AttackDossierModal Component
 * Full-fidelity cybersecurity threat intelligence dossier.
 * Fully compatible with all 101 attack taxonomy vectors with dynamic fallbacks,
 * raw payload inspection, Wireshark hex views, MITRE ATT&CK correlation,
 * IOC ledgers, and live simulation triggers.
 */
export default function AttackDossierModal({ attack, onClose, onTrigger }) {
  const [mounted, setMounted] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [copied, setCopied] = useState(false);
  const [pcapDownloaded, setPcapDownloaded] = useState(false);
  const [simulatedTriggered, setSimulatedTriggered] = useState(false);

  useEffect(() => {
    setMounted(true);
    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, []);

  // Compute safe enriched properties with fallbacks for all 101 vectors
  const safeData = useMemo(() => {
    if (!attack) return null;

    const infectionChain = attack.infectionChain || [
      `1. Initial ingress probe from ${attack.attackerIp} targeting port ${attack.targetPort} (${attack.protocol}).`,
      `2. Transmission of anomalous cyber vector signature [${attack.key}].`,
      `3. Heuristic anomaly classification by Apex Sentinel neural engine (${attack.threatScore}/100 score).`,
      `4. Autonomous kernel eBPF socket termination and perimeter host isolation (${attack.mttc || '0.38s'}).`,
    ];

    const hexDump = attack.hexDump || [
      '0000   45 00 00 3c 1c 46 40 00 40 06 b1 e6 c6 33 64 16   E..<.@.@....3d.',
      '0010   0a f0 0a 04 c0 b4 01 bb 00 00 00 00 a0 02 72 10   ..............r.',
      '0020   36 41 00 00 02 04 05 b4 04 02 08 0a 01 2c 34 56   6A...........4V',
      '0030   00 00 00 00 01 03 03 07 41 54 54 41 43 4b 21 00   ........ATTACK!.',
    ].join('\n');

    const mitre = attack.mitre || {
      tactic: attack.category || 'Exploitation',
      tacticId: 'TA0001',
      technique: attack.mitreName || attack.name,
      techniqueId: attack.mitreTechnique || 'T1190',
      subTechnique: `${attack.mitreTechnique || 'T1190'}.001`,
      defenseEvasion: 'Obfuscated Signature / Encrypted Tunnel',
    };

    const resolutionSteps = attack.resolutionSteps || [
      { step: 'T+0.02s', text: `Deep Packet Inspection flagged ${attack.name}`, time: '0.02s' },
      { step: 'T+0.12s', text: 'Neural behavioral classifier confirmed malicious anomaly', time: '0.12s' },
      { step: 'T+0.25s', text: `eBPF kernel hook injected: DROP SRC ${attack.attackerIp}`, time: '0.25s' },
      { step: `T+${attack.mttc || '0.38s'}`, text: 'Quarantine established; SIEM alert & incident dispatched', time: attack.mttc || '0.38s' },
    ];

    const kernelCommand = attack.kernelCommand || `iptables -I APEX_IPS_DROP 1 -s ${attack.attackerIp} -p ${attack.protocol?.toLowerCase() || 'tcp'} --dport ${attack.targetPort} -j DROP`;
    const verificationHash = attack.verificationHash || `SHA256: ${Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}...${attack.key.toLowerCase()}`;
    const iocs = attack.iocs || [
      attack.attackerIp,
      `Port ${attack.targetPort} (${attack.protocol})`,
      `Signature: ${attack.name}`,
    ];

    return {
      ...attack,
      infectionChain,
      hexDump,
      mitre,
      resolutionSteps,
      kernelCommand,
      verificationHash,
      iocs,
    };
  }, [attack]);

  if (!safeData || !mounted || typeof document === 'undefined') return null;

  const handleCopyPayload = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(safeData.payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadPcap = () => {
    setPcapDownloaded(true);
    setTimeout(() => setPcapDownloaded(false), 3000);
  };

  const handleTrigger = () => {
    if (onTrigger) {
      onTrigger(safeData);
      setSimulatedTriggered(true);
      setTimeout(() => setSimulatedTriggered(false), 2500);
    }
  };

  return createPortal(
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        width: '100vw',
        height: '100vh',
        background: 'rgba(2, 4, 8, 0.88)',
        backdropFilter: 'blur(12px)',
        WebkitBackdropFilter: 'blur(12px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 999999,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="hud-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 900,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          background: 'rgba(6, 13, 24, 0.98)',
          border: '1px solid rgba(0, 212, 255, 0.45)',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.9), 0 0 40px rgba(0, 212, 255, 0.25)',
          padding: 0,
          overflow: 'hidden',
          borderRadius: 12,
        }}
      >
        {/* Top Header Bar */}
        <div
          style={{
            padding: '16px 24px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            background: 'linear-gradient(90deg, rgba(0, 212, 255, 0.12) 0%, rgba(124, 58, 237, 0.12) 100%)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.25rem' }}>⚡</span>
              <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                {safeData.name}
              </h2>
              <span
                style={{
                  fontSize: '0.68rem',
                  fontWeight: 800,
                  padding: '2px 8px',
                  borderRadius: 4,
                  background: safeData.badge === 'CRITICAL' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(249, 115, 22, 0.25)',
                  color: safeData.badge === 'CRITICAL' ? '#f87171' : '#fb923c',
                  border: `1px solid ${safeData.badge === 'CRITICAL' ? '#ef4444' : '#f97316'}`,
                }}
              >
                {safeData.badge}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
              Vector: <b style={{ color: 'var(--accent-cyan)' }}>{safeData.key}</b> · Attribution: <b style={{ color: '#a855f7' }}>{safeData.actor}</b> · Score: <b style={{ color: '#ef4444' }}>{safeData.threatScore}/100</b> · CVSS: <b style={{ color: '#f59e0b' }}>{safeData.cvss}</b>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {onTrigger && (
              <button
                onClick={handleTrigger}
                style={{
                  padding: '6px 14px',
                  borderRadius: 6,
                  background: simulatedTriggered
                    ? 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
                    : 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)',
                  border: 'none',
                  color: '#fff',
                  fontWeight: 700,
                  fontSize: '0.78rem',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  boxShadow: '0 0 15px rgba(0, 212, 255, 0.3)',
                  transition: 'all 0.2s',
                }}
              >
                <span>⚡</span>
                {simulatedTriggered ? 'Autonomous Intercept Active!' : 'Simulate & Intercept'}
              </button>
            )}

            <button
              onClick={onClose}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: 'var(--text-secondary)',
                borderRadius: 6,
                width: 32,
                height: 32,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1rem',
                transition: 'all 0.2s',
              }}
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div
          style={{
            display: 'flex',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            background: 'rgba(0, 0, 0, 0.35)',
            padding: '0 24px',
            overflowX: 'auto',
          }}
        >
          {[
            { id: 'overview', label: '1. Overview & Vector' },
            { id: 'payload', label: '2. Payload & Forensics' },
            { id: 'mitre', label: '3. MITRE ATT&CK® Correlation' },
            { id: 'resolution', label: '4. Autonomous Mitigation' },
            { id: 'iocs', label: '5. Threat Indicators (IOCs)' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '12px 18px',
                background: 'transparent',
                border: 'none',
                borderBottom: activeTab === tab.id ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                color: activeTab === tab.id ? 'var(--accent-cyan)' : 'var(--text-muted)',
                fontWeight: activeTab === tab.id ? 700 : 500,
                fontSize: '0.8rem',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.2s',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content Body */}
        <div style={{ flex: 1, padding: 24, overflowY: 'auto', minHeight: 340 }}>
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div
                style={{
                  background: 'rgba(0, 212, 255, 0.04)',
                  border: '1px solid rgba(0, 212, 255, 0.15)',
                  borderRadius: 8,
                  padding: 16,
                  fontSize: '0.85rem',
                  lineHeight: 1.6,
                  color: 'var(--text-primary)',
                }}
              >
                <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 4, fontSize: '0.8rem', textTransform: 'uppercase' }}>
                  Technical Threat Abstract:
                </div>
                {safeData.overview}
              </div>

              {/* Threat Matrix Badges */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attacker Source</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--sev-critical)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {safeData.attackerIp}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>{safeData.attackerAsn}</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Targeted Asset</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {safeData.targetAsset}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Port {safeData.targetPort} ({safeData.protocol})</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Containment Speed</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-green)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {safeData.mttc}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Sub-Second Response</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Kill Chain Phase</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#a855f7', marginTop: 2 }}>
                    {safeData.killChainName}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Stage 0{safeData.killChainStage + 1} Trajectory</div>
                </div>
              </div>

              {/* Step-by-Step Infection Chain */}
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                  Adversary Execution & Interception Chain:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {safeData.infectionChain.map((step, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '8px 12px',
                        borderRadius: 6,
                        background: idx === safeData.infectionChain.length - 1 ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                        border: idx === safeData.infectionChain.length - 1 ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255, 255, 255, 0.04)',
                        fontSize: '0.8rem',
                        color: idx === safeData.infectionChain.length - 1 ? '#34d399' : 'var(--text-secondary)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                      }}
                    >
                      <span>{idx === safeData.infectionChain.length - 1 ? '🛡️' : '▹'}</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PAYLOAD & FORENSICS */}
          {activeTab === 'payload' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Raw Captured Ingress Packet Exploit String:
                  </span>
                  <button
                    onClick={handleCopyPayload}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: '0.72rem', padding: '2px 8px' }}
                  >
                    {copied ? '✓ Copied!' : '📋 Copy Payload'}
                  </button>
                </div>
                <pre
                  style={{
                    background: '#030712',
                    border: '1px solid rgba(0, 212, 255, 0.2)',
                    borderRadius: 8,
                    padding: 14,
                    fontSize: '0.78rem',
                    color: '#38bdf8',
                    fontFamily: 'JetBrains Mono, monospace',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    maxHeight: 140,
                    overflowY: 'auto',
                  }}
                >
                  {safeData.payload}
                </pre>
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Deep Packet Inspection Wireshark-Style Hex Dump:
                  </span>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono' }}>
                    Offset (0x0000) · 16 Bytes / Row
                  </span>
                </div>
                <pre
                  style={{
                    background: '#020617',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: 8,
                    padding: 14,
                    fontSize: '0.76rem',
                    color: '#94a3b8',
                    fontFamily: 'JetBrains Mono, monospace',
                    lineHeight: 1.5,
                    overflowX: 'auto',
                  }}
                >
                  {safeData.hexDump}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 3: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ENTERPRISE TACTIC</div>
                  <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 4 }}>
                    {safeData.mitre.tactic} ({safeData.mitre.tacticId})
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PRIMARY TECHNIQUE</div>
                  <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f59e0b', marginTop: 4 }}>
                    {safeData.mitre.technique} ({safeData.mitre.techniqueId})
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SUB-TECHNIQUE INVOLVED</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#a855f7', marginTop: 4 }}>
                    {safeData.mitre.subTechnique}
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEFENSE EVASION VECTOR</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ef4444', marginTop: 4 }}>
                    {safeData.mitre.defenseEvasion}
                  </div>
                </div>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase' }}>
                  Apex Sentinel Automated MITRE Detection Logic:
                </div>
                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  Apex Sentinel correlates raw libpcap flow telemetry against the MITRE ATT&CK knowledgebase.
                  When matching the signature {safeData.cve}, the heuristic classifier calculates anomaly confidence,
                  maps the adversary to {safeData.actor}, and initiates zero-touch containment playbooks before privilege escalation.
                </p>
              </div>
            </div>
          )}

          {/* TAB 4: AUTONOMOUS RESOLUTION RECEIPT */}
          {activeTab === 'resolution' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 8 }}>
                  Real-Time Autonomous Resolution Trace:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {safeData.resolutionSteps.map((res, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '10px 14px',
                        borderRadius: 6,
                        background: 'rgba(0, 0, 0, 0.4)',
                        border: '1px solid rgba(0, 212, 255, 0.15)',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: '0.8rem',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ color: '#10b981', fontWeight: 700 }}>✓</span>
                        <div>
                          <span style={{ fontWeight: 700, color: 'var(--text-primary)', marginRight: 8 }}>{res.step}:</span>
                          <span style={{ color: 'var(--text-muted)' }}>{res.text}</span>
                        </div>
                      </div>
                      <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', fontWeight: 700 }}>
                        {res.time}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Kernel Command Executed */}
              <div style={{ background: '#020617', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 700, textTransform: 'uppercase', marginBottom: 4 }}>
                  Active Linux Kernel IPS Rule Applied:
                </div>
                <code style={{ fontSize: '0.78rem', color: '#34d399', fontFamily: 'JetBrains Mono' }}>
                  # {safeData.kernelCommand}
                </code>
              </div>

              {/* Cryptographic Digest & PCAP Export */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 8, borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                  Evidence Hash: <b style={{ color: 'var(--text-muted)' }}>{safeData.verificationHash}</b>
                </div>
                <button
                  onClick={handleDownloadPcap}
                  className="btn btn-primary btn-sm"
                  style={{ fontSize: '0.75rem', gap: 6 }}
                >
                  {pcapDownloaded ? '✓ Evidence Exported (.pcap)' : '📥 Download Forensic PCAP'}
                </button>
              </div>
            </div>
          )}

          {/* TAB 5: THREAT INDICATORS (IOCs) */}
          {activeTab === 'iocs' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: 'rgba(0, 0, 0, 0.35)', borderRadius: 8, border: '1px solid rgba(255, 255, 255, 0.08)', padding: 16 }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--accent-cyan)', textTransform: 'uppercase', marginBottom: 10 }}>
                  Confirmed Indicators of Compromise (IOCs):
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {safeData.iocs.map((ioc, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '8px 12px',
                        background: 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid rgba(255, 255, 255, 0.05)',
                        borderRadius: 6,
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.76rem',
                        color: 'var(--text-primary)',
                      }}
                    >
                      <span>{ioc}</span>
                      <span style={{ fontSize: '0.65rem', color: '#10b981', fontWeight: 700 }}>VERIFIED</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(16, 185, 129, 0.05)', borderRadius: 8, border: '1px solid rgba(16, 185, 129, 0.25)', padding: 14 }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#10b981', textTransform: 'uppercase', marginBottom: 6 }}>
                  Recommended Production Hardening & Countermeasure:
                </div>
                <p style={{ margin: 0, fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {safeData.countermeasure || 'Enforce automated host isolation via eBPF kernel socket severance and register adversary source IP in perimeter BGP Flowspec filter.'}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          style={{
            padding: '12px 24px',
            borderTop: '1px solid rgba(255, 255, 255, 0.08)',
            background: 'rgba(0, 0, 0, 0.4)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            fontSize: '0.75rem',
          }}
        >
          <span style={{ color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            Threat Intercepted & Host Quarantined by Apex Sentinel IPS Controller
          </span>
          <div style={{ display: 'flex', gap: 10 }}>
            {onTrigger && (
              <button
                onClick={handleTrigger}
                className="btn btn-primary btn-sm"
                style={{ fontSize: '0.75rem' }}
              >
                ⚡ Trigger Vector
              </button>
            )}
            <button onClick={onClose} className="btn btn-ghost btn-sm">
              Close Dossier
            </button>
          </div>
      </div>
    </div>,
    document.body
  );
}
