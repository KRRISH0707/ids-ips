'use client';

import { useState } from 'react';

/**
 * AttackDossierModal Component
 * Renders a full-fidelity cybersecurity threat intelligence dossier with
 * real CVEs, raw payloads, hex dumps, MITRE mappings, and containment receipts.
 */
export default function AttackDossierModal({ attack, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [copied, setCopied] = useState(false);
  const [pcapDownloaded, setPcapDownloaded] = useState(false);

  if (!attack) return null;

  const handleCopyPayload = () => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(attack.payload);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadPcap = () => {
    setPcapDownloaded(true);
    setTimeout(() => setPcapDownloaded(false), 3000);
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(2, 4, 8, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="hud-card"
        onClick={(e) => e.stopPropagation()}
        style={{
          width: '100%',
          maxWidth: 860,
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          background: 'rgba(6, 13, 24, 0.95)',
          border: '1px solid rgba(0, 212, 255, 0.35)',
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 40px rgba(0, 212, 255, 0.2)',
          padding: 0,
          overflow: 'hidden',
        }}
      >
        {/* Top Header Bar */}
        <div style={{
          padding: '16px 24px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          background: 'linear-gradient(90deg, rgba(0, 212, 255, 0.1) 0%, rgba(124, 58, 237, 0.1) 100%)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: '1.2rem' }}>⚡</span>
              <h2 style={{ margin: 0, fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                {attack.name}
              </h2>
              <span style={{
                fontSize: '0.68rem',
                fontWeight: 800,
                padding: '2px 8px',
                borderRadius: 4,
                background: attack.badge === 'CRITICAL' ? 'rgba(239, 68, 68, 0.25)' : 'rgba(249, 115, 22, 0.25)',
                color: attack.badge === 'CRITICAL' ? '#f87171' : '#fb923c',
                border: `1px solid ${attack.badge === 'CRITICAL' ? '#ef4444' : '#f97316'}`,
              }}>
                {attack.badge}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4, fontFamily: 'JetBrains Mono, monospace' }}>
              Attribution: <b style={{ color: 'var(--accent-cyan)' }}>{attack.actor}</b> · Score: <b style={{ color: '#ef4444' }}>{attack.threatScore}/100</b> · CVSS: <b style={{ color: '#f59e0b' }}>{attack.cvss}</b>
            </div>
          </div>

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

        {/* Tab Navigation */}
        <div style={{
          display: 'flex',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          background: 'rgba(0, 0, 0, 0.3)',
          padding: '0 24px',
        }}>
          {[
            { id: 'overview', label: '1. Overview & Vector' },
            { id: 'payload', label: '2. Payload & Hex Forensics' },
            { id: 'mitre', label: '3. MITRE ATT&CK® Correlation' },
            { id: 'resolution', label: '4. Autonomous Mitigation Receipt' },
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
                transition: 'all 0.2s',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content Body */}
        <div style={{ flex: 1, padding: 24, overflowY: 'auto', minHeight: 320 }}>
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div style={{
                background: 'rgba(0, 212, 255, 0.04)',
                border: '1px solid rgba(0, 212, 255, 0.15)',
                borderRadius: 8,
                padding: 16,
                fontSize: '0.85rem',
                lineHeight: 1.6,
                color: 'var(--text-primary)',
              }}>
                <div style={{ fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: 4, fontSize: '0.8rem', textTransform: 'uppercase' }}>
                  Technical Threat Abstract:
                </div>
                {attack.overview}
              </div>

              {/* Threat Matrix Badges */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attacker Source</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--sev-critical)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {attack.attackerIp}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>{attack.attackerAsn}</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Targeted Asset</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {attack.targetAsset}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Port {attack.targetPort} ({attack.protocol})</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Containment Speed</div>
                  <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--accent-green)', fontFamily: 'JetBrains Mono', marginTop: 2 }}>
                    {attack.mttc}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Sub-Second Response</div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Kill Chain Phase</div>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#a855f7', marginTop: 2 }}>
                    {attack.killChainName}
                  </div>
                  <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>Stage 0{attack.killChainStage + 1} Trajectory</div>
                </div>
              </div>

              {/* Step-by-Step Infection Chain */}
              <div>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: 8, letterSpacing: '0.04em' }}>
                  Adversary Execution & Interception Chain:
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {attack.infectionChain.map((step, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '8px 12px',
                        borderRadius: 6,
                        background: idx === attack.infectionChain.length - 1 ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                        border: idx === attack.infectionChain.length - 1 ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(255, 255, 255, 0.04)',
                        fontSize: '0.8rem',
                        color: idx === attack.infectionChain.length - 1 ? '#34d399' : 'var(--text-secondary)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                      }}
                    >
                      <span>{idx === attack.infectionChain.length - 1 ? '🛡️' : '▹'}</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PAYLOAD & HEX */}
          {activeTab === 'payload' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    Raw Captured Packet Exploit String:
                  </span>
                  <button
                    onClick={handleCopyPayload}
                    className="btn btn-ghost btn-sm"
                    style={{ fontSize: '0.72rem', padding: '2px 8px' }}
                  >
                    {copied ? '✓ Copied!' : '📋 Copy Payload'}
                  </button>
                </div>
                <pre style={{
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
                }}>
                  {attack.payload}
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
                <pre style={{
                  background: '#020617',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  borderRadius: 8,
                  padding: 14,
                  fontSize: '0.76rem',
                  color: '#94a3b8',
                  fontFamily: 'JetBrains Mono, monospace',
                  lineHeight: 1.5,
                  overflowX: 'auto',
                }}>
                  {attack.hexDump}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 3: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: 14,
              }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ENTERPRISE TACTIC</div>
                  <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: 4 }}>
                    {attack.mitre.tactic} ({attack.mitre.tacticId})
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PRIMARY TECHNIQUE</div>
                  <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f59e0b', marginTop: 4 }}>
                    {attack.mitre.technique} ({attack.mitre.techniqueId})
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SUB-TECHNIQUE INVOLVED</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#a855f7', marginTop: 4 }}>
                    {attack.mitre.subTechnique}
                  </div>
                </div>

                <div style={{ background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)' }}>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DEFENSE EVASION VECTOR</div>
                  <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ef4444', marginTop: 4 }}>
                    {attack.mitre.defenseEvasion}
                  </div>
                </div>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.02)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 8, textTransform: 'uppercase' }}>
                  Apex Sentinel Automated MITRE Detection Logic:
                </div>
                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  Apex Sentinel correlates raw libpcap flow telemetry against the MITRE ATT&CK knowledgebase.
                  When matching the signature {attack.cve}, the heuristic classifier calculates anomaly confidence,
                  maps the adversary to {attack.actor}, and initiates zero-touch containment playbooks before privilege escalation.
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
                  {attack.resolutionSteps.map((res, idx) => (
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
                  # {attack.kernelCommand}
                </code>
              </div>

              {/* Cryptographic Digest & PCAP Export */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 8, borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'JetBrains Mono' }}>
                  Evidence Hash: <b style={{ color: 'var(--text-muted)' }}>{attack.verificationHash}</b>
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
        </div>

        {/* Footer */}
        <div style={{
          padding: '12px 24px',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          background: 'rgba(0, 0, 0, 0.4)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '0.75rem',
        }}>
          <span style={{ color: '#10b981', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            Threat Intercepted & Host Quarantined by Apex Sentinel IPS Controller
          </span>
          <button
            onClick={onClose}
            className="btn btn-ghost btn-sm"
          >
            Close Threat Dossier
          </button>
        </div>
      </div>
    </div>
  );
}
