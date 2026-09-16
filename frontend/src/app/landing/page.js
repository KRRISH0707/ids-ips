'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function LandingPage() {
  const [activeTab, setActiveTab] = useState('linux');
  const [showDemoModal, setShowDemoModal] = useState(false);
  const [demoSubmitted, setDemoSubmitted] = useState(false);
  const [demoForm, setDemoForm] = useState({ name: '', company: '', email: '', endpoints: '50-250' });

  const handleDemoSubmit = (e) => {
    e.preventDefault();
    setDemoSubmitted(true);
  };

  return (
    <div style={{ minHeight: '100vh', background: '#030712', color: '#f8fafc', fontFamily: 'Inter, system-ui, sans-serif' }}>
      {/* Background ambient neon glow spheres */}
      <div style={{ position: 'fixed', top: '-10%', left: '20%', width: '600px', height: '600px', borderRadius: '50%', background: 'radial-gradient(circle, rgba(0, 212, 255, 0.08) 0%, transparent 70%)', filter: 'blur(80px)', pointerEvents: 'none' }} />
      <div style={{ position: 'fixed', bottom: '10%', right: '10%', width: '500px', height: '500px', borderRadius: '50%', background: 'radial-gradient(circle, rgba(124, 58, 237, 0.1) 0%, transparent 70%)', filter: 'blur(90px)', pointerEvents: 'none' }} />

      {/* Navigation Bar */}
      <nav style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '20px 48px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', backdropFilter: 'blur(12px)', position: 'sticky', top: 0, zIndex: 100, background: 'rgba(3, 7, 18, 0.8)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 16px rgba(0, 212, 255, 0.4)' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div>
            <div style={{ fontSize: '1.1rem', fontWeight: 800, letterSpacing: '0.04em', background: 'linear-gradient(90deg, #fff 0%, #cbd5e1 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              AEGIS CYBER DEFENSE
            </div>
            <div style={{ fontSize: '0.65rem', color: '#00d4ff', letterSpacing: '0.1em', fontWeight: 700 }}>
              ENTERPRISE IDS/IPS PLATFORM
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 28, fontSize: '0.88rem', fontWeight: 500 }}>
          <a href="#features" style={{ color: '#94a3b8', textDecoration: 'none', transition: 'color 0.2s' }}>Features</a>
          <a href="#architecture" style={{ color: '#94a3b8', textDecoration: 'none', transition: 'color 0.2s' }}>Architecture</a>
          <a href="#download" style={{ color: '#94a3b8', textDecoration: 'none', transition: 'color 0.2s' }}>Sensor Agent</a>
          <a href="#pricing" style={{ color: '#94a3b8', textDecoration: 'none', transition: 'color 0.2s' }}>Pricing</a>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <button
            onClick={() => setShowDemoModal(true)}
            style={{ padding: '8px 18px', borderRadius: 8, background: 'transparent', border: '1px solid rgba(255, 255, 255, 0.2)', color: '#fff', fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s' }}
          >
            Request Demo
          </button>
          <Link
            href="/login"
            style={{ padding: '8px 20px', borderRadius: 8, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', color: '#fff', fontSize: '0.85rem', fontWeight: 700, textDecoration: 'none', boxShadow: '0 0 20px rgba(0, 212, 255, 0.35)', transition: 'transform 0.2s' }}
          >
            Launch SOC Console →
          </Link>
        </div>
      </nav>

      {/* Hero Section */}
      <section style={{ maxWidth: 1200, margin: '0 auto', padding: '90px 24px 60px', textAlign: 'center', position: 'relative' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.1)', border: '1px solid rgba(0, 212, 255, 0.3)', marginBottom: 24 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#00d4ff', boxShadow: '0 0 8px #00d4ff', display: 'inline-block' }} />
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#38bdf8', letterSpacing: '0.06em' }}>
            ENTERPRISE COMMERCIAL RELEASE v2.4 • MULTI-VECTOR NEURAL IDS/IPS
          </span>
        </div>

        <h1 style={{ fontSize: '3.6rem', fontWeight: 900, lineHeight: 1.15, letterSpacing: '-0.03em', margin: '0 0 24px', background: 'linear-gradient(180deg, #ffffff 0%, #94a3b8 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          Autonomous Cyber Defense &<br />
          <span style={{ background: 'linear-gradient(90deg, #00d4ff 0%, #a855f7 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Predictive Intrusion Prevention
          </span>
        </h1>

        <p style={{ fontSize: '1.2rem', color: '#94a3b8', maxWidth: 780, margin: '0 auto 36px', lineHeight: 1.6 }}>
          Detect, forecast, and neutralize sophisticated cyber attacks before breach execution. Integrates real-time packet telemetry, automated SOAR playbooks, MITRE ATT&CK® mapping, and 1-click endpoint quarantine.
        </p>

        <div style={{ display: 'flex', justifyContent: 'center', gap: 16, marginBottom: 50 }}>
          <Link
            href="/login"
            style={{ padding: '14px 32px', borderRadius: 10, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', color: '#fff', fontSize: '1rem', fontWeight: 800, textDecoration: 'none', boxShadow: '0 0 30px rgba(0, 212, 255, 0.4)', transition: 'transform 0.2s' }}
          >
            Access Security Console
          </Link>
          <button
            onClick={() => setShowDemoModal(true)}
            style={{ padding: '14px 28px', borderRadius: 10, background: 'rgba(255, 255, 255, 0.05)', border: '1px solid rgba(255, 255, 255, 0.15)', color: '#f8fafc', fontSize: '1rem', fontWeight: 600, cursor: 'pointer' }}
          >
            Schedule Product Walkthrough
          </button>
        </div>

        {/* Live Attack Simulator Preview Widget */}
        <div style={{ maxWidth: 960, margin: '0 auto', borderRadius: 16, background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%)', border: '1px solid rgba(0, 212, 255, 0.25)', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 212, 255, 0.15)', overflow: 'hidden', textAlign: 'left' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 20px', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', background: 'rgba(0, 0, 0, 0.4)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#ef4444' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#f59e0b' }} />
              <div style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }} />
              <span style={{ fontSize: '0.75rem', color: '#64748b', marginLeft: 8, fontFamily: 'monospace' }}>aegis-soc-telemetry-engine // live-feed</span>
            </div>
            <span style={{ fontSize: '0.72rem', color: '#10b981', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} /> ACTIVE THREAT MONITORING
            </span>
          </div>

          <div style={{ padding: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
            {/* Live Detection Card */}
            <div style={{ background: 'rgba(0, 0, 0, 0.4)', borderRadius: 10, padding: 18, border: '1px solid rgba(239, 68, 68, 0.3)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 800, padding: '3px 8px', borderRadius: 4, background: 'rgba(239, 68, 68, 0.2)', color: '#f87171' }}>
                  CRITICAL INCIDENT
                </span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Risk Score: 98/100</span>
              </div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fff', marginBottom: 6 }}>
                Cobalt Strike Malleable C2 Beacon
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', fontFamily: 'monospace', marginBottom: 14 }}>
                192.168.1.150:50431 → 45.33.32.156:443
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.75rem', color: '#ef4444', fontWeight: 700 }}>
                <span>🛡️</span> HOST AUTONOMOUSLY QUARANTINED
              </div>
            </div>

            {/* AI Prediction Card */}
            <div style={{ background: 'rgba(0, 0, 0, 0.4)', borderRadius: 10, padding: 18, border: '1px solid rgba(139, 92, 246, 0.3)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 800, padding: '3px 8px', borderRadius: 4, background: 'rgba(139, 92, 246, 0.2)', color: '#c084fc' }}>
                  AI NEURAL INFERENCE
                </span>
                <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>Confidence: 99%</span>
              </div>
              <div style={{ fontWeight: 700, fontSize: '0.95rem', color: '#fff', marginBottom: 6 }}>
                Classified: C2_ACTIVE_SESSION
              </div>
              <div style={{ fontSize: '0.78rem', color: '#fbbf24', marginBottom: 14 }}>
                Forecast: Stage 2 Lateral Movement sweep to domain controller via SMB/RPC
              </div>
              <div style={{ fontSize: '0.75rem', color: '#34d399', fontWeight: 700 }}>
                ✓ SOAR Playbook PB-02 Enforced
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Grid */}
      <section id="features" style={{ maxWidth: 1200, margin: '60px auto', padding: '40px 24px' }}>
        <div style={{ textAlign: 'center', marginBottom: 50 }}>
          <h2 style={{ fontSize: '2.2rem', fontWeight: 800, margin: '0 0 12px' }}>
            Built for Modern Enterprise Security Teams
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '1.05rem', margin: 0 }}>
            Comprehensive visibility, deep forensics, and automated containment in a single pane of glass.
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 24 }}>
          {/* Feature 1 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(0, 212, 255, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              🧠
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>AI/ML Predictive Defense</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Multi-vector anomaly scoring utilizing Shannon entropy analysis, burst velocity tracking, and next-stage trajectory forecasting.
            </p>
          </div>

          {/* Feature 2 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(239, 68, 68, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              🛡️
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>1-Click Endpoint Quarantine</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Instantly sever network communication to compromised machines via kernel-level iptables drops while maintaining management access.
            </p>
          </div>

          {/* Feature 3 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(139, 92, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              🤖
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>SOAR Incident Playbooks</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Automated multi-step remediation for ransomware containment, C2 beacon neutralization, and credential stuffing mitigations.
            </p>
          </div>

          {/* Feature 4 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(245, 158, 11, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              🎯
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>MITRE ATT&CK® Matrix</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Live adversary technique mapping across 9 enterprise tactics with intensity heatmaps and correlated trigger telemetry.
            </p>
          </div>

          {/* Feature 5 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(16, 185, 129, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              🌐
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>Interactive Topology Canvas</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Live network graph animating adversary lateral movement paths, isolated nodes, and perimeter gateway telemetry in real time.
            </p>
          </div>

          {/* Feature 6 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 12, padding: 28 }}>
            <div style={{ width: 44, height: 44, borderRadius: 10, background: 'rgba(59, 130, 246, 0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1.4rem', marginBottom: 16 }}>
              📦
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 10px' }}>DPI & PCAP Forensics</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.88rem', lineHeight: 1.6, margin: 0 }}>
              Deep packet inspection with hex dump byte dissections and one-click Libpcap export ready for forensic Wireshark analysis.
            </p>
          </div>
        </div>
      </section>

      {/* Sensor Agent Download Hub */}
      <section id="download" style={{ maxWidth: 960, margin: '60px auto', padding: '40px 24px' }}>
        <div style={{ background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.5) 100%)', border: '1px solid rgba(0, 212, 255, 0.25)', borderRadius: 16, padding: 36 }}>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 800, margin: '0 0 8px' }}>
            Deploy Sensor Probes Across Your Fleet
          </h2>
          <p style={{ color: '#94a3b8', fontSize: '0.92rem', margin: '0 0 24px' }}>
            Install lightweight inline capture agents on servers, DMZ gateways, or workstation subnets in seconds.
          </p>

          <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
            <button
              onClick={() => setActiveTab('linux')}
              style={{ padding: '6px 16px', borderRadius: 6, background: activeTab === 'linux' ? '#00d4ff' : 'rgba(255, 255, 255, 0.05)', color: activeTab === 'linux' ? '#000' : '#fff', fontWeight: 700, border: 'none', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Linux (Ubuntu / Debian / RHEL)
            </button>
            <button
              onClick={() => setActiveTab('docker')}
              style={{ padding: '6px 16px', borderRadius: 6, background: activeTab === 'docker' ? '#00d4ff' : 'rgba(255, 255, 255, 0.05)', color: activeTab === 'docker' ? '#000' : '#fff', fontWeight: 700, border: 'none', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Docker Inline Agent
            </button>
            <button
              onClick={() => setActiveTab('windows')}
              style={{ padding: '6px 16px', borderRadius: 6, background: activeTab === 'windows' ? '#00d4ff' : 'rgba(255, 255, 255, 0.05)', color: activeTab === 'windows' ? '#000' : '#fff', fontWeight: 700, border: 'none', cursor: 'pointer', fontSize: '0.82rem' }}
            >
              Windows Server (PowerShell)
            </button>
          </div>

          <div style={{ background: '#020617', padding: '16px 20px', borderRadius: 8, fontFamily: 'Consolas, monospace', fontSize: '0.85rem', color: '#38bdf8', border: '1px solid rgba(255, 255, 255, 0.1)', overflowX: 'auto' }}>
            {activeTab === 'linux' && (
              <code>curl -sSL https://raw.githubusercontent.com/KRRISH0707/ids-ips/main/scripts/simulate_attack.py | python3 -</code>
            )}
            {activeTab === 'docker' && (
              <code>docker run -d --name ids-probe --net=host --restart=always -e SENSOR_NAME=&quot;DMZ-Probe&quot; idsips/probe:latest</code>
            )}
            {activeTab === 'windows' && (
              <code>{`powershell -Command "& {[System.Net.ServicePointManager]::SecurityProtocol = 'tls12'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/KRRISH0707/ids-ips/main/scripts/simulate_attack.py' -OutFile 'sensor.py'}; python sensor.py"`}</code>
            )}
          </div>
        </div>
      </section>

      {/* Commercial Pricing */}
      <section id="pricing" style={{ maxWidth: 1100, margin: '60px auto', padding: '40px 24px', textAlign: 'center' }}>
        <h2 style={{ fontSize: '2.2rem', fontWeight: 800, margin: '0 0 12px' }}>
          Commercial Deployment Pricing
        </h2>
        <p style={{ color: '#94a3b8', fontSize: '1rem', margin: '0 0 40px' }}>
          Flexible licensing for enterprise SOC teams, managed security providers, and mid-market organizations.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 24, textAlign: 'left' }}>
          {/* Tier 1 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: 14, padding: 32 }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 4px' }}>Starter Fleet</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '0 0 20px' }}>For small businesses & remote offices</p>
            <div style={{ fontSize: '2.4rem', fontWeight: 900, marginBottom: 20 }}>
              $499 <span style={{ fontSize: '0.9rem', color: '#94a3b8', fontWeight: 500 }}>/ month</span>
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 28px', display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.85rem', color: '#cbd5e1' }}>
              <li>✓ Up to 25 Monitored Probes</li>
              <li>✓ Real-Time Alert Ingestion</li>
              <li>✓ Automated Machine Quarantine</li>
              <li>✓ Community Rule Updates</li>
            </ul>
            <button onClick={() => setShowDemoModal(true)} style={{ width: '100%', padding: '12px', borderRadius: 8, background: 'rgba(255, 255, 255, 0.1)', border: '1px solid rgba(255, 255, 255, 0.2)', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>
              Select Starter
            </button>
          </div>

          {/* Tier 2 - Recommended */}
          <div style={{ background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%)', border: '2px solid #00d4ff', borderRadius: 14, padding: 32, position: 'relative', boxShadow: '0 0 30px rgba(0, 212, 255, 0.2)' }}>
            <div style={{ position: 'absolute', top: -12, right: 24, padding: '2px 10px', borderRadius: 12, background: '#00d4ff', color: '#000', fontSize: '0.72rem', fontWeight: 800 }}>
              MOST POPULAR
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 4px' }}>Enterprise SOC</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '0 0 20px' }}>Full automated intelligence & SOAR</p>
            <div style={{ fontSize: '2.4rem', fontWeight: 900, marginBottom: 20 }}>
              $1,499 <span style={{ fontSize: '0.9rem', color: '#94a3b8', fontWeight: 500 }}>/ month</span>
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 28px', display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.85rem', color: '#cbd5e1' }}>
              <li>✓ Up to 250 Monitored Probes</li>
              <li>✓ AI Multi-Vector Threat Prediction</li>
              <li>✓ SOAR Automated Response Playbooks</li>
              <li>✓ MITRE ATT&CK® Matrix Mapping</li>
              <li>✓ Interactive Network Topology</li>
              <li>✓ Threat Intelligence Feed Sync</li>
            </ul>
            <button onClick={() => setShowDemoModal(true)} style={{ width: '100%', padding: '12px', borderRadius: 8, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', border: 'none', color: '#fff', fontWeight: 800, cursor: 'pointer', boxShadow: '0 0 15px rgba(0, 212, 255, 0.4)' }}>
              Deploy Enterprise SOC
            </button>
          </div>

          {/* Tier 3 */}
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: 14, padding: 32 }}>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, margin: '0 0 4px' }}>Dedicated Appliance</h3>
            <p style={{ color: '#94a3b8', fontSize: '0.8rem', margin: '0 0 20px' }}>Custom multi-tenant clusters</p>
            <div style={{ fontSize: '2.4rem', fontWeight: 900, marginBottom: 20 }}>
              Custom
            </div>
            <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 28px', display: 'flex', flexDirection: 'column', gap: 10, fontSize: '0.85rem', color: '#cbd5e1' }}>
              <li>✓ Unlimited Probes & Endpoints</li>
              <li>✓ On-Premise Air-Gapped Deployment</li>
              <li>✓ Dedicated Threat Intel Feed Integration</li>
              <li>✓ 24/7 Tier-3 Incident Response SLA</li>
            </ul>
            <button onClick={() => setShowDemoModal(true)} style={{ width: '100%', padding: '12px', borderRadius: 8, background: 'rgba(255, 255, 255, 0.1)', border: '1px solid rgba(255, 255, 255, 0.2)', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>
              Contact Sales
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', padding: '36px 48px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.82rem', color: '#64748b' }}>
        <div>
          © 2026 Aegis Enterprise IDS/IPS Platform. All rights reserved.
        </div>
        <div style={{ display: 'flex', gap: 20 }}>
          <Link href="/login" style={{ color: '#94a3b8', textDecoration: 'none' }}>SOC Login</Link>
          <a href="https://github.com/KRRISH0707/ids-ips" target="_blank" rel="noopener noreferrer" style={{ color: '#00d4ff', textDecoration: 'none' }}>GitHub Repository</a>
          <a href="#download" style={{ color: '#94a3b8', textDecoration: 'none' }}>Agent Install</a>
        </div>
      </footer>

      {/* Request Demo Modal */}
      {showDemoModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }} onClick={() => setShowDemoModal(false)}>
          <div className="glass-card" onClick={(e) => e.stopPropagation()} style={{ width: '100%', maxWidth: 460, padding: 28, background: '#0b1120', border: '1px solid rgba(0, 212, 255, 0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 800 }}>Request Commercial Demo</h3>
              <button onClick={() => setShowDemoModal(false)} style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '1.1rem', cursor: 'pointer' }}>✕</button>
            </div>

            {demoSubmitted ? (
              <div style={{ textAlign: 'center', padding: '24px 10px' }}>
                <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🛡️</div>
                <h4 style={{ margin: '0 0 8px', fontSize: '1.1rem', color: '#38bdf8' }}>Demo Access Granted!</h4>
                <p style={{ color: '#94a3b8', fontSize: '0.85rem', lineHeight: 1.5, marginBottom: 20 }}>
                  You can immediately explore the live production SOC console using the credentials:
                  <br /><b style={{ color: '#fff' }}>krrish183224@gmail.com</b> / <b style={{ color: '#fff' }}>183@Krrish</b>
                </p>
                <Link
                  href="/login"
                  style={{ display: 'inline-block', padding: '10px 24px', borderRadius: 8, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', color: '#fff', fontWeight: 700, textDecoration: 'none' }}
                >
                  Enter SOC Console
                </Link>
              </div>
            ) : (
              <form onSubmit={handleDemoSubmit}>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: 4 }}>Full Name</label>
                  <input type="text" required style={{ width: '100%', padding: '10px 12px', borderRadius: 6, background: '#1e293b', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }} placeholder="Alex Mercer" value={demoForm.name} onChange={(e) => setDemoForm({ ...demoForm, name: e.target.value })} />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: 4 }}>Company / Organization</label>
                  <input type="text" required style={{ width: '100%', padding: '10px 12px', borderRadius: 6, background: '#1e293b', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }} placeholder="Cyber Corp Global" value={demoForm.company} onChange={(e) => setDemoForm({ ...demoForm, company: e.target.value })} />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: 4 }}>Work Email</label>
                  <input type="email" required style={{ width: '100%', padding: '10px 12px', borderRadius: 6, background: '#1e293b', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }} placeholder="alex@cybercorp.com" value={demoForm.email} onChange={(e) => setDemoForm({ ...demoForm, email: e.target.value })} />
                </div>
                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', marginBottom: 4 }}>Fleet Size (Endpoints / Probes)</label>
                  <select style={{ width: '100%', padding: '10px 12px', borderRadius: 6, background: '#1e293b', border: '1px solid #334155', color: '#fff', fontSize: '0.85rem' }} value={demoForm.endpoints} onChange={(e) => setDemoForm({ ...demoForm, endpoints: e.target.value })}>
                    <option value="1-50">1 - 50 Endpoints</option>
                    <option value="50-250">50 - 250 Endpoints</option>
                    <option value="250-1000">250 - 1,000 Endpoints</option>
                    <option value="1000+">1,000+ Endpoints</option>
                  </select>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" onClick={() => setShowDemoModal(false)} style={{ padding: '10px 16px', borderRadius: 6, background: 'transparent', border: '1px solid #334155', color: '#94a3b8', cursor: 'pointer' }}>Cancel</button>
                  <button type="submit" style={{ padding: '10px 20px', borderRadius: 6, background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)', border: 'none', color: '#fff', fontWeight: 700, cursor: 'pointer' }}>Submit Request</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
