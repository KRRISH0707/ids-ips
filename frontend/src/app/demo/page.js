'use client';

import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import ThreatPostureGauge from '@/components/ThreatPostureGauge';
import CyberKillChain from '@/components/CyberKillChain';
import GeoThreatRadar from '@/components/GeoThreatRadar';
import AttackLabPanel from '@/components/AttackLabPanel';
import { StatCard, SeverityBadge, StatusBadge } from '@/components/ui';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';

function DemoDashboardContent() {
  const searchParams = useSearchParams();
  const companyName = searchParams.get('company') || 'Cyber Corp Global';
  const userName = searchParams.get('name') || 'Alex Mercer';
  const endpointCount = searchParams.get('endpoints') || '50 - 250 Endpoints';

  // State for simulated scenario
  const [activeScenario, setActiveScenario] = useState('NORMAL');
  const [threatScore, setThreatScore] = useState(64);
  const [threatLevel, setThreatLevel] = useState('GUARDED / ELEVATED');
  const [mttc, setMttc] = useState('1.2s');
  const [blockedCount, setBlockedCount] = useState(3842);
  const [activeKillChainStage, setActiveKillChainStage] = useState(null);

  // Simulated live events list
  const [events, setEvents] = useState([
    {
      id: 'EVT-9041',
      time: 'Just now',
      signature: 'ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)',
      src_ip: '185.220.101.5',
      dst_ip: '10.240.10.12 (k8s-ingress.dmz)',
      severity: 'CRITICAL',
      status: 'AUTO_BLOCKED',
      action: 'IPS Drop & Packet Logged',
    },
    {
      id: 'EVT-9040',
      time: '12s ago',
      signature: 'APT29 Cobalt Strike Malleable C2 HTTPS Beacon',
      src_ip: '45.33.32.156',
      dst_ip: '10.240.20.88 (db-cust-vault.prod)',
      severity: 'HIGH',
      status: 'CONTAINED',
      action: 'DNS Sinkholed by AI Engine',
    },
    {
      id: 'EVT-9039',
      time: '45s ago',
      signature: 'ET POLICY SSH Brute Force Key Extraction',
      src_ip: '198.51.100.42',
      dst_ip: '10.240.10.4 (corp-ad-dc01.internal)',
      severity: 'HIGH',
      status: 'QUARANTINED',
      action: 'Rate-Limited & IP Banned',
    },
    {
      id: 'EVT-9038',
      time: '2m ago',
      signature: 'Kerberoasting Active Directory Ticket Request',
      src_ip: '10.240.15.22',
      dst_ip: '10.240.10.4 (corp-ad-dc01.internal)',
      severity: 'MEDIUM',
      status: 'INVESTIGATING',
      action: 'SOC Analyst Assigned',
    },
    {
      id: 'EVT-9037',
      time: '4m ago',
      signature: 'SYN Stealth Reconnaissance Sweep (> 100 Ports)',
      src_ip: '203.0.113.15',
      dst_ip: '10.240.0.0/24 (DMZ Perimeter)',
      severity: 'LOW',
      status: 'LOGGED',
      action: 'Telemetry Aggregated',
    },
  ]);

  // Simulated time-series traffic velocity
  const [trafficData, setTrafficData] = useState([
    { time: '14:00', packets: 4200, anomalies: 4 },
    { time: '14:15', packets: 6800, anomalies: 8 },
    { time: '14:30', packets: 5100, anomalies: 3 },
    { time: '14:45', packets: 9400, anomalies: 19 },
    { time: '15:00', packets: 12400, anomalies: 42 },
    { time: '15:15', packets: 8100, anomalies: 12 },
    { time: '15:30', packets: 7500, anomalies: 6 },
    { time: '15:45', packets: 14200, anomalies: 68 },
    { time: '16:00', packets: 9100, anomalies: 9 },
  ]);

  // Handle Attack Scenario Triggered from AttackLabPanel
  const handleAttackTriggered = (attack) => {
    setActiveScenario(attack.key);
    setThreatScore(attack.threatScore);
    setThreatLevel(`${attack.badge} // ${attack.name}`);
    setMttc(attack.mttc);
    setBlockedCount((prev) => prev + 1);
    setActiveKillChainStage(attack.killChainStage);

    setEvents((prev) => [
      {
        id: `EVT-${Math.floor(Math.random() * 9000 + 1000)}`,
        time: 'Just now',
        signature: `${attack.name} (${attack.cve.split(' ')[0]})`,
        src_ip: `${attack.attackerIp} (${attack.attackerAsn.split(' ')[0]})`,
        dst_ip: attack.targetAsset,
        severity: attack.badge,
        status: 'AUTO_CONTAINED',
        action: attack.resolutionSteps[attack.resolutionSteps.length - 1].text,
      },
      ...prev,
    ]);
  };

  const handleResetBaseline = () => {
    setActiveScenario('NORMAL');
    setThreatScore(64);
    setThreatLevel('GUARDED / ELEVATED');
    setMttc('1.2s');
    setActiveKillChainStage(null);
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-void)', color: 'var(--text-primary)', display: 'flex', flexDirection: 'column' }}>
      {/* Top Demo Banner */}
      <div style={{
        background: 'linear-gradient(90deg, rgba(124, 58, 237, 0.25) 0%, rgba(0, 212, 255, 0.25) 100%)',
        borderBottom: '1px solid rgba(0, 212, 255, 0.3)',
        padding: '10px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontSize: '0.82rem',
        zIndex: 50,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ padding: '3px 8px', borderRadius: 4, background: '#7c3aed', color: '#fff', fontWeight: 800, fontSize: '0.7rem' }}>
            DEMO SANDBOX
          </span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
            Commercial Evaluation for <b style={{ color: 'var(--accent-cyan)' }}>{companyName}</b> ({endpointCount})
          </span>
          <span style={{ color: 'var(--text-muted)' }}>·</span>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.78rem' }}>
            Operator: {userName} · Isolated Synthetic SOC Environment (Zero Admin Credentials Exposed)
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Link
            href="/landing"
            className="btn btn-ghost btn-sm"
            style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}
          >
            ← Exit Demo
          </Link>
          <a
            href="mailto:sales@ids-ips.enterprise?subject=Commercial%20POC%20Inquiry%20-%20"
            style={{
              padding: '6px 14px',
              borderRadius: 6,
              background: 'linear-gradient(135deg, #00d4ff 0%, #7c3aed 100%)',
              color: '#fff',
              fontWeight: 700,
              fontSize: '0.78rem',
              textDecoration: 'none',
              boxShadow: '0 0 16px rgba(0, 212, 255, 0.3)',
            }}
          >
            Deploy Production Appliance
          </a>
        </div>
      </div>

      {/* Main Container */}
      <div style={{ flex: 1, padding: '24px 36px', maxWidth: 1600, margin: '0 auto', width: '100%' }}>
        {/* Header with Title & Scenario Simulator Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, gap: 20, flexWrap: 'wrap' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 38, height: 38,
                borderRadius: 10,
                background: 'linear-gradient(135deg, rgba(0,212,255,0.2), rgba(124,58,237,0.2))',
                border: '1px solid var(--border-bright)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                color: 'var(--accent-cyan)',
              }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
              </div>
              <div>
                <h1 style={{ fontSize: '1.45rem', fontWeight: 900, margin: 0, letterSpacing: '0.02em', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="glow-gradient">AEGIS-X</span>
                  <span style={{ fontSize: '0.78rem', color: 'var(--accent-cyan)', background: 'rgba(0, 212, 255, 0.1)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(0, 212, 255, 0.3)', fontFamily: 'JetBrains Mono' }}>
                    SANDBOX
                  </span>
                </h1>
                <p style={{ margin: 0, fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Autonomous Neural Threat Interceptor · High-Fidelity Attack Simulator & Synthetic Telemetry
                </p>
              </div>
            </div>
          </div>

        </div>

        {/* Tactical Attack Simulation Laboratory & Autonomous Resolution Pipeline */}
        <div style={{ marginBottom: 24 }}>
          <AttackLabPanel
            onAttackTriggered={handleAttackTriggered}
            onResetBaseline={handleResetBaseline}
          />
        </div>

        {/* Row 1: KPI Stat Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 20 }}>
          <StatCard
            label="Protected Fleet"
            value={endpointCount.split(' ')[0] || '250'}
            color="var(--accent-cyan)"
            delta="100% Probes Online & Healthy"
          />
          <StatCard
            label="Attacks Blocked (24h)"
            value={Number(blockedCount).toLocaleString()}
            color="var(--sev-critical)"
            delta="Autonomous iptables Active"
          />
          <StatCard
            label="Mean Time to Contain"
            value={mttc}
            color="var(--accent-green)"
            delta="98.6% Sub-Second Severing"
          />
          <StatCard
            label="AI Predictive Accuracy"
            value="99.94%"
            color="#a855f7"
            delta="Zero False Positives"
          />
        </div>

        {/* Row 2: Threat Posture Radial Gauge */}
        <div style={{ marginBottom: 20 }}>
          <ThreatPostureGauge
            score={threatScore}
            threatLevel={threatLevel}
            mttc={mttc}
            blockedCount={blockedCount}
          />
        </div>

        {/* Row 3: Cyber Kill Chain Trajectory Pipeline */}
        <div style={{ marginBottom: 20 }}>
          <CyberKillChain activeStageIndex={activeKillChainStage} />
        </div>

        {/* Row 4: Geo Radar & Traffic Velocity Chart */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* Left: Geo Threat Origin Radar */}
          <div style={{ minWidth: 0 }}>
            <GeoThreatRadar />
          </div>

          {/* Right: Ingestion Velocity vs Anomaly Area Chart */}
          <div className="glass-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Telemetry Velocity & Anomaly Spikes
                </h3>
                <p style={{ margin: '2px 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Packets Ingested / sec vs Heuristic Threat Triggers
                </p>
              </div>
              <span style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                100,000 EPS Capable
              </span>
            </div>

            <div style={{ width: '100%', height: 220, minWidth: 0 }}>
              <ResponsiveContainer width="100%" height={220} debounce={50}>
                <AreaChart data={trafficData}>
                  <defs>
                    <linearGradient id="packetsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.0}/>
                    </linearGradient>
                    <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} />
                  <Tooltip contentStyle={{ background: '#0a1628', border: '1px solid rgba(0, 212, 255, 0.3)', borderRadius: 8, fontSize: '0.8rem' }} />
                  <Area type="monotone" dataKey="packets" stroke="#00d4ff" strokeWidth={2} fillOpacity={1} fill="url(#packetsGrad)" name="Packets/sec" />
                  <Area type="monotone" dataKey="anomalies" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#anomGrad)" name="Anomalies" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Row 5: Live Synthetic Threat Stream Table */}
        <div className="glass-card" style={{ padding: 24, marginBottom: 30 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="live-dot" /> Live Synthetic Telemetry & Automated IPS Log
              </h3>
              <p style={{ margin: '2px 0 0', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Demonstration events showing real-time Snort/Suricata rules, AI anomaly evaluations, and active mitigation
              </p>
            </div>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Showing real-time simulated stream
            </span>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ fontSize: '0.82rem' }}>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Timestamp</th>
                  <th>Signature / Exploit Vector</th>
                  <th>Adversary IP</th>
                  <th>Target Host</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Autonomous Action</th>
                </tr>
              </thead>
              <tbody>
                {events.map((evt) => (
                  <tr key={evt.id}>
                    <td style={{ fontFamily: 'monospace', fontWeight: 600, color: 'var(--text-muted)' }}>{evt.id}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{evt.time}</td>
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{evt.signature}</td>
                    <td style={{ fontFamily: 'monospace', color: 'var(--sev-critical)' }}>{evt.src_ip}</td>
                    <td style={{ fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{evt.dst_ip}</td>
                    <td>
                      <SeverityBadge severity={evt.severity} />
                    </td>
                    <td>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: 4,
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        background: evt.status === 'AUTO_BLOCKED' || evt.status === 'HOST_ISOLATED' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                        color: evt.status === 'AUTO_BLOCKED' || evt.status === 'HOST_ISOLATED' ? '#ef4444' : '#10b981',
                      }}>
                        {evt.status}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.75rem', color: '#38bdf8' }}>{evt.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function DemoDashboardPage() {
  return (
    <Suspense fallback={
      <div style={{ minHeight: '100vh', background: 'var(--bg-void)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="loading-dot" style={{ width: 12, height: 12 }} />
      </div>
    }>
      <DemoDashboardContent />
    </Suspense>
  );
}
