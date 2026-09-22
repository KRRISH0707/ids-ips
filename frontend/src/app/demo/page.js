'use client';

import { useState, useEffect, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams, useRouter } from 'next/navigation';
import BrandLogo from '@/components/BrandLogo';
import ThreatPostureGauge from '@/components/ThreatPostureGauge';
import CyberKillChain from '@/components/CyberKillChain';
import GeoThreatRadar from '@/components/GeoThreatRadar';
import AttackLabPanel from '@/components/AttackLabPanel';
import { StatCard, SeverityBadge, StatusBadge } from '@/components/ui';
import { api, getUser, getToken, setToken, setUser, clearToken } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend
} from 'recharts';

function DemoDashboardContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const companyName = searchParams.get('company') || 'Cyber Corp Global';
  const userName = searchParams.get('name') || 'Alex Mercer';
  const endpointCount = searchParams.get('endpoints') || '50 - 250 Endpoints';

  // Demo Authentication & RBAC Viewer State
  const [currentUser, setCurrentUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);
  const [demoEmail, setDemoEmail] = useState('');
  const [demoPassword, setDemoPassword] = useState('');

  useEffect(() => {
    const user = getUser();
    const token = getToken();
    if (user && token) {
      setCurrentUser(user);
    } else {
      setCurrentUser(null);
    }
    setAuthChecked(true);
  }, []);

  const handleDemoAuthenticate = async (e) => {
    e.preventDefault();
    setAuthError('');
    setAuthLoading(true);
    try {
      const data = await api.login(demoEmail, demoPassword);
      setToken(data.access_token);
      setUser(data.user);
      setCurrentUser(data.user);
    } catch (err) {
      setAuthError(err.message || 'Demo authentication failed. Please check credentials.');
    } finally {
      setAuthLoading(false);
    }
  };

  // State for simulated scenario
  const [activeScenario, setActiveScenario] = useState('NORMAL');
  const [threatScore, setThreatScore] = useState(38);
  const [threatLevel, setThreatLevel] = useState('GUARDED DEFENSE');
  const [mttc, setMttc] = useState('0.92s');
  const [accuracy, setAccuracy] = useState('99.94%');
  const [killChainBreakRate, setKillChainBreakRate] = useState('100%');
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
    setThreatLevel(`${attack.badge} // ${attack.shortName}`);
    setMttc(attack.mttc || '0.48s');
    setAccuracy(`${(99.92 + Math.random() * 0.07).toFixed(2)}%`);
    setKillChainBreakRate('100%');
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
    setThreatScore(38);
    setThreatLevel('GUARDED DEFENSE');
    setMttc('0.92s');
    setAccuracy('99.94%');
    setKillChainBreakRate('100%');
    setActiveKillChainStage(null);
  };

  // Real-time synchronization: automatically reflect incoming live cyber attacks in the demo sandbox
  useOnLiveEvent((event) => {
    if (event.signature) {
      setThreatScore(event.risk_score || 88);
      setThreatLevel(`${event.severity || 'CRITICAL'} // LIVE TELEMETRY INTERCEPT`);
      setMttc(event.autonomous_mitigation?.mttc || '0.38s');
      setBlockedCount((prev) => prev + (event.autonomous_mitigation?.prevented ? 1 : 0));
      setEvents((prev) => [
        {
          id: `EVT-${event.id ? String(event.id).slice(0, 4).toUpperCase() : Math.floor(Math.random() * 9000 + 1000)}`,
          time: 'Just now (Live)',
          signature: event.signature,
          src_ip: event.src_ip ? `${event.src_ip}` : 'External Attacker',
          dst_ip: event.dst_ip || '10.240.0.1 (Perimeter Gateway)',
          severity: event.severity || 'CRITICAL',
          status: event.autonomous_mitigation?.prevented ? 'AUTO_CONTAINED' : 'DETECTED',
          action: event.autonomous_mitigation?.action || 'Autonomous IPS Quarantine',
        },
        ...prev.slice(0, 19),
      ]);
    }
  });

  if (!authChecked) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-void)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="loading-dot" style={{ width: 12, height: 12 }} />
      </div>
    );
  }

  // If user is not signed in, enforce Demo Sign-In Gate
  if (!currentUser) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'var(--bg-void)',
        padding: 24,
      }}>
        {/* Ambient glow */}
        <div style={{
          position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
          width: 600, height: 300,
          background: 'radial-gradient(ellipse, rgba(0,212,255,0.06) 0%, transparent 70%)',
          pointerEvents: 'none',
        }}/>

        <div className="hud-card fade-in" style={{ width: '100%', maxWidth: 480, padding: '40px 36px', boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 212, 255, 0.15)' }}>
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <BrandLogo size={56} style={{ margin: '0 auto 14px' }} />
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
              <span className="live-dot" style={{ width: 6, height: 6 }} />
              <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>
                DEMO ACCESS GATEWAY
              </span>
            </div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 900, margin: 0, letterSpacing: '0.04em' }}>
              <span className="glow-gradient">DEMO SIGN-IN REQUIRED</span>
            </h1>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.5 }}>
              To evaluate the Apex Sentinel Autonomous Detection Sandbox, you must authenticate using demo viewer credentials.
            </p>
          </div>

          <form onSubmit={handleDemoAuthenticate}>
            <div style={{ marginBottom: 14 }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                EMAIL ADDRESS
              </label>
              <input
                type="email"
                className="input"
                value={demoEmail}
                onChange={(e) => setDemoEmail(e.target.value)}
                placeholder="name@company.com"
                required
              />
            </div>

            <div style={{ marginBottom: 20 }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 6 }}>
                PASSWORD
              </label>
              <input
                type="password"
                className="input"
                value={demoPassword}
                onChange={(e) => setDemoPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>

            {authError && (
              <div style={{
                background: 'rgba(239,68,68,0.1)',
                border: '1px solid rgba(239,68,68,0.25)',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: '0.8rem',
                color: 'var(--sev-critical)',
                marginBottom: 16,
              }}>
                {authError}
              </div>
            )}

            <button
              type="submit"
              disabled={authLoading}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px 18px', fontSize: '0.88rem', fontWeight: 700 }}
            >
              {authLoading ? 'Authenticating Demo Session...' : '⚡ Launch Demo Dashboard (Viewer)'}
            </button>
          </form>

          <div style={{ textAlign: 'center', marginTop: 20, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <Link href="/login" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textDecoration: 'none' }}>
              Have an Analyst or Admin account? Full Login ➔
            </Link>
            <Link href="/landing" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textDecoration: 'none' }}>
              ← Return to Product Overview
            </Link>
          </div>
        </div>
      </div>
    );
  }

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
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ padding: '3px 8px', borderRadius: 4, background: '#7c3aed', color: '#fff', fontWeight: 800, fontSize: '0.7rem' }}>
            DEMO SANDBOX
          </span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
            Commercial Evaluation for <b style={{ color: 'var(--accent-cyan)' }}>{companyName}</b>
          </span>
          <span style={{ color: 'var(--text-muted)' }}>·</span>
          <span style={{ color: '#10b981', fontWeight: 600, background: 'rgba(16,185,129,0.15)', padding: '2px 8px', borderRadius: 4, fontSize: '0.74rem' }}>
            👁️ Role: {currentUser?.role || 'VIEWER'} ({currentUser?.email})
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Link
            href="/"
            className="btn btn-sm"
            style={{
              fontSize: '0.74rem',
              fontWeight: 600,
              background: 'rgba(0,212,255,0.12)',
              border: '1px solid rgba(0,212,255,0.3)',
              color: '#00d4ff'
            }}
          >
            Go to Production Console ➔
          </Link>
          <button
            onClick={() => {
              clearToken();
              setCurrentUser(null);
            }}
            className="btn btn-ghost btn-sm"
            style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}
          >
            Sign Out
          </button>
        </div>
      </div>

      {/* Main Container */}
      <div style={{ flex: 1, padding: '24px 36px', maxWidth: 1600, margin: '0 auto', width: '100%' }}>
        {/* Header with Title & Scenario Simulator Bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, gap: 20, flexWrap: 'wrap' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <BrandLogo size={38} />
              <div>
                <h1 style={{ fontSize: '1.45rem', fontWeight: 900, margin: 0, letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="glow-gradient">APEX SENTINEL</span>
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
            accuracy={accuracy}
            killChainBreakRate={killChainBreakRate}
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

          <div className="table-wrapper" data-horizontal-scroll="true">
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
