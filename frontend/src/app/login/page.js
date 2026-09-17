'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api, setToken, setUser } from '@/lib/api';
import BrandLogo from '@/components/BrandLogo';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('krrish183224@gmail.com');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(email, password);
      setToken(data.access_token);
      setUser(data.user);
      router.push('/');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

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

      <div className="hud-card fade-in" style={{ width: '100%', maxWidth: 440, padding: '44px 38px', boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 212, 255, 0.12)' }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <BrandLogo size={64} style={{ margin: '0 auto 16px' }} />
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '3px 10px', borderRadius: 20, background: 'rgba(0, 212, 255, 0.08)', border: '1px solid rgba(0, 212, 255, 0.25)', marginBottom: 8 }}>
            <span className="live-dot" style={{ width: 6, height: 6 }} />
            <span style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--accent-cyan)', letterSpacing: '0.06em' }}>AUTONOMOUS IDS/IPS</span>
          </div>
          <h1 style={{ fontSize: '1.7rem', fontWeight: 900, letterSpacing: '0.04em', margin: 0 }}>
            <span className="glow-gradient">APEX SENTINEL</span>
          </h1>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4, letterSpacing: '0.04em' }}>
            AUTONOMOUS THREAT DEFENSE & SOC CONSOLE
          </p>
        </div>

        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
              EMAIL ADDRESS
            </label>
            <input
              id="email"
              type="email"
              className="input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@ids.local"
              required
            />
          </div>

          <div style={{ marginBottom: 24 }}>
            <label style={{ display: 'block', fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 6, letterSpacing: '0.04em' }}>
              PASSWORD
            </label>
            <input
              id="password"
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>

          {error && (
            <div style={{
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.25)',
              borderRadius: 8,
              padding: '10px 14px',
              fontSize: '0.82rem',
              color: 'var(--sev-critical)',
              marginBottom: 16,
            }}>
              {error}
            </div>
          )}

          <button
            id="login-btn"
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '11px 18px', fontSize: '0.9rem' }}
          >
            {loading ? (
              <span style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                <span className="loading-dot" style={{ width: 6, height: 6 }}/>
                <span className="loading-dot" style={{ width: 6, height: 6, animationDelay: '0.2s' }}/>
                <span className="loading-dot" style={{ width: 6, height: 6, animationDelay: '0.4s' }}/>
              </span>
            ) : 'Sign in'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: 24, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <Link
            href="/demo"
            style={{
              padding: '8px 14px',
              borderRadius: 8,
              background: 'rgba(0, 212, 255, 0.08)',
              border: '1px solid rgba(0, 212, 255, 0.25)',
              fontSize: '0.82rem',
              color: 'var(--accent-cyan)',
              textDecoration: 'none',
              fontWeight: 700,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6
            }}
          >
            <span>🎮</span> Testing or Evaluating? Launch Demo Sandbox ➔
          </Link>
          <Link
            href="/landing"
            style={{
              fontSize: '0.78rem',
              color: 'var(--text-secondary)',
              textDecoration: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 4
            }}
          >
            ← Product Overview & Architecture
          </Link>
          <p style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: 4 }}>
            Authorised access only · All telemetry recorded and cryptographically signed
          </p>
        </div>
      </div>
    </div>
  );
}
