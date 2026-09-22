'use client';

import React, { createContext, useContext, useState, useEffect, useMemo } from 'react';

const PRESETS = [
  { key: '24h', label: 'Last 24h', days: 1 },
  { key: '7d', label: 'Last 7 Days', days: 7 },
  { key: '14d', label: 'Last 14 Days', days: 14 },
  { key: '45d', label: 'Last 45 Days', days: 45, badge: 'Full Scope' },
];

const TimeRangeContext = createContext({
  timeRange: '45d',
  days: 45,
  setTimeRange: () => {},
  dateSpanText: '',
});

export function TimeRangeProvider({ children }) {
  const [timeRange, setTimeRangeState] = useState('45d');

  useEffect(() => {
    try {
      const saved = localStorage.getItem('ids_time_range');
      if (saved && PRESETS.some(p => p.key === saved)) {
        setTimeRangeState(saved);
      }
    } catch {}
  }, []);

  const setTimeRange = (rangeKey) => {
    setTimeRangeState(rangeKey);
    if (typeof window !== 'undefined') {
      try {
        localStorage.setItem('ids_time_range', rangeKey);
      } catch {}
    }
  };

  const activePreset = useMemo(() => {
    return PRESETS.find(p => p.key === timeRange) || PRESETS.find(p => p.key === '45d') || PRESETS[0];
  }, [timeRange]);

  const days = activePreset.days;

  const dateSpanText = useMemo(() => {
    const end = new Date();
    const options = { month: 'short', day: 'numeric' };
    if (!days) return 'All Recorded Time';
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
    return `${start.toLocaleDateString('en-US', options)} – ${end.toLocaleDateString('en-US', options)}, ${end.getFullYear()}`;
  }, [days]);

  return (
    <TimeRangeContext.Provider value={{ timeRange, days, setTimeRange, dateSpanText, PRESETS }}>
      {children}
    </TimeRangeContext.Provider>
  );
}


export function useTimeRange() {
  return useContext(TimeRangeContext);
}

export function TimeRangeSelector({ compact = false }) {
  const { timeRange, days, setTimeRange, dateSpanText, PRESETS: presets } = useTimeRange();

  return (
    <div
      className="glass-card"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 12,
        padding: compact ? '4px 10px' : '6px 14px',
        borderRadius: 24,
        border: '1px solid rgba(0, 212, 255, 0.25)',
        background: 'rgba(10, 16, 26, 0.75)',
        backdropFilter: 'blur(12px)',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.4)',
        flexWrap: 'wrap'
      }}
    >
      {/* Scope Badge & Active Beacon */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: timeRange === '45d' ? '#00d4ff' : '#10b981',
            boxShadow: `0 0 10px ${timeRange === '45d' ? '#00d4ff' : '#10b981'}`,
            animation: 'pulse 2s infinite'
          }}
        />
        <span style={{ fontSize: '0.74rem', fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>
          Telemetry Window:
        </span>
        <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#00d4ff', fontFamily: 'monospace' }}>
          {dateSpanText}
        </span>
      </div>

      {/* Preset Pill Buttons */}
      <div style={{ display: 'inline-flex', background: 'rgba(255,255,255,0.04)', borderRadius: 16, padding: 2, border: '1px solid rgba(255,255,255,0.06)' }}>
        {presets.map(p => {
          const isActive = timeRange === p.key;
          return (
            <button
              key={p.key}
              onClick={() => setTimeRange(p.key)}
              style={{
                border: 'none',
                background: isActive ? 'linear-gradient(135deg, rgba(0, 212, 255, 0.25), rgba(59, 130, 246, 0.3))' : 'transparent',
                color: isActive ? '#ffffff' : 'var(--text-secondary)',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.74rem',
                padding: '4px 11px',
                borderRadius: 14,
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                border: isActive ? '1px solid rgba(0, 212, 255, 0.4)' : '1px solid transparent',
                boxShadow: isActive ? '0 0 12px rgba(0, 212, 255, 0.25)' : 'none'
              }}
              title={`View platform telemetry for ${p.label}`}
            >
              <span>{p.label}</span>
              {p.badge && (
                <span
                  style={{
                    fontSize: '0.62rem',
                    background: isActive ? 'rgba(0, 212, 255, 0.35)' : 'rgba(255,255,255,0.1)',
                    color: isActive ? '#ffffff' : '#00d4ff',
                    padding: '1px 5px',
                    borderRadius: 8,
                    fontWeight: 700
                  }}
                >
                  {p.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
