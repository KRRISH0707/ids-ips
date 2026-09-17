'use client';

import React, { useState } from 'react';

/**
 * Apex Sentinel Quantum Hex-Shield Brand Logo
 * Renders the official Quantum Hex-Shield emblem with dynamic glow and vector fallback.
 */
export default function BrandLogo({ size = 34, style = {}, showGlow = true }) {
  const [imgError, setImgError] = useState(false);

  return (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: Math.max(8, Math.round(size * 0.25)),
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.85) 100%)',
        border: '1px solid rgba(0, 212, 255, 0.4)',
        boxShadow: showGlow
          ? '0 0 16px rgba(0, 212, 255, 0.3), 0 0 25px rgba(124, 58, 237, 0.2)'
          : 'none',
        position: 'relative',
        flexShrink: 0,
        ...style,
      }}
      title="Apex Sentinel — Quantum Hex-Shield"
    >
      {!imgError ? (
        <img
          src="/brand/logo.png"
          alt="Apex Sentinel Logo"
          onError={() => setImgError(true)}
          style={{
            width: '100%',
            height: '100%',
            objectFit: 'cover',
            transform: 'scale(1.18)',
          }}
        />
      ) : (
        <svg
          width={Math.round(size * 0.65)}
          height={Math.round(size * 0.65)}
          viewBox="0 0 24 24"
          fill="none"
        >
          <path
            d="M12 2L3 6v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6l-9-4z"
            stroke="url(#apexGradient)"
            strokeWidth="1.8"
            strokeLinejoin="round"
          />
          <polygon
            points="12,7 16,10 16,15 12,18 8,15 8,10"
            stroke="#00d4ff"
            strokeWidth="1.2"
            fill="rgba(0, 212, 255, 0.15)"
          />
          <circle cx="12" cy="12.5" r="2" fill="#7c3aed" stroke="#38bdf8" strokeWidth="1" />
          <defs>
            <linearGradient id="apexGradient" x1="3" y1="2" x2="21" y2="22" gradientUnits="userSpaceOnUse">
              <stop stopColor="#00d4ff" />
              <stop offset="0.5" stopColor="#a855f7" />
              <stop offset="1" stopColor="#00d4ff" />
            </linearGradient>
          </defs>
        </svg>
      )}
    </div>
  );
}
