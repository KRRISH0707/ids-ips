'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { getToken, ensureAuth } from './api';

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000';

/**
 * Connect to the IDS/IPS WebSocket live feed.
 * Returns { messages, isConnected, error }
 */
export function useLiveFeed(maxMessages = 50) {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = useCallback(async () => {
    let token = getToken();
    if (!token) {
      token = await ensureAuth();
    }
    if (!token) {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = setTimeout(connect, 3000);
      return;
    }

    const host = typeof window !== 'undefined' ? window.location.hostname : 'localhost';
    const wsBase = process.env.NEXT_PUBLIC_WS_URL || `ws://${host}:8000`;
    const url = `${wsBase}/api/ws/live?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        setMessages((prev) => [
          { ...msg, _ts: Date.now() },
          ...prev.slice(0, maxMessages - 1),
        ]);
      } catch {
        // ignore non-JSON
      }
    };

    ws.onerror = () => setError('WebSocket connection error');

    ws.onclose = (e) => {
      setIsConnected(false);
      if (e.code !== 1000) {
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      }
    };
  }, [maxMessages]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      wsRef.current?.close(1000, 'component unmounted');
    };
  }, [connect]);

  return { messages, isConnected, error };
}
