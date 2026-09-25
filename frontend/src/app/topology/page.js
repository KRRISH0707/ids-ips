'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner } from '@/components/ui';
import NeuralThreatMeshGraphic from '@/components/NeuralThreatMeshGraphic';
import { api } from '@/lib/api';
import { useLiveFeed } from '@/lib/useLiveFeed';

export default function TopologyPage() {
  const [alertStats, setAlertStats] = useState(null);
  const [ipsStats, setIpsStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const { liveMessages, isConnected } = useLiveFeed();

  const loadTelemetry = useCallback(async (showSpinner = false) => {
    try {
      if (showSpinner) setLoading(true);
      await api.ensureAuth();
      const results = await Promise.allSettled([
        api.getAlertsSummary({ days: 7 }),
        api.getIPSStats({ days: 7 }),
        api.getAlerts({ days: 7, limit: 50 }),
      ]);

      if (results[0].status === 'fulfilled' && results[0].value) {
        setAlertStats(results[0].value);
      }
      if (results[1].status === 'fulfilled' && results[1].value) {
        setIpsStats(results[1].value);
      }
      if (results[2].status === 'fulfilled' && results[2].value?.items) {
        setRecentAlerts(results[2].value.items);
      }
    } catch (err) {
      console.warn('Topology page telemetry load note:', err);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTelemetry(true);
    const interval = setInterval(() => loadTelemetry(false), 8000);
    return () => clearInterval(interval);
  }, [loadTelemetry]);

  return (
    <div className="app-shell" style={{ background: '#020612', minHeight: '100vh' }}>
      <Sidebar />
      <PageLayout>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '70vh' }}>
            <Spinner />
          </div>
        ) : (
          <div style={{ padding: '0 4px' }}>
            {/* Dedicated Fullscreen Neural Threat Mesh Graphic */}
            <NeuralThreatMeshGraphic
              alertStats={alertStats || {}}
              ipsStats={ipsStats || {}}
              recentAlerts={recentAlerts}
              fullScreen={true}
            />
          </div>
        )}
      </PageLayout>
    </div>
  );
}
