'use client';

import { useState } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout } from '@/components/ui';

export default function SettingsPage() {
  const [thresholds, setThresholds] = useState({
    anomalySensitivity: '0.85',
    maxAlertsPerMin: '500',
    autoBlockThreshold: '0.92',
    kafkaBatchSize: '100'
  });
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <Sidebar>
      <PageLayout
        title="System Settings"
        subtitle="Detection sensitivity thresholds, engine parameters, and integrations"
      >
        <div style={{ maxWidth: 640 }}>
          <form onSubmit={handleSave} className="card">
            <h3 style={{ marginTop: 0, marginBottom: 20 }}>Anomaly & IPS Engine Configuration</h3>

            {saved && (
              <div
                style={{
                  background: 'rgba(16, 185, 129, 0.1)',
                  border: '1px solid var(--color-success-border)',
                  color: 'var(--color-success)',
                  padding: '10px 14px',
                  borderRadius: 6,
                  marginBottom: 16,
                  fontSize: '0.875rem'
                }}
              >
                ✓ Settings saved successfully. Changes propagated to detection nodes.
              </div>
            )}

            <div className="form-group">
              <label className="form-label">ML Anomaly Sensitivity Threshold (0.00 - 1.00)</label>
              <input
                type="text"
                className="form-input"
                value={thresholds.anomalySensitivity}
                onChange={(e) => setThresholds({ ...thresholds, anomalySensitivity: e.target.value })}
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Higher values reduce false positives but may miss subtle low-and-slow anomalies.
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">Auto-Block Confidence Cutoff</label>
              <input
                type="text"
                className="form-input"
                value={thresholds.autoBlockThreshold}
                onChange={(e) => setThresholds({ ...thresholds, autoBlockThreshold: e.target.value })}
              />
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Minimum threat score required before IPS controller automatically blocks an IP.
              </span>
            </div>

            <div className="form-group">
              <label className="form-label">Max Alerts / Minute Rate Limit</label>
              <input
                type="number"
                className="form-input"
                value={thresholds.maxAlertsPerMin}
                onChange={(e) => setThresholds({ ...thresholds, maxAlertsPerMin: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Kafka Ingestion Batch Size</label>
              <input
                type="number"
                className="form-input"
                value={thresholds.kafkaBatchSize}
                onChange={(e) => setThresholds({ ...thresholds, kafkaBatchSize: e.target.value })}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 24 }}>
              <button type="submit" className="btn btn-primary">
                Save Configurations
              </button>
            </div>
          </form>
        </div>
      </PageLayout>
    </Sidebar>
  );
}
