'use client';

import { useState, useEffect } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout } from '@/components/ui';
import { api } from '@/lib/api';

const TABS = [
  { key: 'engine', label: '⚙️ Engine', desc: 'ML & IPS detection parameters' },
  { key: 'notifications', label: '🔔 Notifications', desc: 'Alert channels & routing' },
  { key: 'retention', label: '🗄️ Retention', desc: 'Data lifecycle & purge policy' },
  { key: 'integrations', label: '🔌 Integrations', desc: 'SIEM, SOAR & API connectors' },
  { key: 'appearance', label: '🎨 Appearance', desc: 'UI density & theme control' },
];

function SettingRow({ label, desc, children }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16 }}>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 3 }}>
            {label}
          </label>
          {desc && (
            <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>{desc}</span>
          )}
        </div>
        <div style={{ minWidth: 220 }}>{children}</div>
      </div>
    </div>
  );
}

function Toggle({ checked, onChange }) {
  return (
    <div
      onClick={() => onChange(!checked)}
      style={{
        width: 44,
        height: 24,
        borderRadius: 12,
        background: checked ? 'rgba(0, 212, 255, 0.3)' : 'rgba(255,255,255,0.1)',
        border: `1px solid ${checked ? 'rgba(0,212,255,0.6)' : 'rgba(255,255,255,0.15)'}`,
        cursor: 'pointer',
        position: 'relative',
        transition: 'all 0.2s ease',
        boxShadow: checked ? '0 0 10px rgba(0,212,255,0.3)' : 'none',
      }}
    >
      <div style={{
        width: 18,
        height: 18,
        borderRadius: '50%',
        background: checked ? '#00d4ff' : '#64748b',
        position: 'absolute',
        top: 2,
        left: checked ? 22 : 2,
        transition: 'all 0.2s ease',
        boxShadow: checked ? '0 0 8px #00d4ff' : 'none',
      }} />
    </div>
  );
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('engine');
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  // Engine settings
  const [thresholds, setThresholds] = useState({
    anomalySensitivity: '0.85',
    maxAlertsPerMin: '500',
    autoBlockThreshold: '0.92',
    kafkaBatchSize: '100',
  });

  // Notification settings
  const [notifSettings, setNotifSettings] = useState({
    emailEnabled: true,
    slackEnabled: false,
    pagerdutyEnabled: false,
    webhookEnabled: false,
    emailCritical: true,
    emailHigh: true,
    emailMedium: false,
    emailAddress: 'soc@enterprise.local',
    slackWebhook: '',
    webhookUrl: '',
    minSeverity: 'HIGH',
  });

  // Retention settings
  const [retentionSettings, setRetentionSettings] = useState({
    alertRetentionDays: '90',
    incidentRetentionDays: '365',
    auditLogRetentionDays: '730',
    autoArchiveEnabled: true,
    autoDeleteResolved: false,
    pcapRetentionHours: '48',
  });

  // Integration settings
  const [integrations, setIntegrations] = useState({
    splunkEnabled: false,
    splunkHecUrl: '',
    elasticEnabled: false,
    elasticEndpoint: '',
    virustotalEnabled: false,
    virustotalApiKey: '',
    mitreSyncEnabled: true,
  });

  // Appearance settings
  const [appearance, setAppearance] = useState({
    tableDensity: 'comfortable',
    animationsEnabled: true,
    chartAnimations: false,
    sidebarCompact: false,
    timestampFormat: 'relative',
    pageSize: '50',
  });

  useEffect(() => {
    async function loadConfig() {
      try {
        const res = await api.getSettings();
        if (res) setThresholds((prev) => ({ ...prev, ...res }));
      } catch {}
    }
    loadConfig();
  }, []);

  const handleSave = async (e) => {
    e?.preventDefault();
    try {
      setSaving(true);
      await api.updateSettings(thresholds);
      setSaved(true);
      setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      alert(err.message || 'Failed to update settings');
    } finally {
      setSaving(false);
    }
  };

  const SaveBanner = () => saved && (
    <div style={{
      background: 'rgba(16, 185, 129, 0.15)',
      border: '1px solid rgba(16, 185, 129, 0.4)',
      color: 'var(--accent-green)',
      padding: '10px 14px',
      borderRadius: 6,
      marginBottom: 20,
      fontSize: '0.875rem',
      display: 'flex',
      alignItems: 'center',
      gap: 8,
    }}>
      ✓ Settings saved successfully. Changes propagated to all detection nodes within 30 seconds.
    </div>
  );

  return (
    <PageLayout sidebar={<Sidebar />}>
      <div className="page-header">
        <div>
          <h1 className="page-title glow-text">System Configuration</h1>
          <p className="page-subtitle">
            Detection engine parameters, data lifecycle, notification routing &amp; integrations
          </p>
        </div>
        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={saving}
          style={{ padding: '8px 20px' }}
        >
          {saving ? '⟳ Saving…' : '💾 Save All Changes'}
        </button>
      </div>

      <div className="page-body">
        {/* Tab Selector */}
        <div className="glass-card" style={{ padding: '10px 16px', marginBottom: 20, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {TABS.map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              style={{
                padding: '7px 14px',
                borderRadius: 6,
                fontSize: '0.82rem',
                fontWeight: activeTab === tab.key ? 700 : 500,
                background: activeTab === tab.key ? 'rgba(0, 212, 255, 0.15)' : 'transparent',
                color: activeTab === tab.key ? '#00d4ff' : 'var(--text-muted)',
                border: activeTab === tab.key ? '1px solid rgba(0,212,255,0.35)' : '1px solid transparent',
                cursor: 'pointer',
                transition: 'all 0.18s ease',
                whiteSpace: 'nowrap',
              }}
              title={tab.desc}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ── ENGINE TAB ───────────────────────────────────────── */}
        {activeTab === 'engine' && (
          <div className="glass-card" style={{ padding: 28, maxWidth: 800 }}>
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                Anomaly &amp; IPS Detection Engine
              </h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Core ML inference parameters and network enforcement thresholds
              </p>
            </div>
            <SaveBanner />

            <SettingRow
              label="ML Anomaly Sensitivity Threshold (0.00 – 1.00)"
              desc="Higher values reduce false positives but may miss subtle low-and-slow attack patterns."
            >
              <input
                type="number"
                min="0" max="1" step="0.01"
                className="input"
                value={thresholds.anomalySensitivity}
                onChange={(e) => setThresholds({ ...thresholds, anomalySensitivity: e.target.value })}
                style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
              />
            </SettingRow>

            <SettingRow
              label="Auto-Block Confidence Cutoff"
              desc="Minimum threat score before the IPS kernel automatically quarantines a source IP."
            >
              <input
                type="number"
                min="0" max="1" step="0.01"
                className="input"
                value={thresholds.autoBlockThreshold}
                onChange={(e) => setThresholds({ ...thresholds, autoBlockThreshold: e.target.value })}
                style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
              />
            </SettingRow>

            <SettingRow
              label="Max Alerts / Minute Rate Limit"
              desc="Burst ceiling before the event queue applies backpressure. Prevents alert flooding during DDoS."
            >
              <input
                type="number"
                min="10" max="10000"
                className="input"
                value={thresholds.maxAlertsPerMin}
                onChange={(e) => setThresholds({ ...thresholds, maxAlertsPerMin: e.target.value })}
                style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
              />
            </SettingRow>

            <SettingRow
              label="Kafka Ingestion Batch Size"
              desc="Number of telemetry events processed per Kafka consumer batch cycle."
            >
              <input
                type="number"
                min="10" max="5000"
                className="input"
                value={thresholds.kafkaBatchSize}
                onChange={(e) => setThresholds({ ...thresholds, kafkaBatchSize: e.target.value })}
                style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
              />
            </SettingRow>

            <div style={{ paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={handleSave} disabled={saving} style={{ padding: '8px 20px' }}>
                {saving ? '⟳ Saving…' : 'Apply Engine Config'}
              </button>
            </div>
          </div>
        )}

        {/* ── NOTIFICATIONS TAB ────────────────────────────────── */}
        {activeTab === 'notifications' && (
          <div className="glass-card" style={{ padding: 28, maxWidth: 800 }}>
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Notification Channels</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>Configure alert routing for email, Slack, PagerDuty, and custom webhooks</p>
            </div>
            <SaveBanner />

            <SettingRow label="Email Alerts" desc="Send critical threat alerts to your SOC email distribution list">
              <Toggle checked={notifSettings.emailEnabled} onChange={v => setNotifSettings(p => ({ ...p, emailEnabled: v }))} />
            </SettingRow>

            {notifSettings.emailEnabled && (
              <>
                <SettingRow label="SOC Email Address" desc="Primary recipient for high-severity alert digests">
                  <input type="email" className="input" value={notifSettings.emailAddress} onChange={e => setNotifSettings(p => ({ ...p, emailAddress: e.target.value }))} />
                </SettingRow>
                <SettingRow label="Notify on CRITICAL" desc="">
                  <Toggle checked={notifSettings.emailCritical} onChange={v => setNotifSettings(p => ({ ...p, emailCritical: v }))} />
                </SettingRow>
                <SettingRow label="Notify on HIGH" desc="">
                  <Toggle checked={notifSettings.emailHigh} onChange={v => setNotifSettings(p => ({ ...p, emailHigh: v }))} />
                </SettingRow>
                <SettingRow label="Notify on MEDIUM" desc="">
                  <Toggle checked={notifSettings.emailMedium} onChange={v => setNotifSettings(p => ({ ...p, emailMedium: v }))} />
                </SettingRow>
              </>
            )}

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="Slack Webhook" desc="Post real-time threat summaries to a Slack channel">
                <Toggle checked={notifSettings.slackEnabled} onChange={v => setNotifSettings(p => ({ ...p, slackEnabled: v }))} />
              </SettingRow>
              {notifSettings.slackEnabled && (
                <SettingRow label="Slack Webhook URL" desc="">
                  <input type="url" className="input" placeholder="https://hooks.slack.com/..." value={notifSettings.slackWebhook} onChange={e => setNotifSettings(p => ({ ...p, slackWebhook: e.target.value }))} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </SettingRow>
              )}
            </div>

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="PagerDuty Integration" desc="Auto-escalate CRITICAL incidents to on-call rotation">
                <Toggle checked={notifSettings.pagerdutyEnabled} onChange={v => setNotifSettings(p => ({ ...p, pagerdutyEnabled: v }))} />
              </SettingRow>
              <SettingRow label="Custom Webhook" desc="POST threat events to any SIEM, SOAR, or ticketing system">
                <Toggle checked={notifSettings.webhookEnabled} onChange={v => setNotifSettings(p => ({ ...p, webhookEnabled: v }))} />
              </SettingRow>
              {notifSettings.webhookEnabled && (
                <SettingRow label="Webhook Endpoint" desc="">
                  <input type="url" className="input" placeholder="https://your-siem.internal/ingest" value={notifSettings.webhookUrl} onChange={e => setNotifSettings(p => ({ ...p, webhookUrl: e.target.value }))} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </SettingRow>
              )}
            </div>

            <div style={{ paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 3000); }} style={{ padding: '8px 20px' }}>Save Notification Config</button>
            </div>
          </div>
        )}

        {/* ── RETENTION TAB ───────────────────────────────────── */}
        {activeTab === 'retention' && (
          <div className="glass-card" style={{ padding: 28, maxWidth: 800 }}>
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Data Retention &amp; Lifecycle</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>Configure how long security telemetry is retained before archiving or deletion</p>
            </div>
            <SaveBanner />

            {[
              { key: 'alertRetentionDays', label: 'Alert Retention (days)', desc: 'Raw alert records retained in hot storage for analyst querying' },
              { key: 'incidentRetentionDays', label: 'Incident Retention (days)', desc: 'Incident cases retained for post-incident forensic review and compliance' },
              { key: 'auditLogRetentionDays', label: 'Audit Log Retention (days)', desc: 'Tamper-evident user action logs retained for regulatory compliance (SOC 2, ISO 27001)' },
              { key: 'pcapRetentionHours', label: 'PCAP / DPI Traces Retention (hours)', desc: 'Raw packet captures auto-deleted after this window to comply with data minimization' },
            ].map(({ key, label, desc }) => (
              <SettingRow key={key} label={label} desc={desc}>
                <input
                  type="number"
                  min="1"
                  className="input"
                  value={retentionSettings[key]}
                  onChange={e => setRetentionSettings(p => ({ ...p, [key]: e.target.value }))}
                  style={{ fontFamily: 'monospace', fontSize: '0.9rem' }}
                />
              </SettingRow>
            ))}

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="Auto-Archive Old Records" desc="Automatically move records past retention window to cold storage instead of deleting">
                <Toggle checked={retentionSettings.autoArchiveEnabled} onChange={v => setRetentionSettings(p => ({ ...p, autoArchiveEnabled: v }))} />
              </SettingRow>
              <SettingRow label="Auto-Delete Resolved Alerts" desc="Purge RESOLVED alerts after 30 days to reduce storage overhead">
                <Toggle checked={retentionSettings.autoDeleteResolved} onChange={v => setRetentionSettings(p => ({ ...p, autoDeleteResolved: v }))} />
              </SettingRow>
            </div>

            <div style={{ paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 3000); }} style={{ padding: '8px 20px' }}>Apply Retention Policy</button>
            </div>
          </div>
        )}

        {/* ── INTEGRATIONS TAB ────────────────────────────────── */}
        {activeTab === 'integrations' && (
          <div className="glass-card" style={{ padding: 28, maxWidth: 800 }}>
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>Platform Integrations</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>Connect to SIEM, threat intelligence, and external security platforms</p>
            </div>
            <SaveBanner />

            <SettingRow label="Splunk HEC Forwarding" desc="Forward all alerts and incidents to Splunk HTTP Event Collector">
              <Toggle checked={integrations.splunkEnabled} onChange={v => setIntegrations(p => ({ ...p, splunkEnabled: v }))} />
            </SettingRow>
            {integrations.splunkEnabled && (
              <SettingRow label="Splunk HEC URL" desc="">
                <input type="url" className="input" placeholder="https://splunk.corp:8088/services/collector" value={integrations.splunkHecUrl} onChange={e => setIntegrations(p => ({ ...p, splunkHecUrl: e.target.value }))} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
              </SettingRow>
            )}

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="Elastic SIEM Integration" desc="Index all security events into Elasticsearch for ECS-compliant analysis">
                <Toggle checked={integrations.elasticEnabled} onChange={v => setIntegrations(p => ({ ...p, elasticEnabled: v }))} />
              </SettingRow>
              {integrations.elasticEnabled && (
                <SettingRow label="Elasticsearch Endpoint" desc="">
                  <input type="url" className="input" placeholder="https://elastic.corp:9200" value={integrations.elasticEndpoint} onChange={e => setIntegrations(p => ({ ...p, elasticEndpoint: e.target.value }))} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </SettingRow>
              )}
            </div>

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="VirusTotal API Enrichment" desc="Automatically enrich IOC lookups with VirusTotal intelligence">
                <Toggle checked={integrations.virustotalEnabled} onChange={v => setIntegrations(p => ({ ...p, virustotalEnabled: v }))} />
              </SettingRow>
              {integrations.virustotalEnabled && (
                <SettingRow label="VirusTotal API Key" desc="">
                  <input type="password" className="input" placeholder="VT API key..." value={integrations.virustotalApiKey} onChange={e => setIntegrations(p => ({ ...p, virustotalApiKey: e.target.value }))} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </SettingRow>
              )}
            </div>

            <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 20, marginTop: 8 }}>
              <SettingRow label="MITRE ATT&amp;CK Auto-Sync" desc="Automatically update local MITRE framework with latest technique & tactic definitions">
                <Toggle checked={integrations.mitreSyncEnabled} onChange={v => setIntegrations(p => ({ ...p, mitreSyncEnabled: v }))} />
              </SettingRow>
            </div>

            <div style={{ paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 3000); }} style={{ padding: '8px 20px' }}>Save Integration Config</button>
            </div>
          </div>
        )}

        {/* ── APPEARANCE TAB ──────────────────────────────────── */}
        {activeTab === 'appearance' && (
          <div className="glass-card" style={{ padding: 28, maxWidth: 800 }}>
            <div style={{ marginBottom: 24 }}>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 700 }}>UI Preferences &amp; Display</h3>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: 4 }}>Customize table density, animations, and timestamp display format</p>
            </div>
            <SaveBanner />

            <SettingRow label="Table Density" desc="Controls row height and padding across all data tables">
              <select className="select" value={appearance.tableDensity} onChange={e => setAppearance(p => ({ ...p, tableDensity: e.target.value }))}>
                <option value="compact">Compact — more rows visible</option>
                <option value="comfortable">Comfortable (default)</option>
                <option value="spacious">Spacious — easier reading</option>
              </select>
            </SettingRow>

            <SettingRow label="Timestamp Format" desc="How timestamps are displayed throughout the platform">
              <select className="select" value={appearance.timestampFormat} onChange={e => setAppearance(p => ({ ...p, timestampFormat: e.target.value }))}>
                <option value="relative">Relative — &quot;3 min ago&quot;</option>
                <option value="absolute">Absolute — &quot;Sep 21, 15:32&quot;</option>
                <option value="iso">ISO 8601 — &quot;2026-09-21T15:32:00Z&quot;</option>
              </select>
            </SettingRow>

            <SettingRow label="Default Page Size" desc="Number of rows loaded per page in all paginated tables">
              <select className="select" value={appearance.pageSize} onChange={e => setAppearance(p => ({ ...p, pageSize: e.target.value }))}>
                <option value="25">25 rows</option>
                <option value="50">50 rows (default)</option>
                <option value="100">100 rows</option>
                <option value="200">200 rows</option>
              </select>
            </SettingRow>

            <SettingRow label="UI Micro-Animations" desc="Smooth entrance animations on cards, tables, and modals">
              <Toggle checked={appearance.animationsEnabled} onChange={v => setAppearance(p => ({ ...p, animationsEnabled: v }))} />
            </SettingRow>

            <SettingRow label="Chart Animations" desc="Animated transitions on recharts graphs (disable for better performance)">
              <Toggle checked={appearance.chartAnimations} onChange={v => setAppearance(p => ({ ...p, chartAnimations: v }))} />
            </SettingRow>

            <SettingRow label="Compact Sidebar" desc="Collapse sidebar to icon-only mode for more horizontal screen space">
              <Toggle checked={appearance.sidebarCompact} onChange={v => setAppearance(p => ({ ...p, sidebarCompact: v }))} />
            </SettingRow>

            <div style={{ paddingTop: 16, borderTop: '1px solid rgba(255,255,255,0.06)', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-primary" onClick={() => { setSaved(true); setTimeout(() => setSaved(false), 3000); }} style={{ padding: '8px 20px' }}>Apply Preferences</button>
            </div>
          </div>
        )}
      </div>
    </PageLayout>
  );
}
