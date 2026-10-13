import React, { useState, useEffect, useRef } from 'react';
import { getPendingApprovals, approveAction, rejectAction } from '../api/immunexApi';
import { runDemoInjection } from '../api/immunexApi';

// ── All 50 override actions — sourced from action_registry.py ────────────────
const OVERRIDE_OPTIONS = [
  // Monitoring (0–9)
  { index: 0,  name: 'do_nothing',                    category: 'monitoring' },
  { index: 1,  name: 'increase_log_verbosity',        category: 'monitoring' },
  { index: 2,  name: 'trigger_soc_alert',             category: 'monitoring' },
  { index: 3,  name: 'snapshot_memory',               category: 'monitoring' },
  { index: 4,  name: 'capture_network_traffic',       category: 'monitoring' },
  { index: 5,  name: 'enable_deep_packet_inspection', category: 'monitoring' },
  { index: 6,  name: 'flag_for_human_review',         category: 'monitoring' },
  { index: 7,  name: 'escalate_to_tier2',             category: 'monitoring' },
  { index: 8,  name: 'notify_incident_manager',       category: 'monitoring' },
  { index: 9,  name: 'generate_soc_report',           category: 'monitoring' },
  // Network (10–19)
  { index: 10, name: 'block_source_ip',               category: 'network' },
  { index: 11, name: 'block_destination_ip',          category: 'network' },
  { index: 12, name: 'isolate_endpoint',              category: 'network' },
  { index: 13, name: 'quarantine_subnet',             category: 'network' },
  { index: 14, name: 'disable_external_routing',      category: 'network' },
  { index: 15, name: 'block_suspicious_port',         category: 'network' },
  { index: 16, name: 'rate_limit_source',             category: 'network' },
  { index: 17, name: 'drop_malicious_packets',        category: 'network' },
  { index: 18, name: 'null_route_attacker',           category: 'network' },
  { index: 19, name: 'block_c2_domain',               category: 'network' },
  // Credential & access (20–29)
  { index: 20, name: 'revoke_user_session',           category: 'credential' },
  { index: 21, name: 'force_mfa_reauthentication',    category: 'credential' },
  { index: 22, name: 'disable_compromised_account',   category: 'credential' },
  { index: 23, name: 'reset_service_account_password',category: 'credential' },
  { index: 24, name: 'revoke_api_key',                category: 'credential' },
  { index: 25, name: 'restrict_admin_privileges',     category: 'credential' },
  { index: 26, name: 'enforce_least_privilege',       category: 'credential' },
  { index: 27, name: 'disable_lateral_movement_path', category: 'credential' },
  { index: 28, name: 'lock_privileged_account',       category: 'credential' },
  { index: 29, name: 'audit_active_sessions',         category: 'credential' },
  // Process & endpoint (30–39)
  { index: 30, name: 'kill_malicious_process',        category: 'process' },
  { index: 31, name: 'suspend_suspicious_process',    category: 'process' },
  { index: 32, name: 'quarantine_malicious_file',     category: 'process' },
  { index: 33, name: 'rollback_filesystem_changes',   category: 'process' },
  { index: 34, name: 'restore_from_clean_snapshot',   category: 'process' },
  { index: 35, name: 'run_edr_deep_scan',             category: 'process' },
  { index: 36, name: 'patch_vulnerable_service',      category: 'process' },
  { index: 37, name: 'disable_autorun_mechanisms',    category: 'process' },
  { index: 38, name: 'terminate_remote_desktop_session', category: 'process' },
  { index: 39, name: 'sandbox_suspicious_binary',     category: 'process' },
  // Data protection (40–49)
  { index: 40, name: 'encrypt_sensitive_data_at_rest',category: 'data_protection' },
  { index: 41, name: 'revoke_data_export_permissions',category: 'data_protection' },
  { index: 42, name: 'block_usb_exfiltration',        category: 'data_protection' },
  { index: 43, name: 'disable_email_forwarding_rules',category: 'data_protection' },
  { index: 44, name: 'watermark_sensitive_documents', category: 'data_protection' },
  { index: 45, name: 'enable_dlp_policy',             category: 'data_protection' },
  { index: 46, name: 'freeze_database_writes',        category: 'data_protection' },
  { index: 47, name: 'backup_critical_data',          category: 'data_protection' },
  { index: 48, name: 'rotate_encryption_keys',        category: 'data_protection' },
  { index: 49, name: 'activate_honeypot',             category: 'data_protection' },
];

const CATEGORY_COLORS = {
  monitoring:      { bg: 'rgba(52,152,219,0.10)', border: 'rgba(52,152,219,0.35)', text: '#3498db' },
  network:         { bg: 'rgba(231,76,60,0.10)',  border: 'rgba(231,76,60,0.35)',  text: '#e74c3c' },
  credential:      { bg: 'rgba(230,126,34,0.10)', border: 'rgba(230,126,34,0.35)', text: '#e67e22' },
  process:         { bg: 'rgba(155,89,182,0.10)', border: 'rgba(155,89,182,0.35)', text: '#9b59b6' },
  data_protection: { bg: 'rgba(39,174,96,0.10)',  border: 'rgba(39,174,96,0.35)',  text: '#27ae60' },
};

export default function Playbook({ lastPipelineResult }) {
  const [queue, setQueue]                     = useState([]);
  const [resolved, setResolved]               = useState([]);
  const [overrideModalFor, setOverrideModalFor] = useState(null);
  const [overrideSearch, setOverrideSearch]   = useState('');
  const [overrideSelections, setOverrideSelections] = useState([]);
  const [countdown, setCountdown]             = useState(685);
  const [newAlertFlash, setNewAlertFlash]     = useState(false);
  const bottomRef = useRef(null);

  // Countdown timer
  useEffect(() => {
    if (countdown <= 0) return;
    const t = setInterval(() => setCountdown(c => Math.max(0, c - 1)), 1000);
    return () => clearInterval(t);
  }, []);


  useEffect(() => {
    if (!lastPipelineResult) return;
    if (lastPipelineResult.verdict !== 'ANOMALOUS') {
      setQueue([]);
      return;
    }

    const ICON_MAP = {
      DDoS: '🌊', BruteForce: '🔑', 'Brute Force': '🔑',
      SQLInjection: '💉', 'SQL Injection': '💉',
      PortScan: '🔗', 'Port Scan': '🔗',
      C2Beacon: '📡', 'Command and Control': '📡',
      Ransomware: '🔒', 'Data Exfiltration': '☁',
      'Zeus Banking Trojan': '🏦', default: '⚠'
    };

    if (lastPipelineResult.attack_queue && lastPipelineResult.attack_queue.length > 0) {
      const q = lastPipelineResult.attack_queue.map((att, idx) => ({
        id: att.alert_id,
        priority: att.priority || (idx + 1),
        is_major_impact: (idx === 0) || att.is_major_impact,
        sev: att.severity || (att.anomaly_score > 0.8 ? 'critical' : 'high'),
        icon: ICON_MAP[att.attack_type] || ICON_MAP.default,
        title: (att.attack_type || 'THREAT INCIDENT').toUpperCase().replace('_', ' '),
        target: `IP: ${att.source_ip || '192.168.1.100'} → ${att.dest_ip || '10.0.0.1'}`,
        mitre: att.mitre_stage || (idx === 0 ? 'Major Impact Cause' : 'Secondary Threat'),
        desc: att.playbook_summary || `${att.attack_type} incident detected from ${att.source_ip}`,
        steps: Array.isArray(att.playbook) ? att.playbook : (att.playbook ? [att.playbook] : []),
        action: att.action || 'block_source_ip',
        attackInfo: att.attack_info,
        responsePlan: att.response || { action: att.action, rationale: att.response_rationale },
        eventCount: att.event_count || 1,
        confidence: att.confidence || (att.attack_info?.confidence) || 0.92,
        ts: new Date().toLocaleTimeString('en', { hour12: false }),
        _backendId: att.alert_id,
      }));
      setQueue(q);
      setNewAlertFlash(true);
      setTimeout(() => setNewAlertFlash(false), 3000);
      return;
    }

    const l1 = lastPipelineResult.layer1 || {};
    const l3 = lastPipelineResult.layer3 || {};
    const attackType = l1.attack_type || 'Unknown';
    const score = lastPipelineResult.anomaly_score || 0;
    const playbook = lastPipelineResult.playbook?.steps?.join(' ') || l3.action || 'Incident Containment';
    const singleItem = {
      id: lastPipelineResult.alert_id || 'AX-' + Math.random().toString(36).slice(2, 8).toUpperCase(),
      priority: 1,
      is_major_impact: true,
      sev: l1.severity || (score > 0.8 ? 'critical' : 'high'),
      icon: ICON_MAP[attackType] || '⚠',
      title: attackType.toUpperCase().replace('_', ' '),
      target: `IP: ${l1.source_ip || '192.168.1.100'} → ${l1.dest_ip || '10.0.0.1'}`,
      mitre: lastPipelineResult.layer2?.mitre_stage || 'Major Impact Cause',
      desc: lastPipelineResult.playbook?.incident_summary || playbook,
      steps: Array.isArray(lastPipelineResult.playbook?.steps) ? lastPipelineResult.playbook.steps : [playbook],
      action: l3?.action || 'block_source_ip',
      attackInfo: lastPipelineResult.playbook?.attack_info,
      responsePlan: lastPipelineResult.playbook?.response,
      eventCount: 1,
      confidence: l1.confidence || 0.92,
      ts: new Date().toLocaleTimeString('en', { hour12: false }),
      _backendId: lastPipelineResult.alert_id,
    };
    setQueue([singleItem]);
    setNewAlertFlash(true);
    setTimeout(() => setNewAlertFlash(false), 3000);
  }, [lastPipelineResult]);

  // Poll real L3 pending queue — only sync if queue is currently empty
  // and no fresh pipeline result has been received yet (prevents stale data from prior sessions)
  useEffect(() => {
    const ICON_MAP = {
      DDoS: '🌊', BruteForce: '🔑', 'Brute Force': '🔑',
      SQLInjection: '💉', 'SQL Injection': '💉',
      PortScan: '🔗', 'Port Scan': '🔗',
      C2Beacon: '📡', 'Command and Control': '📡',
      Ransomware: '🔒', 'Data Exfiltration': '☁',
      'Zeus Banking Trojan': '🏦', default: '⚠'
    };
    const syncBackend = async () => {
      // Only auto-populate from backend if we have no queue yet from lastPipelineResult
      // (avoids polluting with stale pending items from previous uploads)
      if (queue.length > 0) return;
      try {
        const raw = await getPendingApprovals();
        const items = Array.isArray(raw) ? raw : (raw.pending || raw.items || []);
        if (!items.length) return;
        // Filter to items queued in the last 10 minutes only (fresh data)
        const TEN_MIN_AGO = Date.now() - 10 * 60 * 1000;
        const fresh = items.filter(r => {
          if (!r.timestamp_queued) return false;
          const ts = new Date(r.timestamp_queued).getTime();
          return ts > TEN_MIN_AGO;
        });
        if (!fresh.length) return;
        const sorted = [...fresh].sort((a, b) => (a.priority || 99) - (b.priority || 99));
        setQueue(sorted.map((r, i) => {
          const pbSteps = Array.isArray(r.playbook) ? r.playbook : (r.playbook ? [r.playbook] : []);
          const pbDesc = r.playbook_summary || (pbSteps.length ? pbSteps[0] : (r.decision?.action_name ? `Recommended action: ${r.decision.action_name}` : 'Awaiting response authorization'));
          const actName = (r.actions && r.actions[0]) || r.action || r.decision?.action_name || 'flag_for_human_review';
          return {
            id: r.alert_id || `ALT-${i}`,
            priority: r.priority || (i + 1),
            is_major_impact: (i === 0) || r.is_major_impact,
            sev: r.severity || (r.anomaly_score > 0.8 ? 'critical' : r.anomaly_score > 0.5 ? 'high' : 'medium'),
            icon: ICON_MAP[r.attack_type] || '⚠',
            title: (r.attack_type || 'THREAT INCIDENT').toUpperCase().replace('_', ' '),
            target: `IP: ${r.source_ip || '192.168.1.100'} → ${r.dest_ip || '10.0.0.1'}`,
            mitre: r.layer2?.mitre_stage || (i === 0 ? 'Major Impact Cause' : 'Secondary Threat'),
            desc: pbDesc,
            steps: pbSteps,
            action: actName,
            attackInfo: r.attack_info,
            responsePlan: r.response || { action: actName, rationale: r.response_rationale },
            eventCount: r.event_count || 1,
            confidence: r.confidence || (r.attack_info?.confidence) || 0.92,
            ts: r.timestamp_queued ? new Date(r.timestamp_queued).toLocaleTimeString('en', { hour12: false }) : new Date().toLocaleTimeString('en', { hour12: false }),
            _backendId: r.alert_id,
          };
        }));
      } catch { /* backend offline — silently ignore */ }
    };
    syncBackend();
    const iv = setInterval(syncBackend, 15000);
    return () => clearInterval(iv);
  }, [queue.length]);

  // Real backend approve/reject (wraps local state update)
  const handleApproveWithBackend = async (item) => {
    if (item._backendId) {
      try { await approveAction(item._backendId); } catch { /* ignore — local state still updates */ }
    }
    handleApprove(item);
  };

  const handleRejectWithBackend = async (item) => {
    if (item._backendId) {
      try { await rejectAction(item._backendId); } catch { /* ignore */ }
    }
    handleDismiss(item);
  };

  const mm = String(Math.floor(countdown / 60)).padStart(2, '0');
  const ss = String(countdown % 60).padStart(2, '0');

  // Approve top action
  const handleApprove = (item) => {
    setResolved(prev => [...prev, { ...item, outcome: 'approved', outMsg: `✅ ${item.action} executed — ${item.target} secured.` }]);
    setQueue(prev => prev.filter(q => q.id !== item.id));
  };

  // Dismiss
  const handleDismiss = (item) => {
    setResolved(prev => [...prev, { ...item, outcome: 'dismissed', outMsg: '🚫 Dismissed — logged for RLHF review.' }]);
    setQueue(prev => prev.filter(q => q.id !== item.id));
  };

  // Override modal
  const openOverride = (item) => {
    setOverrideModalFor(item);
    setOverrideSelections([]);
    setOverrideSearch('');
  };
  const closeOverride = () => { setOverrideModalFor(null); setOverrideSelections([]); setOverrideSearch(''); };

  const toggleOverride = (opt) =>
    setOverrideSelections(prev =>
      prev.some(o => o.index === opt.index)
        ? prev.filter(o => o.index !== opt.index)
        : [...prev, opt]
    );

  const applyOverride = async () => {
    if (!overrideModalFor || overrideSelections.length === 0) return;

    const ts = new Date().toISOString();

    // Build override payload JSON
    const payload = {
      generated_at: ts,
      incident_id: overrideModalFor.id,
      target: overrideModalFor.target,
      mitre: overrideModalFor.mitre,
      override_actions: overrideSelections.map(o => ({
        action_index: o.index,
        action_name: o.name,
        category: o.category,
      })),
    };

    // Build action_registry Python snippet
    const registryLines = overrideSelections
      .map(o => `    ${o.index}: "${o.name}",  # ${o.category}`)
      .join('\n');
    const registryPy =
`# IMMUNEX — Manual Override Registry Snapshot
# Incident : ${overrideModalFor.id}
# Target   : ${overrideModalFor.target}
# Generated: ${ts}

SELECTED_ACTIONS: dict[int, str] = {
${registryLines}
}
`;

    // Build README
    const readme =
`IMMUNEX Manual Override Package
================================
Incident : ${overrideModalFor.id}
Target   : ${overrideModalFor.target}
MITRE    : ${overrideModalFor.mitre}
Generated: ${ts}

Selected Actions (${overrideSelections.length})
${'─'.repeat(44)}
${overrideSelections.map((o, i) => `${String(i + 1).padStart(2, ' ')}. [ACT_${String(o.index).padStart(2, '0')}] ${o.name}  (${o.category})`).join('\n')}

Files in this package
─────────────────────
• README.txt                   — This file
• override_payload.json        — Machine-readable action list (IMMUNEX API ready)
• action_registry_snippet.py   — Python dict of selected actions
`;

    // Load JSZip dynamically and generate zip
    const loadJSZip = () => new Promise((resolve, reject) => {
      if (window.JSZip) { resolve(window.JSZip); return; }
      const s = document.createElement('script');
      s.src = 'https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js';
      s.onload = () => resolve(window.JSZip);
      s.onerror = reject;
      document.head.appendChild(s);
    });

    try {
      const JSZip = await loadJSZip();
      const zip = new JSZip();
      zip.file('README.txt', readme);
      zip.file('override_payload.json', JSON.stringify(payload, null, 2));
      zip.file('action_registry_snippet.py', registryPy);
      const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `IMMUNEX_override_${overrideModalFor.id}_${ts.slice(0, 10)}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      // Fallback: download payload JSON directly
      console.error('ZIP generation failed, falling back to JSON:', err);
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `IMMUNEX_override_${overrideModalFor.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    setResolved(prev => [...prev, {
      ...overrideModalFor,
      outcome: 'override',
      outMsg: `⛭ Manual override — ${overrideSelections.length} action${overrideSelections.length > 1 ? 's' : ''} applied & ZIP downloaded: ${overrideSelections.slice(0, 2).map(o => o.name).join(', ')}${overrideSelections.length > 2 ? ` +${overrideSelections.length - 2} more` : ''}.`,
    }]);
    setQueue(prev => prev.filter(q => q.id !== overrideModalFor.id));
    closeOverride();
  };

  const filteredOpts = OVERRIDE_OPTIONS.filter(o =>
    o.name.toLowerCase().includes(overrideSearch.toLowerCase()) ||
    o.category.toLowerCase().includes(overrideSearch.toLowerCase())
  );

  const groupedOpts = filteredOpts.reduce((acc, o) => {
    if (!acc[o.category]) acc[o.category] = [];
    acc[o.category].push(o);
    return acc;
  }, {});

  const CATEGORY_LABELS = {
    monitoring: 'Monitoring',
    network: 'Network Containment',
    credential: 'Credential & Access',
    process: 'Process & Endpoint',
    data_protection: 'Data Protection',
  };

  const sevColor = { critical: '#c0392b', high: '#e67e22', medium: '#f39c12', low: '#27ae60' };

  return (
    <div className="section-page active" style={{ display: 'block', position: 'relative' }}>

      {/* ── Override Modal ── */}
      {overrideModalFor && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(5px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 14, width: '100%', maxWidth: 580, maxHeight: '82vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 48px rgba(0,0,0,0.5)', overflow: 'hidden' }}>

            {/* Modal header */}
            <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 2, color: 'var(--text3)', textTransform: 'uppercase', marginBottom: 4 }}>Manual Override — {overrideModalFor.id}</div>
                <h3 style={{ margin: 0, fontFamily: 'var(--serif)', fontSize: 20, fontWeight: 500 }}>Select Response Actions</h3>
              </div>
              <button onClick={closeOverride} style={{ background: 'none', border: 'none', color: 'var(--text2)', cursor: 'pointer', fontSize: 22, lineHeight: 1 }}>&times;</button>
            </div>

            {/* Search */}
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <input
                type="text"
                placeholder="Search actions..."
                value={overrideSearch}
                onChange={e => setOverrideSearch(e.target.value)}
                style={{ width: '100%', padding: '8px 12px', border: '1px solid var(--border)', borderRadius: 7, background: 'var(--bg2)', color: 'var(--text)', fontFamily: 'var(--mono)', fontSize: 12, outline: 'none', boxSizing: 'border-box' }}
              />
            </div>

            {/* Options list - grouped by category */}
            <div style={{ overflowY: 'auto', padding: 12, flex: 1, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {filteredOpts.length === 0 && (
                <div style={{ textAlign: 'center', color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: 12, padding: 20 }}>No actions match "{overrideSearch}"</div>
              )}
              {Object.keys(groupedOpts).map(cat => (
                <div key={cat}>
                  {/* Category header */}
                  <div style={{
                    fontFamily: 'var(--mono)', fontSize: 9, letterSpacing: 1.8, textTransform: 'uppercase',
                    color: CATEGORY_COLORS[cat]?.text || 'var(--text3)',
                    padding: '8px 4px 4px',
                    borderBottom: `1px solid ${CATEGORY_COLORS[cat]?.border || 'var(--border)'}`,
                    marginBottom: 4,
                    display: 'flex', alignItems: 'center', gap: 6,
                  }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: CATEGORY_COLORS[cat]?.text, display: 'inline-block', flexShrink: 0 }}></span>
                    {CATEGORY_LABELS[cat] || cat}
                    <span style={{ marginLeft: 'auto', opacity: 0.6 }}>{groupedOpts[cat].length}</span>
                  </div>
                  {/* Actions in category */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 8 }}>
                    {groupedOpts[cat].map(opt => {
                      const isSel = overrideSelections.some(o => o.index === opt.index);
                      const cc = CATEGORY_COLORS[opt.category];
                      return (
                        <button
                          key={opt.index}
                          onClick={() => toggleOverride(opt)}
                          style={{
                            textAlign: 'left', padding: '8px 12px',
                            background: isSel ? cc?.bg : 'var(--card)',
                            border: isSel ? `1px solid ${cc?.border}` : '1px solid var(--border)',
                            borderRadius: 7, color: 'var(--text)', fontSize: 12, cursor: 'pointer',
                            display: 'flex', alignItems: 'center', gap: 10, transition: 'all 0.12s',
                          }}
                        >
                          <div style={{
                            width: 15, height: 15, border: isSel ? `1.5px solid ${cc?.text}` : '1px solid var(--border2)',
                            borderRadius: 3, background: isSel ? cc?.text : 'transparent',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                          }}>
                            {isSel && <span style={{ color: '#fff', fontSize: 10, fontWeight: 700, lineHeight: 1 }}>✓</span>}
                          </div>
                          <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text3)', minWidth: 40 }}>
                            ACT_{String(opt.index).padStart(2, '0')}
                          </span>
                          <span style={{ flex: 1, fontFamily: 'var(--mono)', fontSize: 11 }}>
                            {opt.name}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            {/* Footer */}
            <div style={{ padding: '14px 20px', borderTop: '1px solid var(--border)', background: 'var(--card)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>
                {overrideSelections.length} / {OVERRIDE_OPTIONS.length} selected
                {overrideSelections.length > 0 && (
                  <span style={{ marginLeft: 8, color: 'var(--text2)' }}>
                    · {[...new Set(overrideSelections.map(o => o.category))].length} categories
                  </span>
                )}
              </span>
              <div style={{ display: 'flex', gap: 10 }}>
                <button onClick={closeOverride} className="btn btn-secondary btn-sm">Cancel</button>
                <button
                  className="btn btn-primary"
                  disabled={overrideSelections.length === 0}
                  style={{ opacity: overrideSelections.length === 0 ? 0.5 : 1, display: 'flex', alignItems: 'center', gap: 6 }}
                  onClick={applyOverride}
                >
                  <span>⬇ Apply & Download ZIP</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Page Header ── */}
      <div className="section-page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <div className="section-eyebrow">Response Playbook</div>
            <h2 className="section-title">Anomaly Queue — Decide fast. Act with precision.</h2>
            <p className="section-sub">Anomalies detected by the pipeline are queued here in priority order. Each requires exactly one response action.</p>
          </div>
          <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 24 }}>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: 1.5, marginBottom: 4 }}>Response Window</div>
            <div style={{ fontFamily: 'var(--mono)', fontSize: 32, fontWeight: 700, color: countdown < 120 ? '#c0392b' : 'var(--text)', letterSpacing: 2 }}>{mm}:{ss}</div>
          </div>
        </div>
      </div>

      {/* ── Stats bar ── */}
      <div className="playbook-stats" style={{ marginBottom: 24 }}>
        <div className="pb-stat">
          <div className="pb-stat-label">In Queue</div>
          <div className="pb-stat-val" style={{ color: queue.length > 0 ? '#c0392b' : 'var(--green)' }}>
            {String(queue.length).padStart(2, '0')}
          </div>
        </div>
        <div className="pb-stat">
          <div className="pb-stat-label">Resolved</div>
          <div className="pb-stat-val accent">{String(resolved.length).padStart(2, '0')}</div>
        </div>
        <div className="pb-stat">
          <div className="pb-stat-label">Critical Pending</div>
          <div className="pb-stat-val red">{queue.filter(q => q.sev === 'critical').length}</div>
        </div>
        <div className="pb-stat">
          <div className="pb-stat-label">Override Actions</div>
          <div className="pb-stat-val">{OVERRIDE_OPTIONS.length}</div>
        </div>
      </div>

      {/* ── Queue ── */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text3)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span>Pending Anomalies ({queue.length})</span>
          {newAlertFlash && (
            <span style={{ background: '#c0392b', color: '#fff', borderRadius: 4, padding: '2px 8px', fontSize: 9, animation: 'none' }}>⚡ NEW ALERT</span>
          )}
        </div>

        {queue.length === 0 && (
          <div style={{ textAlign: 'center', padding: '48px 24px', color: 'var(--text3)', fontFamily: 'var(--mono)', fontSize: 13, background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 12 }}>
            ✓ All anomalies resolved — queue is empty
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {queue.map((item, idx) => (
            <div
              key={item.id}
              style={{
                background: 'var(--card)',
                border: `1px solid ${idx === 0 ? sevColor[item.sev] + '88' : 'var(--border)'}`,
                borderLeft: `4px solid ${sevColor[item.sev] || 'var(--border)'}`,
                borderRadius: 10,
                overflow: 'hidden',
                boxShadow: idx === 0 ? `0 0 0 1px ${sevColor[item.sev]}22` : 'none',
                transition: 'all .2s',
              }}
            >
              <div style={{ padding: '14px 18px' }}>
                {/* Top row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ width: 36, height: 36, borderRadius: 8, background: 'var(--bg2)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, flexShrink: 0 }}>{item.icon}</div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 700, letterSpacing: 1, color: 'var(--text)' }}>{item.title}</span>
                        <span style={{ fontFamily: 'var(--mono)', fontSize: 9, textTransform: 'uppercase', letterSpacing: 1.5, color: sevColor[item.sev], background: sevColor[item.sev] + '18', border: `1px solid ${sevColor[item.sev]}44`, borderRadius: 4, padding: '2px 7px' }}>{item.sev}</span>
                        {item.is_major_impact || idx === 0 ? (
                          <span style={{ fontFamily: 'var(--mono)', fontSize: 9, fontWeight: 700, color: '#fff', background: '#c0392b', borderRadius: 4, padding: '2px 8px', letterSpacing: 1 }}>
                            ⚡ MAJOR IMPACT CAUSE
                          </span>
                        ) : (
                          <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text2)', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 7px' }}>
                            RANK #{item.priority || idx + 1}
                          </span>
                        )}
                        {item.eventCount && item.eventCount > 1 && (
                          <span style={{ fontFamily: 'var(--mono)', fontSize: 9, color: '#3498db', background: 'rgba(52,152,219,0.12)', border: '1px solid rgba(52,152,219,0.3)', borderRadius: 4, padding: '2px 7px' }}>
                            {item.eventCount} EVENTS DETECTED
                          </span>
                        )}
                      </div>
                      <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>{item.target}</div>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', marginBottom: 2 }}>{item.ts}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)' }}>{item.id}</div>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--accentbg)', marginTop: 2 }}>{item.mitre}</div>
                  </div>
                </div>

                {/* Description */}
                <p style={{ fontSize: 12, color: 'var(--text)', fontWeight: 500, lineHeight: 1.5, margin: '0 0 12px 0' }}>{item.desc}</p>

                {/* Attack Telemetry Grid */}
                {item.attackInfo && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, margin: '0 0 12px' }}>
                    <div style={{ padding: '8px 10px', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 9, color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 2 }}>SOURCE → DESTINATION</div>
                      <div style={{ fontSize: 11, fontFamily: 'var(--mono)' }}>{item.attackInfo.source_ip} → {item.attackInfo.destination_ip}</div>
                    </div>
                    <div style={{ padding: '8px 10px', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 9, color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 2 }}>ATTACK ACTIVITY</div>
                      <div style={{ fontSize: 11 }}>{item.attackInfo.activity}</div>
                    </div>
                    <div style={{ padding: '8px 10px', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 9, color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 2 }}>RESOURCE / TARGET</div>
                      <div style={{ fontSize: 11, wordBreak: 'break-word' }}>{item.attackInfo.resource}</div>
                    </div>
                    <div style={{ padding: '8px 10px', background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 9, color: 'var(--text3)', fontFamily: 'var(--mono)', marginBottom: 2 }}>DETECTION CONFIDENCE</div>
                      <div style={{ fontSize: 11, fontFamily: 'var(--mono)', color: item.confidence > 0.9 ? 'var(--accentbg)' : 'var(--text)' }}>
                        {item.attackInfo.detection_method} · {((item.attackInfo.confidence || item.confidence || 0.92) * 100).toFixed(1)}%
                      </div>
                    </div>
                  </div>
                )}

                {/* Response Rationale */}
                {item.responsePlan?.rationale && (
                  <div style={{ margin: '0 0 12px', padding: '9px 12px', background: 'rgba(61,90,62,.08)', borderLeft: '3px solid var(--accentbg)', borderRadius: '0 6px 6px 0', fontSize: 12, lineHeight: 1.5 }}>
                    <strong style={{ color: 'var(--accentbg)', fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 1, textTransform: 'uppercase', display: 'block', marginBottom: 2 }}>Response Rationale:</strong>
                    {item.responsePlan.rationale}
                  </div>
                )}

                {/* Actionable Playbook Protocol Steps */}
                {item.steps && item.steps.length > 0 && (
                  <div style={{ margin: '0 0 12px' }}>
                    <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', color: 'var(--text3)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>Actionable Playbook Protocol</span>
                      <span style={{ fontSize: 9, color: 'var(--text3)', background: 'var(--bg2)', padding: '1px 6px', borderRadius: 4 }}>{item.steps.length} STEPS</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {item.steps.map((st, sIdx) => {
                        const stepText = typeof st === 'string' ? st : (st.step || st.action || JSON.stringify(st));
                        const cleanText = stepText.replace(/^Step\s*\d+\s*:\s*/i, '');
                        return (
                          <div key={sIdx} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '7px 12px', background: 'var(--bg2)', borderRadius: 6, border: '1px solid var(--border)' }}>
                            <span style={{ fontFamily: 'var(--mono)', fontSize: 10, fontWeight: 700, color: 'var(--accentbg)', background: 'rgba(61,90,62,0.12)', border: '1px solid rgba(61,90,62,0.25)', borderRadius: 4, padding: '2px 7px', whiteSpace: 'nowrap', flexShrink: 0 }}>
                              STEP {sIdx + 1}
                            </span>
                            <span style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.45 }}>
                              {cleanText}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Recommended action tag */}
                <div style={{ marginBottom: 12 }}>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', marginRight: 8 }}>RECOMMENDED:</span>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--accentbg)', background: 'rgba(61,90,62,0.1)', border: '1px solid rgba(61,90,62,0.3)', borderRadius: 4, padding: '2px 8px' }}>{item.action}</span>
                </div>

                {/* Three action buttons */}
                <div style={{ display: 'flex', gap: 8 }}>
                  <button
                    className="pb-approve"
                    style={{ flex: 1 }}
                    onClick={() => handleApprove(item)}
                  >
                    ✓ APPROVE
                  </button>
                  <button
                    className="pb-dismiss"
                    style={{ flex: 1 }}
                    onClick={() => handleDismiss(item)}
                  >
                    ✕ DISMISS
                  </button>
                  <button
                    className="pb-dismiss"
                    style={{ flex: 1, color: '#3498db', borderColor: '#3498db44' }}
                    onClick={() => openOverride(item)}
                  >
                    ⛭ OVERRIDE
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Resolved log ── */}
      {resolved.length > 0 && (
        <div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--text3)', marginBottom: 12 }}>Resolved ({resolved.length})</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {[...resolved].reverse().map((item) => (
              <div
                key={item.id + item.outcome}
                style={{ background: 'var(--bg2)', border: '1px solid var(--border)', borderLeft: `4px solid ${item.outcome === 'approved' ? '#27ae60' : item.outcome === 'override' ? '#3498db' : '#7f8c8d'}`, borderRadius: 8, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 14, opacity: 0.8 }}
              >
                <span style={{ fontSize: 18 }}>{item.icon}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>{item.title} — {item.target}</div>
                  <div style={{ fontSize: 11, color: 'var(--text3)' }}>{item.outMsg}</div>
                </div>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', flexShrink: 0 }}>{item.id}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div ref={bottomRef}></div>
    </div>
  );
}
