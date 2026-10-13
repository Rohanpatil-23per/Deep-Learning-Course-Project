import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  getOrchestratorHealth,
  getLayerHealthStats,
  getMeshNodes,
  getPendingApprovals,
  getRecentAlerts,
  getOrchestratorMetrics,
  getLatestAttackGraph,
} from '../api/immunexApi';

// ─── Stage colour helper ──────────────────────────────────────────────────────
const STAGE_COLORS = {
  Attacker:              '#6b21a8',
  Target:                '#1e40af',
  Reconnaissance:        '#1d4ed8',
  'Initial Access':      '#d97706',
  Initial_Access:        '#d97706',
  Execution:             '#ea580c',
  'Credential Access':   '#d97706',
  'Privilege Escalation':'#ea580c',
  'Lateral Movement':    '#ea580c',
  'Command and Control': '#dc2626',
  Exfiltration:          '#991b1b',
  Impact:                '#7f1d1d',
  Containment:           '#15803d',
  Discovery:             '#0369a1',
};

function getStageColor(stage) {
  return STAGE_COLORS[stage] || '#3b82f6';
}

export default function Dashboard({ navigateTo, lastPipelineResult }) {
  const [expandedRows, setExpandedRows] = useState({});
  const toggleRow = (i) => setExpandedRows(prev => ({ ...prev, [i]: !prev[i] }));

  const [layerHealth, setLayerHealth] = useState([
    { name: 'L1 Detection',     latency: '—', online: null },
    { name: 'L2 Correlation',   latency: '—', online: null },
    { name: 'L3 Response',      latency: '—', online: null },
    { name: 'L4 Immunity',      latency: '—', online: null },
    { name: 'L5 Threat Memory', latency: '—', online: null },
  ]);
  const [meshNodes, setMeshNodes]       = useState([]);
  const [pendingCount, setPendingCount] = useState('—');
  const [liveAlerts, setLiveAlerts]     = useState([]);
  const [lastRefresh, setLastRefresh]   = useState(null);
  const [orchestratorOnline, setOrchestratorOnline] = useState(null);
  const [metricsHistory, setMetricsHistory] = useState([]);

  // ── Threat Graph State on Dashboard ──
  const [dashGraph, setDashGraph] = useState(null);
  const [selectedGraphNode, setSelectedGraphNode] = useState(null);
  const graphCanvasRef = useRef(null);

  const criticalCount = liveAlerts.filter(a => a.sev === 'critical').length;
  const activeCount   = liveAlerts.filter(a => a.status === 'active' || a.status === 'unresolved').length;

  // Simple metrics chart component
  const MetricsChart = ({ data, height = 80 }) => {
    const canvasRef = useRef(null);

    useEffect(() => {
      const canvas = canvasRef.current;
      if (!canvas || !data.length) return;

      const ctx = canvas.getContext('2d');
      const W = canvas.offsetWidth || 300;
      const H = height;
      canvas.width = W;
      canvas.height = H;

      ctx.clearRect(0, 0, W, H);
      if (data.length < 2) return;

      const maxVal = Math.max(...data) || 1;
      const points = data.map((val, i) => ({
        x: (i / (data.length - 1)) * W,
        y: H - ((val / maxVal) * H * 0.8) - H * 0.1
      }));

      const grad = ctx.createLinearGradient(0, 0, 0, H);
      grad.addColorStop(0, 'rgba(0,212,170,0.3)');
      grad.addColorStop(1, 'rgba(0,212,170,0.05)');

      ctx.beginPath();
      ctx.moveTo(points[0].x, H);
      points.forEach(p => ctx.lineTo(p.x, p.y));
      ctx.lineTo(points[points.length - 1].x, H);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      ctx.beginPath();
      points.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
      ctx.strokeStyle = '#00d4aa';
      ctx.lineWidth = 2;
      ctx.stroke();
    }, [data, height]);

    return <canvas ref={canvasRef} style={{ width: '100%', height: `${height}px`, display: 'block' }} />;
  };

  // ── Draw Threat Graph on Dashboard Canvas ─────────────────────────────────
  const drawThreatGraph = useCallback(() => {
    const canvas = graphCanvasRef.current;
    if (!canvas) return;

    const W = canvas.offsetWidth || 800;
    const H = 220;
    canvas.width = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, W, H);

    // Subtle technical grid
    ctx.strokeStyle = '#ede8dc20';
    ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

    if (!dashGraph || !dashGraph.nodes || dashGraph.nodes.length === 0) {
      // Empty standby state
      ctx.font = "12px 'IBM Plex Mono', monospace";
      ctx.fillStyle = '#6b7280';
      ctx.textAlign = 'center';
      ctx.fillText('Awaiting live threat sequence telemetry...', W / 2, H / 2 - 8);
      ctx.font = "11px 'IBM Plex Mono', monospace";
      ctx.fillStyle = '#9ca3af';
      ctx.fillText('Inject a log via Detect to visualize the real-time GATv2 attack graph.', W / 2, H / 2 + 14);
      return;
    }

    const nodes = dashGraph.nodes;
    const edges = dashGraph.edges || [];
    const predNode = dashGraph.predicted_node || null;

    const xy = (n) => ({ x: n.x * W, y: n.y * H });

    // 1. Draw Edges
    for (let i = 0; i < nodes.length - 1; i++) {
      const a = xy(nodes[i]);
      const b = xy(nodes[i + 1]);
      const w = edges[i]?.weight ?? dashGraph.graph_attack_prob ?? 0.8;
      const ec = w > 0.7 ? '#dc2626' : w > 0.4 ? '#d97706' : '#ca8a04';
      const cx = (a.x + b.x) / 2;

      ctx.beginPath();
      ctx.setLineDash([5, 3]);
      ctx.moveTo(a.x, a.y);
      ctx.bezierCurveTo(cx, a.y - 25, cx, b.y - 25, b.x, b.y);
      ctx.strokeStyle = ec + 'bb';
      ctx.lineWidth = 2;
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrowhead
      const angle = Math.atan2(b.y - a.y, b.x - a.x);
      ctx.save();
      ctx.translate(b.x - 20 * Math.cos(angle), b.y - 20 * Math.sin(angle));
      ctx.rotate(angle);
      ctx.beginPath();
      ctx.moveTo(0, 0); ctx.lineTo(-8, -4); ctx.lineTo(-8, 4); ctx.closePath();
      ctx.fillStyle = ec;
      ctx.fill();
      ctx.restore();

      // Action label
      const act = edges[i]?.action;
      if (act) {
        ctx.font = "9px 'IBM Plex Mono', monospace";
        ctx.fillStyle = '#6b7280';
        ctx.textAlign = 'center';
        ctx.fillText(act.slice(0, 36), (a.x + b.x) / 2, Math.min(a.y, b.y) - 28);
      }
    }

    // 2. Draw Predicted Edge
    if (predNode && nodes.length > 0) {
      const last = xy(nodes[nodes.length - 1]);
      const pred = xy(predNode);
      const cx = (last.x + pred.x) / 2;

      ctx.beginPath();
      ctx.setLineDash([4, 4]);
      ctx.moveTo(last.x, last.y);
      ctx.bezierCurveTo(cx, last.y - 25, cx, pred.y - 25, pred.x, pred.y);
      ctx.strokeStyle = '#94a3b8aa';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // 3. Draw Nodes
    nodes.forEach((n) => {
      const { x, y } = xy(n);
      const isSel = selectedGraphNode?.id === n.id;
      const color = n.color || getStageColor(n.stage);
      const r = isSel ? 24 : 20;

      ctx.shadowColor = color + '55';
      ctx.shadowBlur = isSel ? 16 : 8;
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = isSel ? 3 : 2;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Icon
      ctx.font = '12px serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(n.icon || '🔷', x, y);

      // Label below
      ctx.font = "600 9px 'IBM Plex Mono', monospace";
      ctx.fillStyle = '#1f2937';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const label = (n.label || n.stage || '').toUpperCase();
      ctx.fillText(label.slice(0, 16), x, y + r + 5);
    });

    // 4. Draw Predicted Node
    if (predNode) {
      const { x, y } = xy(predNode);
      const color = predNode.color || getStageColor(predNode.stage);
      ctx.save();
      ctx.globalAlpha = 0.6;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.arc(x, y, 19, 0, Math.PI * 2);
      ctx.fillStyle = '#f8fafc';
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.font = '12px serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(predNode.icon || '🔮', x, y);

      ctx.font = "500 8px 'IBM Plex Mono', monospace";
      ctx.fillStyle = '#64748b';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText((predNode.label || '').toUpperCase().slice(0, 14), x, y + 23);
      ctx.restore();
    }
  }, [dashGraph, selectedGraphNode]);

  // Redraw when graph data changes or window resizes
  useEffect(() => {
    drawThreatGraph();
    window.addEventListener('resize', drawThreatGraph);
    return () => window.removeEventListener('resize', drawThreatGraph);
  }, [drawThreatGraph]);

  // Click on Dashboard graph canvas to select node
  const handleGraphClick = (e) => {
    if (!dashGraph?.nodes?.length) return;
    const canvas = graphCanvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const cx = e.clientX - rect.left;
    const cy = e.clientY - rect.top;
    const W = canvas.offsetWidth;
    const H = 220;

    let found = null;
    dashGraph.nodes.forEach(n => {
      const nx = n.x * W;
      const ny = n.y * H;
      const dist = Math.hypot(cx - nx, cy - ny);
      if (dist <= 26) found = n;
    });
    setSelectedGraphNode(found);
  };

  const fetchHealth = async () => {
    try {
      await getOrchestratorHealth();
      setOrchestratorOnline(true);
      const stats = await getLayerHealthStats();
      setLayerHealth(stats);

      try {
        const metrics = await getOrchestratorMetrics();
        const newPoint = {
          timestamp: Date.now(),
          threats: metrics.counters?.pipeline_anomalous || 0,
          processed: metrics.counters?.pipeline_started || 0,
          uptime: metrics.metrics?.uptime_seconds || 0
        };
        setMetricsHistory(prev => [...prev.slice(-19), newPoint]);
      } catch {}

      setLastRefresh(new Date().toLocaleTimeString('en', { hour12: false }));
    } catch {
      setOrchestratorOnline(false);
    }
  };

  const fetchNodes = async () => {
    try {
      const d = await getMeshNodes();
      const nodes = d.nodes || {};
      setMeshNodes(Object.entries(nodes).map(([url, info]) => ({
        url, alive: info.alive || info.online,
        gpu: info.gpu_eligible, latency: info.latency_ms,
        device: info.device,
      })));
    } catch {}
  };

  const fetchPending = async () => {
    try {
      const raw = await getPendingApprovals();
      const items = Array.isArray(raw) ? raw : (raw.pending || raw.items || []);
      setPendingCount(items.length);
    } catch {}
  };

  const fetchAlerts = async () => {
    try {
      const alerts = await getRecentAlerts();
      setLiveAlerts(alerts);
    } catch {}
  };

  // Sync threat graph data from lastPipelineResult or backend
  const fetchGraph = async () => {
    if (lastPipelineResult?.layer2?.attack_graph?.nodes?.length > 0) {
      setDashGraph(lastPipelineResult.layer2.attack_graph);
      return;
    }
    if (lastPipelineResult?.layer2?.nodes?.length > 0) {
      setDashGraph(lastPipelineResult.layer2);
      return;
    }
    try {
      const latest = await getLatestAttackGraph();
      if (latest?.nodes?.length > 0) {
        setDashGraph(latest);
      }
    } catch {}
  };

  useEffect(() => {
    fetchHealth();
    fetchNodes();
    fetchPending();
    fetchAlerts();
    fetchGraph();

    const iv = setInterval(() => {
      fetchHealth();
      fetchNodes();
      fetchPending();
      fetchAlerts();
      fetchGraph();
    }, 20000);
    return () => clearInterval(iv);
  }, [lastPipelineResult]);

  const onlineCount = layerHealth.filter(l => l.online).length;

  return (
    <div className="section-page active" style={{ display: 'block' }}>

      {/* ── Hero ── */}
      <div className="dash-hero">
        <div>
          <div className="section-eyebrow">System Overview</div>
          <h1 className="section-headline">Your threat landscape,<br />right now.</h1>
          <p className="section-sub" style={{ marginBottom: 24 }}>
            Live monitoring across all detection surfaces. Expert-curated intelligence streaming in real-time.
          </p>
          <div className="dash-actions">
            <button className="btn btn-primary"   onClick={() => navigateTo('detect')}>Inject Logs</button>
            <button className="btn btn-secondary" onClick={() => navigateTo('attack-graph')}>View Threats</button>
          </div>
        </div>
        <div className="terminal-card">
          <div className="terminal-header">
            <div className="term-dot r"></div>
            <div className="term-dot y"></div>
            <div className="term-dot g"></div>
            <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', marginLeft: 8, letterSpacing: 1 }}>immunex@detect:~</span>
          </div>
          <div className="terminal-body">
            <span className="term-line sys">[SYS] Neural GATv2 & BiLSTM correlation engine active</span>
            <span className="term-line sys">[L2] Neo4j graph persistence: bolt://localhost:7687</span>
            <span className="term-line alert">[ALRT] Live GATv2 graph probability: {dashGraph?.graph_attack_prob != null ? `${(dashGraph.graph_attack_prob * 100).toFixed(1)}%` : 'Active'}</span>
            <span className="term-line info">[INTL] MITRE ATT&CK tactic: {dashGraph?.mitre_stage || 'Correlating...'}</span>
            <span className="term-line sys">[SYS] Autonomous containment ready.</span>
            <span className="term-line sys">&gt; <span className="term-cursor"></span></span>
          </div>
        </div>
      </div>

      <div className="section-body">

        {/* ── Stats Row ── */}
        <div className="stats-row">
          <div className="stat-block">
            <div className="stat-label">Total Incidents</div>
            <span className="stat-num">{liveAlerts.length}</span>
          </div>
          <div className="stat-block">
            <div className="stat-label">Active Threats</div>
            <span className="stat-num red">{activeCount}</span>
          </div>
          <div className="stat-block">
            <div className="stat-label">Pending Actions</div>
            <span className="stat-num">{pendingCount}</span>
          </div>
          <div className="stat-block">
            <div className="stat-label">Critical Alerts</div>
            <span className="stat-num" style={{ color: '#c0392b' }}>{criticalCount}</span>
          </div>
          <div className="stat-block">
            <div className="stat-label">Layers Online</div>
            <span className="stat-num accent">
              {layerHealth.every(l => l.online === null) ? '—' : `${onlineCount}/5`}
            </span>
          </div>
        </div>

        {/* ── Active Threat Attack Graph Showcase ─────────────────────────────── */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 2, textTransform: 'uppercase', color: 'var(--accentbg)', marginBottom: 4 }}>
                Active Threat Intelligence · Neural GATv2 Kill-Chain
              </div>
              <h2 className="section-title" style={{ margin: 0 }}>Correlated Threat Attack Graph</h2>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              {dashGraph?.graph_attack_prob != null && (
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600,
                  color: dashGraph.graph_attack_prob > 0.7 ? '#c0392b' : '#d97706',
                  background: dashGraph.graph_attack_prob > 0.7 ? 'rgba(192,57,43,0.1)' : 'rgba(217,119,6,0.1)',
                  border: `1px solid ${dashGraph.graph_attack_prob > 0.7 ? '#c0392b44' : '#d9770644'}`,
                  borderRadius: 6, padding: '4px 10px',
                }}>
                  ● {(dashGraph.graph_attack_prob * 100).toFixed(1)}% GATv2 Probability
                </span>
              )}
              {dashGraph?.predicted_next_stage && (
                <span style={{
                  fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text2)',
                  background: 'var(--bg2)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '4px 10px',
                }}>
                  Next: <strong>{dashGraph.predicted_next_stage}</strong>
                </span>
              )}
              <button className="btn btn-secondary btn-sm" onClick={() => navigateTo('attack-graph')}>
                Full Graph View →
              </button>
            </div>
          </div>

          <div className="card" style={{ padding: 14, overflow: 'hidden' }}>
            <canvas
              ref={graphCanvasRef}
              onClick={handleGraphClick}
              style={{
                width: '100%', height: '220px', display: 'block', cursor: 'pointer',
                borderRadius: 8, background: 'var(--bg2)',
              }}
            />

            {/* Selected Node Details Ribbon */}
            {selectedGraphNode && (
              <div style={{
                marginTop: 10, padding: '10px 14px', background: 'var(--card)',
                border: `1px solid ${selectedGraphNode.color || getStageColor(selectedGraphNode.stage)}`,
                borderRadius: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12,
              }}>
                <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                  <span style={{ fontWeight: 600, color: selectedGraphNode.color || getStageColor(selectedGraphNode.stage), fontFamily: 'var(--mono)' }}>
                    {selectedGraphNode.icon} {selectedGraphNode.label} ({selectedGraphNode.stage})
                  </span>
                  <span style={{ color: 'var(--text2)', fontSize: 11 }}>
                    {selectedGraphNode.details || `Observed in attack chain`}
                  </span>
                </div>
                <button onClick={() => setSelectedGraphNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)' }}>✕</button>
              </div>
            )}

            {/* Quick telemetry footer */}
            {dashGraph?.nodes?.length > 0 && (
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12,
                marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border)',
                fontFamily: 'var(--mono)', fontSize: 11,
              }}>
                <div>
                  <div style={{ color: 'var(--text3)', fontSize: 9 }}>ATTACK TYPE</div>
                  <div style={{ fontWeight: 600, color: 'var(--text)' }}>{dashGraph.attack_type || 'Port Scan'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text3)', fontSize: 9 }}>CURRENT STAGE</div>
                  <div style={{ fontWeight: 600, color: '#d97706' }}>{dashGraph.mitre_stage || 'Initial Access'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text3)', fontSize: 9 }}>PREDICTED NEXT</div>
                  <div style={{ fontWeight: 600, color: '#ea580c' }}>{dashGraph.predicted_next_stage || 'Execution'}</div>
                </div>
                <div>
                  <div style={{ color: 'var(--text3)', fontSize: 9 }}>NEO4J AUDIT</div>
                  <div style={{ fontWeight: 600, color: '#15803d' }}>● Committed (Chain Active)</div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Two Column: Alerts Table + Severity Breakdown ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 24, marginBottom: 32 }}>

          {/* Alerts Table */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <h2 className="section-title" style={{ margin: 0 }}>Recent Intelligence Alerts</h2>
              <button className="btn btn-secondary btn-sm" onClick={() => navigateTo('alerts')}>View All →</button>
            </div>
            <div className="card" style={{ padding: 0 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {liveAlerts.slice(0, 8).map((a, i) => (
                    <React.Fragment key={i}>
                      <tr onClick={() => toggleRow(i)} style={{ cursor: 'pointer' }}>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 600 }}>{a.id}</td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 11 }}>{a.ts}</td>
                        <td style={{ fontWeight: 500 }}>{a.type}</td>
                        <td><span className={`sev-tag sev-${a.sev}`}>{a.sev}</span></td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>{a.ip}</td>
                        <td><span className={`status-tag status-${a.status}`}>{a.status}</span></td>
                      </tr>
                      {expandedRows[i] && (
                        <tr>
                          <td colSpan={6} style={{ background: 'var(--bg2)', padding: '12px 16px' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, fontFamily: 'var(--mono)', fontSize: 11 }}>
                              <div><div style={{ color: 'var(--text3)', marginBottom: 3 }}>MITRE Tactic</div><div style={{ fontWeight: 600 }}>{a.mitre}</div></div>
                              <div><div style={{ color: 'var(--text3)', marginBottom: 3 }}>Attack Vector</div><div style={{ fontWeight: 600 }}>{a.vector}</div></div>
                              <div><div style={{ color: 'var(--text3)', marginBottom: 3 }}>Recommendation</div><div style={{ fontWeight: 600 }}>{a.rec}</div></div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div>
            <h2 className="section-title" style={{ marginBottom: 14 }}>Severity Breakdown</h2>
            <div className="card">
              {['critical', 'high', 'medium', 'low'].map(sev => {
                const count = liveAlerts.filter(a => a.sev === sev).length;
                const pct   = liveAlerts.length ? Math.round((count / liveAlerts.length) * 100) : 0;
                return (
                  <div key={sev} style={{ marginBottom: 16 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                      <span className={`sev-tag sev-${sev}`}>{sev}</span>
                      <span style={{ fontFamily: 'var(--mono)', fontSize: 12, fontWeight: 600 }}>{count}</span>
                    </div>
                    <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${pct}%`, borderRadius: 3, background: sev === 'critical' ? '#c0392b' : sev === 'high' ? '#d4680a' : sev === 'medium' ? '#b8860b' : '#3d5a3e' }}></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── System Health (live) ── */}
        <div style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h2 className="section-title" style={{ margin: 0 }}>System Health</h2>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
              {lastRefresh && (
                <span style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)' }}>
                  Last checked: {lastRefresh}
                </span>
              )}
              <button className="btn btn-secondary btn-sm" onClick={fetchHealth}>Refresh</button>
            </div>
          </div>
          <div className="health-grid">
            {layerHealth.map(({ name, latency, online }) => (
              <div key={name} className="health-item">
                <span className="health-name">{name}</span>
                <div className="health-status">
                  <span className="health-latency">{latency}</span>
                  <div className={`health-dot ${online === null ? '' : online ? '' : 'offline'}`}></div>
                </div>
              </div>
            ))}
            <div className="health-item">
              <span className="health-name">Orchestrator</span>
              <div className="health-status">
                <span className="health-latency">—</span>
                <div className={`health-dot ${orchestratorOnline === null ? '' : orchestratorOnline ? '' : 'offline'}`}></div>
              </div>
            </div>
            {meshNodes.slice(0, 3).map(n => {
              const label = n.url.replace(/https?:\/\//, '').replace(':8000', '');
              return (
                <div key={n.url} className="health-item">
                  <span className="health-name">{label}</span>
                  <div className="health-status">
                    <span className="health-latency">{n.latency ? n.latency.toFixed(0) + 'ms' : '—'}</span>
                    <div className={`health-dot ${n.alive ? '' : 'offline'}`}></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Live Metrics Chart ── */}
        <div style={{ marginBottom: 32 }}>
          <h2 className="section-title" style={{ marginBottom: 14 }}>Threat Detection Trends</h2>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div className="card" style={{ padding: 16 }}>
              <div style={{ marginBottom: 8, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>Threats Detected</div>
              <MetricsChart data={metricsHistory.map(m => m.threats)} height={60} />
              <div style={{ marginTop: 8, fontFamily: 'var(--mono)', fontSize: 14, fontWeight: 600 }}>
                {metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1].threats : 0} total
              </div>
            </div>
            <div className="card" style={{ padding: 16 }}>
              <div style={{ marginBottom: 8, fontFamily: 'var(--mono)', fontSize: 11, color: 'var(--text3)' }}>Logs Processed</div>
              <MetricsChart data={metricsHistory.map(m => m.processed)} height={60} />
              <div style={{ marginTop: 8, fontFamily: 'var(--mono)', fontSize: 14, fontWeight: 600 }}>
                {metricsHistory.length > 0 ? metricsHistory[metricsHistory.length - 1].processed : 0} total
              </div>
            </div>
          </div>
        </div>

        {/* ── Quick Actions ── */}
        <div>
          <h2 className="section-title" style={{ marginBottom: 14 }}>Quick Actions</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Inject Logs',    icon: '⬆', section: 'detect',       desc: 'Feed telemetry into detection engine' },
              { label: 'View Playbook',  icon: '📋', section: 'playbook',     desc: 'Review pending response actions' },
              { label: 'Attack Graph',   icon: '🕸', section: 'attack-graph', desc: 'Visualize threat kill chain' },
              { label: 'AIS Engine',     icon: '🧠', section: 'ais',          desc: 'Trigger adaptive retraining' },
            ].map(({ label, icon, section, desc }) => (
              <button key={section} onClick={() => navigateTo(section)}
                style={{ background: 'var(--card)', border: '1px solid var(--border)', borderRadius: 10, padding: '16px 18px', textAlign: 'left', cursor: 'pointer', transition: 'all .2s' }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accentbg)'}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border)'}
              >
                <div style={{ fontSize: 22, marginBottom: 8 }}>{icon}</div>
                <div style={{ fontFamily: 'var(--mono)', fontSize: 11, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase', color: 'var(--text)', marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 11, color: 'var(--text3)', lineHeight: 1.4 }}>{desc}</div>
              </button>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
