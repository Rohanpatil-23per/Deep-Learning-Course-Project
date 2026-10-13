import React, { useCallback, useEffect, useRef, useState } from 'react';
import { correlateAttack, getAttackGraph, getLatestAttackGraph } from '../api/immunexApi';

// ─── Stage colour map (matches backend STAGE_META) ───────────────────────────
const STAGE_COLOR = {
  Attacker:             '#6b21a8',
  Target:               '#1e40af',
  Reconnaissance:       '#1d4ed8',
  'Initial Access':     '#d97706',
  Execution:            '#ea580c',
  'Credential Access':  '#d97706',
  'Privilege Escalation':'#ea580c',
  'Lateral Movement':   '#ea580c',
  'Command and Control':'#dc2626',
  Exfiltration:         '#991b1b',
  Impact:               '#7f1d1d',
  Containment:          '#15803d',
  Discovery:            '#0369a1',
};

function stageColor(stage) {
  return STAGE_COLOR[stage] || '#4b5563';
}

function edgeColor(weight) {
  if (weight > 0.7) return '#dc2626';
  if (weight > 0.4) return '#d97706';
  return '#ca8a04';
}

// ─── Sample payload used for mount-time correlation ───────────────────────────
const SAMPLE_PAYLOAD = {
  alert_id:    'graph-init',
  source_ip:   '192.168.1.100',
  dest_ip:     '10.0.0.5',
  attack_type: 'Port Scan',
  severity:    'high',
  text:        'NMAP scan src=192.168.1.100 dst=10.0.0.5 proto=TCP port=22,80,443 failed_auth brute',
};

// ─── AttackGraph component ────────────────────────────────────────────────────
export default function AttackGraph({ lastPipelineResult }) {
  const canvasRef   = useRef(null);
  const animRef     = useRef(null);

  const [nodes,          setNodes]         = useState([]);
  const [edges,          setEdges]         = useState([]);
  const [predictedNode,  setPredictedNode] = useState(null);
  const [timeline,       setTimeline]      = useState([]);
  const [selectedNode,   setSelectedNode]  = useState(null);
  const [backendMode,    setBackendMode]   = useState(false);
  const [animating,      setAnimating]     = useState(false);
  const [animStep,       setAnimStep]      = useState(999);
  const [chainId,        setChainId]       = useState(null);
  const [loading,        setLoading]       = useState(false);
  const [errorMsg,       setErrorMsg]      = useState('');
  const [confidence,     setConfidence]    = useState(null);
  const [nextStage,      setNextStage]     = useState('');

  // ── Ingest a layer2 result object ──────────────────────────────────────────
  const ingestL2 = useCallback((l2) => {
    if (!l2) return;
    const graph = l2.attack_graph || l2.graph || {};
    const bNodes = graph.nodes || l2.nodes || [];
    const bEdges = graph.edges || l2.edges || [];
    const pred   = graph.predicted_node || null;
    const tl     = l2.timeline || [];

    if (bNodes.length > 0) {
      setNodes(bNodes);
      setEdges(bEdges);
      setPredictedNode(pred);
      setBackendMode(true);
      setAnimStep(999);
    }
    if (tl.length > 0) setTimeline(tl);
    if (l2.chain_id)             setChainId(l2.chain_id);
    if (l2.confidence != null)   setConfidence(l2.confidence);
    if (l2.predicted_next_stage) setNextStage(l2.predicted_next_stage);
  }, []);

  // ── Use lastPipelineResult prop if provided ────────────────────────────────
  useEffect(() => {
    if (lastPipelineResult?.layer2) ingestL2(lastPipelineResult.layer2);
  }, [lastPipelineResult, ingestL2]);

  // ── Fetch on mount via /graph/latest ──────────────────────────────────────
  useEffect(() => {
    if (lastPipelineResult?.layer2) return; // already have data
    const fetch = async () => {
      setLoading(true);
      try {
        const latest = await getLatestAttackGraph();
        if (latest?.nodes?.length > 0) {
          ingestL2(latest);
          setErrorMsg('');
        }
      } catch {
        setBackendMode(false);
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Load from Neo4j ────────────────────────────────────────────────────────
  const loadFromNeo4j = async () => {
    if (!chainId) return;
    setLoading(true);
    try {
      const sub = await getAttackGraph(chainId);
      if (sub.nodes?.length > 0) {
        setNodes(sub.nodes);
        setEdges(sub.edges || []);
        setBackendMode(true);
        setAnimStep(999);
      }
      setErrorMsg('');
    } catch (e) {
      setErrorMsg(`Neo4j fetch failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // ── Canvas draw ────────────────────────────────────────────────────────────
  const draw = useCallback((upTo) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const W = canvas.offsetWidth  || 800;
    const H = canvas.offsetHeight || 420;
    canvas.width  = W;
    canvas.height = H;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, W, H);

    // Grid background
    ctx.strokeStyle = '#ede8dc28'; ctx.lineWidth = 1;
    for (let x = 0; x < W; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, H); ctx.stroke(); }
    for (let y = 0; y < H; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke(); }

    const xy = (n) => ({ x: n.x * W, y: n.y * H });
    const visibleNodes = nodes.slice(0, upTo);

    if (visibleNodes.length === 0) {
      ctx.font = "600 12px 'IBM Plex Mono', monospace";
      ctx.fillStyle = '#9ca3af';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('// AWAITING INCIDENT TELEMETRY — INJECT OR UPLOAD LOGS TO VISUALIZE THREAT GRAPH', W / 2, H / 2);
      return;
    }

    // Draw edges
    for (let i = 0; i < Math.min(upTo - 1, nodes.length - 1); i++) {
      const a = xy(nodes[i]);
      const b = xy(nodes[i + 1]);
      const ec = edgeColor(edges[i]?.weight ?? 0.5);
      const cx = (a.x + b.x) / 2;

      ctx.beginPath();
      ctx.setLineDash([6, 4]);
      ctx.moveTo(a.x, a.y);
      ctx.bezierCurveTo(cx, a.y - 30, cx, b.y - 30, b.x, b.y);
      ctx.strokeStyle = ec + 'aa';
      ctx.lineWidth   = 2;
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrowhead
      const angle = Math.atan2(b.y - a.y, b.x - a.x);
      ctx.save();
      ctx.translate(b.x - 20 * Math.cos(angle), b.y - 20 * Math.sin(angle));
      ctx.rotate(angle);
      ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(-9, -4); ctx.lineTo(-9, 4); ctx.closePath();
      ctx.fillStyle = ec; ctx.fill();
      ctx.restore();

      // Edge action label
      const label = edges[i]?.action;
      if (label) {
        ctx.font         = "10px 'IBM Plex Mono', monospace";
        ctx.fillStyle    = '#6b7280';
        ctx.textAlign    = 'center';
        ctx.textBaseline = 'bottom';
        ctx.fillText(label.slice(0, 44), (a.x + b.x) / 2, Math.min(a.y, b.y) - 36);
      }
    }

    // Draw predicted edge (dashed, lighter)
    if (predictedNode && upTo >= nodes.length && nodes.length > 0) {
      const last = xy(nodes[nodes.length - 1]);
      const pred = xy(predictedNode);
      const cx   = (last.x + pred.x) / 2;
      ctx.beginPath();
      ctx.setLineDash([4, 6]);
      ctx.moveTo(last.x, last.y);
      ctx.bezierCurveTo(cx, last.y - 30, cx, pred.y - 30, pred.x, pred.y);
      ctx.strokeStyle = '#94a3b8aa';
      ctx.lineWidth   = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Draw nodes
    visibleNodes.forEach((n) => {
      const { x, y } = xy(n);
      const isImpact  = /impact|exfil/i.test(n.stage);
      const isSelected = selectedNode?.id === n.id;
      const r = isImpact ? 32 : 26;
      const color = n.color || stageColor(n.stage);

      ctx.shadowColor = color + '55'; ctx.shadowBlur = isSelected ? 20 : 10;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = '#fff'; ctx.fill();
      ctx.strokeStyle = color; ctx.lineWidth = isSelected ? 3 : 1.8; ctx.stroke();
      ctx.shadowBlur = 0;

      // Icon
      ctx.font         = `${isImpact ? 16 : 14}px serif`;
      ctx.textAlign    = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle    = color;
      ctx.fillText(n.icon || '🔷', x, y);

      // Label below
      ctx.font         = `500 9px 'IBM Plex Mono', monospace`;
      ctx.fillStyle    = '#374151';
      ctx.textAlign    = 'center';
      ctx.textBaseline = 'top';
      const lbl = (n.label || n.stage || '').toUpperCase();
      ctx.fillText(lbl.slice(0, 16), x, y + r + 5);
    });

    // Draw predicted node (dashed border, lighter)
    if (predictedNode && upTo >= nodes.length) {
      const { x, y } = xy(predictedNode);
      const color = predictedNode.color || stageColor(predictedNode.stage);
      ctx.save();
      ctx.globalAlpha = 0.55;
      ctx.setLineDash([5, 5]);
      ctx.beginPath(); ctx.arc(x, y, 26, 0, Math.PI * 2);
      ctx.fillStyle   = '#f9fafb'; ctx.fill();
      ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.stroke();
      ctx.setLineDash([]);
      ctx.font         = '14px serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillStyle    = color; ctx.fillText(predictedNode.icon || '?', x, y);
      ctx.font         = `500 9px 'IBM Plex Mono', monospace`; ctx.textBaseline = 'top';
      ctx.fillStyle    = '#6b7280';
      ctx.fillText((predictedNode.label || '').toUpperCase().slice(0, 16), x, y + 30);
      ctx.restore();
    }
  }, [nodes, edges, predictedNode, selectedNode]);

  // Redraw whenever data or selection changes
  useEffect(() => { draw(animStep); }, [draw, animStep]);

  // ── Canvas click → node selection ─────────────────────────────────────────
  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx   = (e.clientX - rect.left) * (canvas.width  / rect.width);
    const my   = (e.clientY - rect.top)  * (canvas.height / rect.height);
    const W = canvas.width, H = canvas.height;
    let hit = null;
    for (const n of nodes) {
      const dx = n.x * W - mx, dy = n.y * H - my;
      if (Math.sqrt(dx * dx + dy * dy) < 32) { hit = n; break; }
    }
    setSelectedNode(hit === selectedNode ? null : hit);
  };

  // ── Animate ────────────────────────────────────────────────────────────────
  const animate = () => {
    if (animating || nodes.length === 0) return;
    setAnimating(true);
    setAnimStep(0);
    let cur = 0;
    animRef.current = setInterval(() => {
      cur++;
      setAnimStep(cur);
      if (cur >= nodes.length + 1) {
        clearInterval(animRef.current);
        setAnimating(false);
        setAnimStep(999);
      }
    }, 380);
  };

  // ── Severity dot color ─────────────────────────────────────────────────────
  const sevColor = (sev) => ({
    critical: '#dc2626', high: '#d97706', medium: '#ca8a04', low: '#15803d',
  }[sev] || '#6b7280');

  // ─── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="section-page active" style={{ display: 'block' }}>
      {/* ── Header ── */}
      <div className="section-page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
          <div>
            <div className="section-eyebrow">Threat Visualization</div>
            <h2 className="section-title">Attack Graph Engine</h2>
            <p className="section-sub">
              Real-time reconstruction of adversarial movement across the MITRE ATT&amp;CK kill chain.
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            {/* Live / Static badge */}
            <span style={{
              fontFamily: 'var(--mono)', fontSize: 10, letterSpacing: 1.5,
              textTransform: 'uppercase', color: backendMode ? '#15803d' : 'var(--text3)',
              background: 'var(--bg2)',
              border: `1px solid ${backendMode ? '#15803d' : 'var(--border)'}`,
              borderRadius: 6, padding: '4px 10px',
            }}>
              ● {loading ? 'Loading…' : backendMode ? 'Live' : 'Static'} Mode
            </span>

            {/* Animate button */}
            <button className="btn btn-primary" onClick={animate} disabled={animating || nodes.length === 0}>
              ▶ Animate Attack Chain
            </button>

            {/* Load from Neo4j */}
            {chainId && (
              <button
                className="btn"
                style={{ fontFamily: 'var(--mono)', fontSize: 11, padding: '5px 12px',
                         background: 'var(--bg2)', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}
                onClick={loadFromNeo4j}
                disabled={loading}
              >
                🗄 Load from Neo4j
              </button>
            )}
          </div>
        </div>

        {/* Predicted next stage banner */}
        {nextStage && (
          <div style={{
            marginTop: 6, display: 'inline-flex', alignItems: 'center', gap: 8,
            background: stageColor(nextStage) + '18',
            border: `1px dashed ${stageColor(nextStage)}`,
            borderRadius: 8, padding: '5px 14px', fontSize: 12, color: stageColor(nextStage),
            fontFamily: 'var(--mono)',
          }}>
            ⚡ Predicted next stage: <strong>{nextStage}</strong>
            {confidence != null && (
              <span style={{ opacity: 0.7 }}> — confidence {(confidence * 100).toFixed(1)}%</span>
            )}
          </div>
        )}

        {errorMsg && (
          <div style={{ marginTop: 6, fontSize: 11, color: '#d97706', fontFamily: 'var(--mono)' }}>
            ⚠ {errorMsg}
          </div>
        )}
      </div>

      {/* ── Main layout ── */}
      <div className="graph-page-layout">

        {/* ── Canvas side ── */}
        <div className="graph-canvas-side">
          <canvas
            ref={canvasRef}
            id="attackCanvas"
            onClick={handleCanvasClick}
            style={{
              width: '100%', height: '420px', display: 'block', cursor: 'pointer',
              background: 'var(--card)', border: '1px solid var(--border)',
              borderRadius: 12, boxShadow: '0 4px 24px rgba(0,0,0,0.05)',
            }}
          />

          {/* ── Node detail panel ── */}
          {selectedNode && (
            <div style={{
              marginTop: 14, padding: 16, background: 'var(--bg2)',
              border: `1px solid ${selectedNode.color || stageColor(selectedNode.stage)}`,
              borderRadius: 10,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontFamily: 'var(--mono)', fontSize: 13, fontWeight: 600,
                               color: selectedNode.color || stageColor(selectedNode.stage) }}>
                  {selectedNode.icon} {selectedNode.label}
                </span>
                <button onClick={() => setSelectedNode(null)} style={{
                  background: 'none', border: 'none', cursor: 'pointer', fontSize: 16, color: 'var(--text3)',
                }}>✕</button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 14px', fontSize: 12 }}>
                {[
                  ['Stage',       selectedNode.stage],
                  ['Source IP',   selectedNode.source_ip],
                  ['Dest IP',     selectedNode.dest_ip],
                  ['Attack Type', selectedNode.attack_type],
                  ['Risk Score',  selectedNode.risk_score != null ? (selectedNode.risk_score * 100).toFixed(1) + '%' : '—'],
                  ['Timestamp',   selectedNode.timestamp ? new Date(selectedNode.timestamp).toLocaleTimeString() : '—'],
                ].map(([k, v]) => v && (
                  <React.Fragment key={k}>
                    <span style={{ color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{k}</span>
                    <span style={{ color: 'var(--text1)' }}>{v}</span>
                  </React.Fragment>
                ))}
              </div>
              {selectedNode.details && (
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text2)', fontStyle: 'italic' }}>
                  {selectedNode.details}
                </div>
              )}
            </div>
          )}

          {/* ── Node card grid ── */}
          {nodes.length > 0 && (
            <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 8 }}>
              {nodes.map((n) => (
                <div
                  key={n.id}
                  onClick={() => setSelectedNode(selectedNode?.id === n.id ? null : n)}
                  style={{
                    padding: 10, background: 'var(--bg2)',
                    border: `1px solid ${selectedNode?.id === n.id ? (n.color || stageColor(n.stage)) : 'var(--border)'}`,
                    borderRadius: 8, cursor: 'pointer', transition: 'border-color .15s',
                  }}
                >
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: n.color || stageColor(n.stage) }}>
                    {n.icon} {n.label}
                  </div>
                  <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text2)' }}>
                    {(n.details || n.stage || '').slice(0, 60)}
                  </div>
                </div>
              ))}
              {predictedNode && (
                <div style={{
                  padding: 10, background: 'var(--bg2)',
                  border: `1px dashed ${predictedNode.color || stageColor(predictedNode.stage)}`,
                  borderRadius: 8, opacity: 0.65,
                }}>
                  <div style={{ fontFamily: 'var(--mono)', fontSize: 11, color: predictedNode.color || stageColor(predictedNode.stage) }}>
                    {predictedNode.icon} {predictedNode.label} <span style={{ fontSize: 9 }}>(predicted)</span>
                  </div>
                  <div style={{ marginTop: 4, fontSize: 11, color: 'var(--text2)' }}>{predictedNode.details}</div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── Timeline side ── */}
        <div className="timeline-side">
          <div className="card-label">Event Reconstruction Timeline</div>
          {chainId && (
            <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text3)', marginBottom: 8 }}>
              Chain: {chainId}
            </div>
          )}
          <div id="attack-timeline">
            {timeline.length === 0 && !loading && (
              <div style={{ fontSize: 12, color: 'var(--text3)', padding: '12px 0' }}>
                No timeline events yet. Run a pipeline analysis to populate.
              </div>
            )}
            {timeline.map((e, i) => (
              <div key={i} className="timeline-item" style={{
                opacity: animating && i > animStep ? 0.3 : 1, transition: 'opacity .3s',
              }}>
                <div className="timeline-dot-wrap">
                  <div
                    className="timeline-dot"
                    style={{ background: sevColor(e.severity), border: 'none' }}
                  />
                  {i < timeline.length - 1 && <div className="timeline-line" />}
                </div>
                <div style={{ width: 58 }}>
                  <span className="timeline-ts" style={{ display: 'block', fontSize: 9 }}>
                    {e.timestamp ? new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}
                  </span>
                </div>
                <div className="timeline-content">
                  <div className="timeline-title" style={{ color: stageColor(e.stage) }}>
                    {e.stage}
                  </div>
                  <div className="timeline-desc" style={{ fontSize: 10 }}>
                    {e.severity?.toUpperCase()}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Legend */}
          <div style={{ marginTop: 20, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
            <div className="card-label" style={{ marginBottom: 8 }}>Edge Weight Legend</div>
            {[['> 0.7', '#dc2626', 'Critical risk'], ['> 0.4', '#d97706', 'High risk'], ['≤ 0.4', '#ca8a04', 'Medium risk']].map(([label, color, desc]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, fontSize: 11 }}>
                <div style={{ width: 24, height: 3, background: color, borderRadius: 2 }} />
                <span style={{ fontFamily: 'var(--mono)', color }}>{label}</span>
                <span style={{ color: 'var(--text3)' }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
