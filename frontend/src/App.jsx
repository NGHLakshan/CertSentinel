import { useEffect, useState, useRef, useCallback } from 'react'
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
  PieChart, Pie, Legend,
} from 'recharts'
import './index.css'
import GeoIPMap from './GeoIPMap'
import HistoricalAnalytics from './HistoricalAnalytics'

const WS_URL = 'ws://localhost:8000/ws'
const BAR_COLORS = ['#e63946', '#f4a261', '#2a9d8f', '#457b9d', '#a8dadc', '#e9c46a', '#264653', '#6a4c93']

// ── helpers ──────────────────────────────────────────────────────────────────
function getBucket() {
  const d = new Date()
  const mm = Math.floor(d.getMinutes() / 1) * 1   // 1-min bucket label
  return `${String(d.getHours()).padStart(2, '0')}:${String(mm).padStart(2, '0')}`
}

function exportCSV(alerts) {
  const rows = ['Domain,Timestamp,Keyword,TLD,RiskScore',
    ...alerts.map(a => `${a.domain},${a.timestamp},${a.keyword || ''},${a.tld || ''},${a.risk_score || 0}%`)
  ]
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = 'phishing_alerts.csv'; a.click()
  URL.revokeObjectURL(url)
}

// ── component ─────────────────────────────────────────────────────────────────
export default function App() {
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total_scanned: 0, total_suspicious: 0 })
  const [connected, setConnected] = useState(false)
  const [search, setSearch] = useState('')

  // ── link scanner state ─────────────────────────────────────────────────────
  const [scanUrl, setScanUrl] = useState('')
  const [scanResult, setScanResult] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [scanError, setScanError] = useState('')

  const handleScan = async () => {
    if (!scanUrl.trim()) return
    setScanLoading(true)
    setScanResult(null)
    setScanError('')
    try {
      const res = await fetch('http://localhost:8000/api/scan-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: scanUrl.trim() }),
      })
      const data = await res.json()
      if (data.error) {
        setScanError(data.error)
      } else {
        setScanResult(data)
      }
    } catch {
      setScanError('Backend එකට connect වෙන්න බැරි උනා. Server එක run වෙනවද check කරන්න.')
    } finally {
      setScanLoading(false)
    }
  }

  const getRiskColor = (score) => score >= 70 ? 'var(--accent)' : score >= 40 ? 'var(--accent2)' : 'var(--green)'
  const getRiskLabel = (score) => score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MEDIUM RISK' : 'SAFE'

  // chart data
  const [timelineData, setTimelineData] = useState([])   // [{time, count}]
  const [keywordCounts, setKeywordCounts] = useState({})   // {word: n}
  const [tldCounts, setTldCounts] = useState({})   // {tld: n}

  // alert rate (alerts in last 60s)
  const recentRef = useRef([])         // timestamps of recent alerts
  const [alertRate, setAlertRate] = useState(0)

  const wsRef = useRef(null)
  const destroyedRef = useRef(false)

  // ── alert rate ticker ──────────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now()
      recentRef.current = recentRef.current.filter(t => now - t < 60000)
      setAlertRate(recentRef.current.length)
    }, 1000)
    return () => clearInterval(id)
  }, [])

  // ── process incoming alert ─────────────────────────────────────────────────
  const processAlert = useCallback((data) => {
    // 1. dedup
    setAlerts(prev =>
      prev.some(a => a.domain === data.domain)
        ? prev
        : [data, ...prev].slice(0, 200)
    )

    // 2. alert rate
    recentRef.current.push(Date.now())

    // 3. timeline (1-min buckets)
    const bucket = getBucket()
    setTimelineData(prev => {
      const last = prev[prev.length - 1]
      if (last && last.time === bucket) {
        return [...prev.slice(0, -1), { time: bucket, count: last.count + 1 }]
      }
      return [...prev, { time: bucket, count: 1 }].slice(-20)
    })

    // 4. keyword freq
    if (data.keyword) {
      setKeywordCounts(prev => ({ ...prev, [data.keyword]: (prev[data.keyword] || 0) + 1 }))
    }

    // 5. TLD freq
    if (data.tld) {
      setTldCounts(prev => ({ ...prev, [data.tld]: (prev[data.tld] || 0) + 1 }))
    }
  }, [])

  // ── WebSocket ──────────────────────────────────────────────────────────────
  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws

      ws.onopen = () => { setConnected(true); console.log('✅ WS connected') }

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'stats') {
          setStats({ total_scanned: data.total_scanned, total_suspicious: data.total_suspicious })
        }
        if (data.type === 'alert') {
          setStats({ total_scanned: data.total_scanned, total_suspicious: data.total_suspicious })
          processAlert(data)
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (!destroyedRef.current) {
          console.log('🔄 WS disconnected. Reconnecting...')
          setTimeout(connect, 3000)
        }
      }

      ws.onerror = (err) => { console.error('WS error:', err); ws.close() }
    }

    destroyedRef.current = false
    connect()
    return () => { destroyedRef.current = true; wsRef.current?.close() }
  }, [processAlert])

  // ── derived data for charts ────────────────────────────────────────────────
  const keywordChartData = Object.entries(keywordCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, value]) => ({ name, value }))

  const tldChartData = Object.entries(tldCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }))

  const filteredAlerts = search.trim()
    ? alerts.filter(a => a.domain.toLowerCase().includes(search.toLowerCase()))
    : alerts

  const detectionRate = stats.total_scanned > 0
    ? ((stats.total_suspicious / stats.total_scanned) * 100).toFixed(2) + '%'
    : '0.00%'

  // ── render ─────────────────────────────────────────────────────────────────
  return (
    <>
      {/* ── Header ─────────────────────────────────────────────────── */}
      <header className="header">
        <div className="status-dot" />
        <h1>Cert<span>Sentinel</span></h1>
        <div className="header-right">
          {!connected && <span className="connecting">⚡ Connecting...</span>}
          <button className="export-btn" onClick={() => exportCSV(alerts)} disabled={alerts.length === 0}>
            💾 Export CSV
          </button>
        </div>
      </header>

      {/* ── Stats ──────────────────────────────────────────────────── */}
      <section className="stats">
        <div className="stat-card safe">
          <span className="label">Total Scanned</span>
          <span className="value">{stats.total_scanned.toLocaleString()}</span>
        </div>
        <div className="stat-card danger">
          <span className="label">Suspicious Domains</span>
          <span className="value">{stats.total_suspicious.toLocaleString()}</span>
        </div>
        <div className="stat-card">
          <span className="label">Detection Rate</span>
          <span className="value" style={{ color: '#f4a261' }}>{detectionRate}</span>
        </div>
        <div className="stat-card rate">
          <span className="label">⚡ Alert Rate</span>
          <span className="value" style={{ color: '#a8dadc' }}>
            {alertRate}<span style={{ fontSize: '1rem', color: 'var(--text-muted)', marginLeft: 4 }}>/min</span>
          </span>
        </div>
      </section>

      {/* ── Link Scanner ──────────────────────────────────────────── */}
      <section className="scanner-section">
        <h2 className="scanner-title">🔗 Manual Link Scanner</h2>
        <p className="scanner-desc">Link එකක් paste කරලා ඒක safe ද නැද්ද check කරන්න</p>

        <div className="scanner-input-row">
          <input
            id="scan-url-input"
            className="scanner-input"
            type="text"
            placeholder="https://example.com/login..."
            value={scanUrl}
            onChange={e => setScanUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          <button
            id="scan-btn"
            className="scanner-btn"
            onClick={handleScan}
            disabled={scanLoading || !scanUrl.trim()}
          >
            {scanLoading ? (
              <span className="scanner-spinner" />
            ) : '🔍 Scan'}
          </button>
        </div>

        {scanError && (
          <div className="scan-error">⚠️ {scanError}</div>
        )}

        {scanResult && (
          <div className="scan-result" id="scan-result">
            <div className="scan-result-header">
              <div className="risk-gauge">
                <svg viewBox="0 0 100 100" className="risk-circle">
                  <circle cx="50" cy="50" r="40" className="risk-circle-bg" />
                  <circle
                    cx="50" cy="50" r="40"
                    className="risk-circle-fill"
                    style={{
                      stroke: getRiskColor(scanResult.risk_score),
                      strokeDasharray: `${scanResult.risk_score * 2.51} 251`,
                    }}
                  />
                </svg>
                <div className="risk-gauge-text">
                  <span className="risk-gauge-number" style={{ color: getRiskColor(scanResult.risk_score) }}>
                    {scanResult.risk_score}%
                  </span>
                  <span className="risk-gauge-label">Risk Score</span>
                </div>
              </div>

              <div className="scan-info">
                <div className="scan-domain">{scanResult.domain}</div>
                <span
                  className="verdict-badge"
                  style={{
                    borderColor: getRiskColor(scanResult.risk_score),
                    color: getRiskColor(scanResult.risk_score),
                    background: `${getRiskColor(scanResult.risk_score)}15`,
                  }}
                >
                  {getRiskLabel(scanResult.risk_score)}
                </span>

                {scanResult.matched_keywords.length > 0 && (
                  <div className="scan-keywords">
                    <span className="scan-keywords-label">Suspicious Keywords:</span>
                    {scanResult.matched_keywords.map(kw => (
                      <span key={kw} className="kw-badge">{kw}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="scan-features">
              <div className="feature-item">
                <span className="feature-label">Length</span>
                <span className="feature-value">{scanResult.features.length}</span>
              </div>
              <div className="feature-item">
                <span className="feature-label">Entropy</span>
                <span className="feature-value">{scanResult.features.entropy.toFixed(2)}</span>
              </div>
              <div className="feature-item">
                <span className="feature-label">Digits</span>
                <span className="feature-value">{scanResult.features.num_digits}</span>
              </div>
              <div className="feature-item">
                <span className="feature-label">Hyphens</span>
                <span className="feature-value">{scanResult.features.num_hyphens}</span>
              </div>
              <div className="feature-item">
                <span className="feature-label">Sus Keywords</span>
                <span className="feature-value">{scanResult.features.has_sus_keyword ? '✅ Yes' : '❌ No'}</span>
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ── GeoIP Heatmap ──────────────────────────────────────────── */}
      <section className="map-section" style={{ background: 'var(--card-bg)', borderRadius: '12px', padding: '20px', border: '1px solid var(--border)', marginBottom: '1.5rem', boxShadow: '0 4px 20px rgba(0,0,0,0.2)' }}>
        <h2 style={{ fontSize: '1.2rem', marginBottom: '15px', color: 'var(--text-bright)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          🗺️ Live Suspicious Domain Geolocation Map
        </h2>
        <div style={{ height: '400px', width: '100%' }}>
          <GeoIPMap alerts={alerts} />
        </div>
      </section>

      {/* ── Historical Analytics ──────────────────────────────────── */}
      <HistoricalAnalytics />

      {/* ── Charts ─────────────────────────────────────────────────── */}
      <section className="charts-grid">

        {/* Line Chart */}
        <div className="chart-card">
          <h3>📈 Alerts Over Time</h3>
          {timelineData.length === 0
            ? <div className="chart-empty">Waiting for data...</div>
            : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={timelineData}>
                  <XAxis dataKey="time" stroke="#8b949e" tick={{ fontSize: 11 }} />
                  <YAxis stroke="#8b949e" tick={{ fontSize: 11 }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                  <Line type="monotone" dataKey="count" stroke="#e63946" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )
          }
        </div>

        {/* Bar Chart — keywords */}
        <div className="chart-card">
          <h3>🔑 Top Phishing Keywords</h3>
          {keywordChartData.length === 0
            ? <div className="chart-empty">Waiting for data...</div>
            : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={keywordChartData} layout="vertical">
                  <XAxis type="number" stroke="#8b949e" tick={{ fontSize: 11 }} />
                  <YAxis type="category" dataKey="name" stroke="#8b949e" tick={{ fontSize: 11 }} width={60} />
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {keywordChartData.map((_, i) => (
                      <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )
          }
        </div>

        {/* Pie Chart — TLD */}
        <div className="chart-card">
          <h3>🌐 TLD Breakdown</h3>
          {tldChartData.length === 0
            ? <div className="chart-empty">Waiting for data...</div>
            : (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={tldChartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%" cy="50%"
                    innerRadius={50} outerRadius={80}
                    paddingAngle={3}
                  >
                    {tldChartData.map((_, i) => (
                      <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: 11, color: '#8b949e' }} />
                </PieChart>
              </ResponsiveContainer>
            )
          }
        </div>

      </section>

      {/* ── Live Alert Feed ────────────────────────────────────────── */}
      <section className="feed-section">
        <div className="feed-header">
          <h2>🚨 Live Alert Feed
            <span className="alert-count">{alerts.length}</span>
          </h2>
          <input
            className="search-bar"
            type="text"
            placeholder="🔍 Search domain..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="alert-list">
          {filteredAlerts.length === 0
            ? (
              <div className="empty-state">
                <div className="icon">🔍</div>
                <p>{search ? 'No matching domains.' : 'Scanning live certificates... alerts will appear here.'}</p>
              </div>
            )
            : filteredAlerts.map((a, i) => {
              const riskColor = a.risk_score >= 80 ? 'var(--accent)' : a.risk_score >= 50 ? 'var(--accent2)' : 'var(--green)'
              return (
                <div className="alert-item" key={i}>
                  <span className="alert-emoji">🚨</span>
                  <span className="alert-domain">{a.domain}</span>
                  {a.keyword && <span className="kw-badge">{a.keyword}</span>}
                  {a.tld && <span className="tld-badge">{a.tld}</span>}
                  <span className="risk-badge" style={{ borderColor: riskColor, color: riskColor, background: `${riskColor}20` }}>
                    {a.risk_score || 0}% RISK
                  </span>
                  <span className="alert-time">{a.timestamp}</span>
                </div>
              )
            })
          }
        </div>
      </section>
    </>
  )
}
