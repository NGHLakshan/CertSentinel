import { useEffect, useState } from 'react'
import {
    AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'

const API = 'http://localhost:8000/api/analytics'

export default function HistoricalAnalytics() {
    const [view, setView] = useState('daily')
    const [data, setData] = useState([])
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    async function fetchData(v) {
        setLoading(true)
        setError('')
        try {
            const res = await fetch(`${API}?view=${v}`)
            const json = await res.json()
            setData(json.data || [])
        } catch {
            setError('Backend එකට connect වෙන්න බැරි උනා.')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => { fetchData(view) }, [view])

    const toggle = (v) => { if (v !== view) setView(v) }

    const CustomTooltip = ({ active, payload, label }) => {
        if (active && payload && payload.length) {
            return (
                <div className="analytics-tooltip">
                    <div className="analytics-tooltip-label">{label}</div>
                    <div className="analytics-tooltip-value">
                        🚨 <strong>{payload[0].value}</strong> threats
                    </div>
                </div>
            )
        }
        return null
    }

    return (
        <section className="analytics-section">
            <div className="analytics-header">
                <h2 className="analytics-title">
                    📊 Historical Analytics
                </h2>
                <p className="analytics-desc">
                    Stored data වලින් daily/weekly threat trends
                </p>
                <div className="analytics-toggle">
                    <button
                        className={`analytics-toggle-btn ${view === 'daily' ? 'active' : ''}`}
                        onClick={() => toggle('daily')}
                    >
                        Daily
                    </button>
                    <button
                        className={`analytics-toggle-btn ${view === 'weekly' ? 'active' : ''}`}
                        onClick={() => toggle('weekly')}
                    >
                        Weekly
                    </button>
                </div>
            </div>

            <div className="analytics-chart-wrap">
                {loading && (
                    <div className="analytics-loading">
                        <span className="scanner-spinner" />
                    </div>
                )}
                {error && <div className="scan-error">⚠️ {error}</div>}
                {!loading && !error && data.length === 0 && (
                    <div className="chart-empty" style={{ height: 240 }}>
                        No historical data yet — threats will appear after they are detected.
                    </div>
                )}
                {!loading && !error && data.length > 0 && (
                    <ResponsiveContainer width="100%" height={240}>
                        <AreaChart data={data} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                            <defs>
                                <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#e63946" stopOpacity={0.35} />
                                    <stop offset="95%" stopColor="#e63946" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
                            <XAxis
                                dataKey="label"
                                stroke="#8b949e"
                                tick={{ fontSize: 11 }}
                                tickLine={false}
                            />
                            <YAxis
                                stroke="#8b949e"
                                tick={{ fontSize: 11 }}
                                tickLine={false}
                                axisLine={false}
                                allowDecimals={false}
                            />
                            <Tooltip content={<CustomTooltip />} />
                            <Area
                                type="monotone"
                                dataKey="count"
                                stroke="#e63946"
                                strokeWidth={2}
                                fill="url(#threatGrad)"
                                dot={{ fill: '#e63946', r: 3, strokeWidth: 0 }}
                                activeDot={{ r: 5, fill: '#e63946' }}
                            />
                        </AreaChart>
                    </ResponsiveContainer>
                )}
            </div>
        </section>
    )
}
