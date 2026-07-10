import React from 'react';
import {
    ComposableMap,
    Geographies,
    Geography,
    Marker
} from 'react-simple-maps';
import { Tooltip as ReactTooltip } from 'react-tooltip';
import 'react-tooltip/dist/react-tooltip.css';

const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json";

export default function GeoIPMap({ alerts }) {
    // Filter alerts that have valid location coordinates
    const markers = alerts.filter(a => a.lat && a.lon && a.lat !== 0 && a.lon !== 0);

    return (
        <div style={{ width: '100%', height: '100%', minHeight: '300px', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            <ComposableMap projectionConfig={{ scale: 145 }} style={{ width: '100%', height: '100%' }}>
                <Geographies geography={geoUrl}>
                    {({ geographies }) =>
                        geographies.map((geo) => (
                            <Geography
                                key={geo.rsmKey}
                                geography={geo}
                                fill="#161b22"
                                stroke="#30363d"
                                strokeWidth={0.5}
                                style={{
                                    default: { outline: 'none' },
                                    hover: { fill: "#21262d", outline: 'none' },
                                    pressed: { outline: 'none' }
                                }}
                            />
                        ))
                    }
                </Geographies>

                {markers.map((a, i) => (
                    <Marker
                        key={i}
                        coordinates={[a.lon, a.lat]}
                    >
                        {/* Heatmap blur radius */}
                        <circle
                            r={14}
                            fill="#e63946"
                            fillOpacity={0.15}
                            style={{ filter: "blur(2px)" }}
                            data-tooltip-id="map-tooltip"
                            data-tooltip-content={`${a.domain} (Risk: ${a.risk_score}%) - ${a.country}`}
                        />
                        <circle
                            r={8}
                            fill="#e63946"
                            fillOpacity={0.25}
                            style={{ filter: "blur(1px)" }}
                            data-tooltip-id="map-tooltip"
                            data-tooltip-content={`${a.domain} (Risk: ${a.risk_score}%) - ${a.country}`}
                        />
                        {/* Core point */}
                        <circle
                            r={2}
                            fill="#ff4d4d"
                        />
                    </Marker>
                ))}
            </ComposableMap>
            <ReactTooltip
                id="map-tooltip"
                place="top"
                style={{ backgroundColor: '#161b22', zIndex: 1000, borderRadius: '8px', border: '1px solid #30363d' }}
            />
        </div>
    );
}
