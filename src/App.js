import React, { useState } from 'react';
import axios from 'axios';
import { Shield, Activity } from 'lucide-react';

export default function App() {
  const [target, setTarget] = useState('');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const startScan = async () => {
    if(!target) return alert("Please enter a URL");
    setLoading(true);
    try {
      const res = await axios.get(`http://localhost:8000/scan?target=${target}`);
      setData(res.data);
    } catch (e) { alert("Backend offline! Restart main.py."); }
    setLoading(false);
  };

  return (
    <div style={{ backgroundColor: '#020617', color: 'white', minHeight: '100vh', padding: '50px', fontFamily: 'sans-serif' }}>
      <center>
        <h1 style={{ fontSize: '3rem', fontWeight: 'bold' }}>
          Vamshi Krishna’s <span style={{ color: '#06b6d4' }}>Top Highlight</span>
        </h1>
        <p style={{ color: '#94a3b8', letterSpacing: '2px' }}>AUTOMATED VULNERABILITY ASSESSMENT AND SECURITY ANALYSIS</p>
        <div style={{ marginTop: '30px' }}>
          <input 
            style={{ padding: '15px', borderRadius: '10px', width: '350px', backgroundColor: '#0f172a', border: '1px solid #334155', color: 'white' }}
            placeholder="https://example.com" 
            onChange={(e) => setTarget(e.target.value)} 
          />
          <button onClick={startScan} style={{ padding: '15px 30px', marginLeft: '10px', backgroundColor: '#2563eb', color: 'white', borderRadius: '10px', border: 'none', cursor: 'pointer', fontWeight: 'bold' }}>
            {loading ? "SCANNING..." : "START SCAN"}
          </button>
        </div>
      </center>

      {data && (
        <div style={{ maxWidth: '800px', margin: '40px auto' }}>
          <div style={{ background: '#1e293b', padding: '30px', borderRadius: '20px', textAlign: 'center', border: '1px solid #334155' }}>
            <h2>Security Score: <span style={{ color: '#22c55e' }}>{data.score}%</span></h2>
            <p style={{ color: '#94a3b8' }}>Open Ports: {data.ports.join(', ')}</p>
          </div>
          {data.findings.map((f, i) => (
            <div key={i} style={{ background: '#0f172a', border: '1px solid #334155', padding: '20px', borderRadius: '15px', marginTop: '15px' }}>
              <h3 style={{ margin: 0, color: f.severity === 'CRITICAL' ? '#ef4444' : '#fbbf24' }}>{f.name}</h3>
              <p style={{ color: '#94a3b8' }}><strong>Solution:</strong> {f.solution}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}