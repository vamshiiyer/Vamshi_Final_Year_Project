import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Shield, Download, AlertTriangle, ShieldCheck, Target, Activity, Code, ChevronDown, ChevronUp } from 'lucide-react';

const API_BASE = 'http://127.0.0.1:8000';

function Radar({ themeColor }) {
  return (
    <div className="relative w-64 h-64 border rounded-full flex items-center justify-center overflow-hidden bg-black/50"
         style={{ borderColor: themeColor, boxShadow: `0 0 30px ${themeColor}33` }}>
      <div className="absolute inset-0 border rounded-full scale-75" style={{ borderColor: `${themeColor}4D` }} />
      <div className="absolute inset-0 border rounded-full scale-50" style={{ borderColor: `${themeColor}33` }} />
      <div className="absolute inset-0 border rounded-full scale-25" style={{ borderColor: `${themeColor}1A` }} />
      <div className="w-full h-[1px] absolute" style={{ backgroundColor: `${themeColor}4D` }} />
      <div className="h-full w-[1px] absolute" style={{ backgroundColor: `${themeColor}4D` }} />
      <motion.div
        className="absolute top-1/2 left-1/2 w-32 h-32 origin-top-left"
        style={{
          background: `conic-gradient(from 180deg at 0% 0%, rgba(0,0,0,0) 0%, ${themeColor} 100%)`,
          opacity: 0.6
        }}
        animate={{ rotate: 360 }}
        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
      />
      <Activity className="animate-pulse relative z-10" size={32} style={{ color: themeColor }} />
    </div>
  );
}

function App() {
  const [url, setUrl] = useState('');
  const [status, setStatus] = useState('idle'); // idle, scanning, result, error
  const [scanData, setScanData] = useState(null);
  const [displayScore, setDisplayScore] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [openDropdowns, setOpenDropdowns] = useState({});

  const toggleDropdown = (index) => {
    setOpenDropdowns(prev => ({ ...prev, [index]: !prev[index] }));
  };

  const getTheme = (score) => {
    if (score >= 90) return { color: '#10b981', label: 'EXCELLENT', class: 'text-emerald-500', border: 'border-emerald-500' };
    if (score >= 70) return { color: '#3b82f6', label: 'STABLE', class: 'text-blue-500', border: 'border-blue-500' };
    if (score >= 45) return { color: '#f59e0b', label: 'WARNING', class: 'text-amber-500', border: 'border-amber-500' };
    return { color: '#ef4444', label: 'CRITICAL', class: 'text-red-500', border: 'border-red-500' };
  };

  // We initially use the system target theme #FF0000 (red) pending scan
  const activeTheme = status === 'result' ? getTheme(displayScore) : getTheme(0);
  const themeHex = status === 'result' ? activeTheme.color : '#FF0000';

  const speakResult = (score, data) => {
    if ('speechSynthesis' in window) {
      setTimeout(() => {
        const msg = new SpeechSynthesisUtterance();
        
        let text = `Infrastructure audit complete. Final security health is ${score} percent.`;
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            // Find highest risk vulnerability
            const crit = data.vulnerabilities.find(v => v.severity === 'Critical' || v.severity === 'High') || data.vulnerabilities[0];
            text += ` Top critical risk found: ${crit.issue}, which ${crit.why.toLowerCase()}`;
        } else {
            text = `Infrastructure is fully optimized. Security Health is 100 percent.`;
        }
        
        msg.text = text;
        msg.rate = 1.0;
        
        let voices = window.speechSynthesis.getVoices();
        if (voices.length === 0) {
          window.speechSynthesis.onvoiceschanged = () => {
             voices = window.speechSynthesis.getVoices();
             setVoiceAndSpeak(msg, voices);
          };
        } else {
          setVoiceAndSpeak(msg, voices);
        }
      }, 1000);
    }
  };

  const setVoiceAndSpeak = (msg, voices) => {
    const voice = voices.find(v => 
      v.name.includes('Samantha') || 
      (v.name.includes('Google') && v.name.includes('US') && v.name.includes('Female')) ||
      v.name.includes('Victoria') ||
      v.name.includes('Karen') ||
      v.name.includes('Tessa')
    ) || voices.find(v => v.lang === 'en-US');
    if (voice) msg.voice = voice;
    
    window.speechSynthesis.speak(msg);
  };

  useEffect(() => {
    if (status === 'result' && scanData) {
      let currentScore = 0;
      const targetScore = scanData.score;
      if (targetScore === 0) {
          setDisplayScore(0);
          speakResult(0, scanData);
          return;
      }
      const interval = setInterval(() => {
        currentScore += 1;
        if (currentScore >= targetScore) {
          setDisplayScore(targetScore);
          clearInterval(interval);
          speakResult(targetScore, scanData);
        } else {
          setDisplayScore(currentScore);
        }
      }, 20);
      return () => clearInterval(interval);
    }
  }, [status, scanData]);

  const handleScan = async (e) => {
    if(e) e.preventDefault();
    if (!url) return;
    setStatus('scanning');
    setScanData(null);
    setDisplayScore(0);
    setErrorMsg('');
    setOpenDropdowns({});
    window.speechSynthesis.cancel();

    try {
      const res = await axios.post(`${API_BASE}/api/scan`, { url });
      setScanData(res.data);
      setTimeout(() => {
        setStatus('result');
      }, 1500); 
    } catch (err) {
      setStatus('error');
      setErrorMsg("CONNECTION ERROR: Target unreachable or connection violently dropped.");
    }
  };

  const handleDownload = async () => {
    if (!scanData) return;
    try {
      const res = await axios.post(`${API_BASE}/api/report`, scanData, {
        responseType: 'blob'
      });
      const downloadUrl = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement('a');
      link.href = downloadUrl;
      link.setAttribute('download', "SECURE_AI_REPORT.pdf");
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => window.URL.revokeObjectURL(downloadUrl), 100);
    } catch (err) {
      alert("Failed to extract report. Please try scanning again.");
    }
  };

  return (
    <div className="min-h-screen bg-background text-white font-mono flex flex-col items-center py-12 px-4 transition-colors duration-1000">
      {status === 'scanning' && <div className="laser-beam" style={{ backgroundColor: themeHex, boxShadow: `0 0 15px ${themeHex}, 0 0 30px ${themeHex}` }} />}
      
      <header className="mb-12 text-center">
        <h1 className="text-4xl md:text-5xl font-bold tracking-widest flex items-center justify-center gap-4 mb-2 transition-colors duration-1000" style={{ color: themeHex }}>
          <Terminal size={40} />
          SECURE.AI
        </h1>
        <p className="text-zinc-400 tracking-widest text-sm uppercase">Global Threat Intelligence Console</p>
      </header>

      <main className="w-full max-w-4xl flex flex-col items-center">
        <form onSubmit={handleScan} className="w-full mb-12 flex relative">
          <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none transition-colors duration-1000" style={{ color: themeHex }}>
            <Target size={20} />
          </div>
          <input
            type="text"
            className="w-full bg-card border-l-4 text-white py-4 pl-12 pr-32 focus:outline-none transition-colors duration-1000 shadow-xl"
            style={{ borderLeftColor: themeHex }}
            placeholder="ENTER TARGET DOMAIN OR IP..."
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={status === 'scanning'}
          />
          <button
            type="submit"
            className="absolute right-2 top-2 bottom-2 text-black font-bold px-6 uppercase transition-all duration-300 disabled:opacity-50"
            style={{ backgroundColor: themeHex }}
            disabled={status === 'scanning'}
          >
            {status === 'scanning' ? 'SCANNING' : 'INITIATE'}
          </button>
        </form>

        {status === 'idle' && (
          <div className="text-zinc-600 mt-20 text-center animate-pulse">
            <Shield size={64} className="mx-auto mb-4 opacity-20" />
            <p>SYSTEM STANDBY. AWAITING TARGET INPUT.</p>
          </div>
        )}

        {status === 'scanning' && (
          <div className="flex flex-col items-center mt-10">
            <Radar themeColor={themeHex} />
            <p className="mt-8 animate-pulse tracking-[0.2em] font-bold" style={{ color: themeHex }}>DEEP PACKET INSPECTION IN PROGRESS...</p>
          </div>
        )}

        {status === 'error' && (
          <div className="bg-card border p-6 w-full text-center shadow-2xl relative overflow-hidden" style={{ borderColor: themeHex }}>
            <AlertTriangle className="mx-auto mb-4" size={48} style={{ color: themeHex }} />
            <h2 className="text-2xl font-bold mb-2 uppercase" style={{ color: themeHex }}>CONNECTION ERROR</h2>
            <p className="text-zinc-400">{errorMsg}</p>
            <p className="text-xs text-zinc-600 mt-4">OPERATION TERMINATED.</p>
          </div>
        )}

        {status === 'result' && scanData && (
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`w-full bg-card border border-zinc-800 p-8 shadow-2xl relative overflow-hidden`}
          >
            {/* Header / Score */}
            <div className="flex flex-col md:flex-row justify-between items-center mb-10 pb-6 border-b border-zinc-800">
              <div>
                <h2 className="text-xl text-zinc-400 uppercase tracking-wider mb-1 text-center md:text-left">Target Authenticated</h2>
                <p className="text-2xl font-bold text-white break-all text-center md:text-left">{scanData.url}</p>
                <div className="mt-4 inline-block px-4 py-1 text-sm font-bold tracking-widest text-black" style={{ backgroundColor: themeHex }}>
                    SYSTEM: {activeTheme.label}
                </div>
              </div>
              <div className="mt-6 md:mt-0 flex flex-col items-center">
                <div className="relative">
                  <svg className="w-32 h-32 transform -rotate-90">
                    <circle cx="64" cy="64" r="58" stroke="currentColor" strokeWidth="6" fill="transparent" className="text-zinc-800" />
                    <circle 
                      cx="64" cy="64" r="58" stroke="currentColor" strokeWidth="6" fill="transparent" 
                      strokeDasharray={364.4}
                      strokeDashoffset={364.4 - (364.4 * displayScore) / 100}
                      className="transition-all duration-300"
                      style={{ color: themeHex }}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center flex-col">
                    <span className="text-4xl font-bold transition-colors duration-1000" style={{ color: themeHex }}>{displayScore}</span>
                  </div>
                </div>
                <p className="text-xs text-zinc-500 mt-2 tracking-widest uppercase">Health Index</p>
              </div>
            </div>

            {/* Missing Headers Log */}
            <div className="mb-8">
              <h3 className="text-lg text-white mb-4 flex items-center gap-2">
                <Terminal size={18} className="text-zinc-500"/> 
                VULNERABILITY LOGS
              </h3>
              {scanData.vulnerabilities.length === 0 ? (
                <div className="bg-zinc-900 border border-emerald-900/50 p-4 text-emerald-500 flex items-center gap-3">
                  <ShieldCheck size={24} />
                  <p>All required security measures present. Target infrastructure operating at high efficiency.</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {scanData.vulnerabilities.map((vuln, idx) => (
                    <div key={idx} className="bg-black border border-zinc-800 overflow-hidden flex flex-col">
                      <div className="bg-zinc-900/50 p-4 border-b border-zinc-800 flex justify-between items-center text-white">
                        <div className="flex items-center gap-3">
                          <AlertTriangle size={18} className={vuln.severity === 'Critical' ? 'text-red-500' : vuln.severity === 'High' ? 'text-amber-500' : 'text-zinc-400'} />
                          <span className="font-bold tracking-wider">{vuln.issue}</span>
                        </div>
                        <div className="flex items-center gap-4">
                            <span className="text-zinc-500 text-sm font-bold">-{vuln.points_deducted} PTS</span>
                        </div>
                      </div>
                      <div className="p-4 space-y-4">
                        <div className="flex justify-between items-center">
                          <p className={`text-xs uppercase tracking-widest font-bold ${vuln.severity === 'Critical' ? 'text-red-500' : vuln.severity === 'High' ? 'text-amber-500' : 'text-blue-400'}`}>
                            Severity: {vuln.severity}
                          </p>
                        </div>
                        <div>
                          <p className="text-zinc-500 text-xs mb-1 uppercase tracking-widest">The Risk</p>
                          <p className="text-zinc-300">{vuln.why}</p>
                        </div>
                        
                        <div className="mt-2">
                            <button 
                                onClick={() => toggleDropdown(idx)}
                                className="flex items-center w-full justify-between bg-zinc-900 hover:bg-zinc-800 p-3 rounded border border-zinc-800 transition-colors"
                            >
                                <span className="text-zinc-400 text-xs uppercase tracking-widest flex items-center gap-2">
                                    <Code size={14} /> How to Fix (Remediation)
                                </span>
                                {openDropdowns[idx] ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                            </button>
                            <AnimatePresence>
                                {openDropdowns[idx] && (
                                    <motion.div 
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        className="overflow-hidden"
                                    >
                                        <div className="bg-black border border-t-0 border-zinc-800 p-4">
                                            <code className="text-blue-400 text-sm break-all font-mono">
                                                {vuln.remediation}
                                            </code>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Action Bar */}
            <div className="mt-10 flex justify-center">
              <button 
                onClick={handleDownload}
                className="flex items-center gap-3 border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-white px-8 py-3 uppercase tracking-widest text-sm transition-all shadow-lg"
              >
                <Download size={18} />
                Extract Confidential Report
              </button>
            </div>
          </motion.div>
        )}
      </main>
    </div>
  );
}

export default App;
