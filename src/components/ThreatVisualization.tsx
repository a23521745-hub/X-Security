import React, { useState, useEffect } from 'react';
import { 
  MessageSquare, 
  MapPin, 
  Mic, 
  Play, 
  RotateCcw, 
  FileCode, 
  Binary, 
  Hash, 
  FolderArchive, 
  CheckCircle2, 
  AlertTriangle,
  Layers,
  ArrowRight
} from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const ThreatVisualization: React.FC = () => {
  const { t } = useLanguage();
  const [activeStep, setActiveStep] = useState<number>(0);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<'clean' | 'threat' | null>(null);

  const threatVectors = [
    {
      icon: MessageSquare,
      title: t.threat_card_msg_title,
      desc: t.threat_card_msg_desc,
    },
    {
      icon: MapPin,
      title: t.threat_card_loc_title,
      desc: t.threat_card_loc_desc,
    },
    {
      icon: Mic,
      title: t.threat_card_mic_title,
      desc: t.threat_card_mic_desc,
    },
  ];

  const pipelineStages = [
    { id: 1, label: t.sim_step_apk, icon: FileCode },
    { id: 2, label: t.sim_step_yara, icon: Layers },
    { id: 3, label: t.sim_step_clamav, icon: Binary },
    { id: 4, label: t.sim_step_hash, icon: Hash },
    { id: 5, label: t.sim_step_zip, icon: FolderArchive },
    { id: 6, label: t.sim_step_result, icon: AlertTriangle },
  ];

  const runSimulation = () => {
    setIsScanning(true);
    setActiveStep(1);
    setScanResult(null);

    const stepInterval = setInterval(() => {
      setActiveStep((prev) => {
        if (prev >= 5) {
          clearInterval(stepInterval);
          setIsScanning(false);
          setScanResult('threat');
          return 6;
        }
        return prev + 1;
      });
    }, 700);
  };

  const resetSimulation = () => {
    setIsScanning(false);
    setActiveStep(0);
    setScanResult(null);
  };

  return (
    <section id="threat" className="py-24 relative overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-danger/30 bg-danger/10 text-danger text-xs font-mono tracking-wider uppercase">
            <span className="w-1.5 h-1.5 rounded-full bg-danger animate-pulse" />
            <span>{t.threat_badge}</span>
          </div>
          <h2 className="font-display font-bold text-3xl sm:text-4xl text-white tracking-tight">
            {t.threat_title}
          </h2>
          <p className="text-cyber-slate text-sm sm:text-base leading-relaxed">
            {t.threat_desc}
          </p>
        </div>

        {/* Threat Vector Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12">
          {threatVectors.map((item, idx) => {
            const Icon = item.icon;
            return (
              <div 
                key={idx} 
                className="glass-panel-danger p-6 rounded-2xl relative overflow-hidden group hover:border-danger/50 transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-xl bg-danger/10 border border-danger/30 text-danger flex items-center justify-center mb-4 group-hover:scale-110 group-hover:shadow-cyber-danger transition-all duration-300">
                  <Icon className="w-6 h-6" />
                </div>
                <h3 className="font-display font-semibold text-lg text-white mb-2">
                  {item.title}
                </h3>
                <p className="text-xs sm:text-sm text-cyber-slate leading-relaxed">
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>

        {/* Interactive Threat Visualizer Simulator */}
        <div className="mt-16 glass-panel-glow p-6 sm:p-8 rounded-3xl border border-cyan/20 relative overflow-hidden">
          
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/10 pb-6">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan animate-pulse" />
                <h3 className="font-display font-bold text-xl text-white">{t.sim_title}</h3>
              </div>
              <p className="text-xs sm:text-sm text-cyber-slate mt-1">{t.sim_subtitle}</p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={runSimulation}
                disabled={isScanning}
                className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-display font-semibold text-xs uppercase tracking-wider text-background bg-gradient-to-r from-cyan to-emerald hover:shadow-cyber-cyan disabled:opacity-50 transition-all duration-200"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{t.sim_btn_start}</span>
              </button>

              <button
                onClick={resetSimulation}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl font-display text-xs text-cyber-light border border-white/10 hover:bg-white/5 transition-all duration-200"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>{t.sim_btn_reset}</span>
              </button>
            </div>
          </div>

          {/* Interactive Pipeline Stages */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4 my-8">
            {pipelineStages.map((stage) => {
              const Icon = stage.icon;
              const isCurrent = activeStep === stage.id;
              const isPassed = activeStep > stage.id;

              return (
                <div
                  key={stage.id}
                  className={`p-4 rounded-xl border flex flex-col items-center text-center gap-3 transition-all duration-300 ${
                    isCurrent
                      ? 'border-cyan bg-cyan/15 text-cyan shadow-cyber-cyan scale-105 animate-pulse'
                      : isPassed
                      ? 'border-emerald/40 bg-emerald/10 text-emerald'
                      : 'border-white/5 bg-white/[0.02] text-cyber-muted'
                  }`}
                >
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-black/40 border border-current">
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="font-mono text-xs font-medium leading-tight">
                    {stage.label}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Simulator Status Terminal */}
          <div className="bg-black/60 rounded-xl p-4 border border-white/10 font-mono text-xs space-y-2">
            <div className="flex items-center justify-between text-cyber-muted border-b border-white/5 pb-2">
              <span className="text-[10px] uppercase tracking-widest text-cyan">SECURITY_SANDBOX_LOG</span>
              <span>STATE: {isScanning ? 'ANALYZING' : scanResult ? 'VERDICT_READY' : 'STANDBY'}</span>
            </div>

            <div className="min-h-[40px] flex items-center text-sm">
              {activeStep === 0 && (
                <span className="text-cyber-muted">{'>'} Hazır. Taramayı başlatmak için yukarıdaki butona tıklayın.</span>
              )}
              {isScanning && (
                <span className="text-cyan animate-pulse">
                  {'>'} Katman {activeStep} devrede: Analiz yapılıyor... [AES-256 Memory Guard ACTIVE]
                </span>
              )}
              {scanResult === 'threat' && (
                <div className="flex items-center gap-2 text-danger font-semibold">
                  <AlertTriangle className="w-4 h-4" />
                  <span>{t.sim_status_threat} (Echap Stalkerware Signature Match: SHA-256)</span>
                </div>
              )}
            </div>
          </div>

          {/* Explicit Demonstration Disclaimer */}
          <div className="mt-4 text-center">
            <span className="text-[11px] font-mono text-cyber-muted tracking-wide">
              {t.sim_disclaimer}
            </span>
          </div>

        </div>

      </div>
    </section>
  );
};
