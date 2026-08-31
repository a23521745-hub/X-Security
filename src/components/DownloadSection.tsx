import React, { useEffect, useRef, useState } from 'react';
import { Download, QrCode, ExternalLink, ShieldCheck, Smartphone } from 'lucide-react';
import qrcode from 'qrcode-generator';
import { useLanguage } from '../hooks/useLanguage';

export const DownloadSection: React.FC = () => {
  const { t } = useLanguage();
  const [qrSvg, setQrSvg] = useState<string>('');
  const releaseUrl = 'https://github.com/a23521745-hub/X-Security/releases/latest';

  useEffect(() => {
    try {
      const qr = qrcode(0, 'M');
      qr.addData(releaseUrl);
      qr.make();
      const count = qr.getModuleCount();
      const cellSize = 5;
      const margin = 2;
      const size = (count + margin * 2) * cellSize;

      let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" class="w-full h-full" shape-rendering="crispEdges">`;
      svg += `<rect width="${size}" height="${size}" fill="#ffffff" rx="12"/>`;

      for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
          if (qr.isDark(row, col)) {
            svg += `<rect x="${(col + margin) * cellSize}" y="${(row + margin) * cellSize}" width="${cellSize}" height="${cellSize}" fill="#05070d"/>`;
          }
        }
      }
      svg += '</svg>';
      setQrSvg(svg);
    } catch (e) {
      console.warn('QR Code generation failed, fallback enabled:', e);
    }
  }, [releaseUrl]);

  return (
    <section id="download" className="py-24 relative overflow-hidden">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        <div className="glass-panel-glow p-8 sm:p-14 rounded-3xl border border-cyan/30 text-center relative overflow-hidden space-y-8">
          
          {/* Background Ambient Glow */}
          <div className="absolute -top-32 -left-32 w-64 h-64 bg-cyan/20 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute -bottom-32 -right-32 w-64 h-64 bg-emerald/20 rounded-full blur-3xl pointer-events-none" />

          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan/30 bg-cyan/10 text-cyan text-xs font-mono tracking-wider uppercase">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{t.download_badge}</span>
          </div>

          {/* Title */}
          <h2 className="font-display font-extrabold text-3xl sm:text-5xl text-white tracking-tight">
            {t.download_title}
          </h2>

          <p className="text-cyber-slate text-sm sm:text-base max-w-xl mx-auto leading-relaxed">
            {t.download_desc}
          </p>

          {/* Download Buttons & QR Presentation Grid */}
          <div className="flex flex-col md:flex-row items-center justify-center gap-8 pt-4">
            
            {/* Primary Action Button */}
            <div className="space-y-4 text-center md:text-left">
              <a
                href={releaseUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center justify-center gap-3 px-8 py-4 rounded-2xl font-display font-bold text-base uppercase tracking-wider text-background bg-gradient-to-r from-cyan via-teal-400 to-emerald hover:shadow-cyber-cyan hover:scale-105 active:scale-95 transition-all duration-300 shadow-xl"
              >
                <Download className="w-5 h-5" />
                <span>{t.download_btn_release}</span>
              </a>

              <div className="flex items-center justify-center md:justify-start gap-4 text-xs font-mono text-cyber-muted">
                <span className="flex items-center gap-1">
                  <Smartphone className="w-3.5 h-3.5 text-cyan" />
                  Android 8.0+
                </span>
                <span>•</span>
                <span>~6 MB APK</span>
                <span>•</span>
                <span className="text-emerald">GPL v3</span>
              </div>
            </div>

            {/* Client-Side QR Code Presentation */}
            <div className="p-4 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-xl flex flex-col items-center gap-3 shadow-2xl">
              <div className="w-36 h-36 rounded-xl overflow-hidden shadow-inner bg-white p-1.5 flex items-center justify-center">
                {qrSvg ? (
                  <div dangerouslySetInnerHTML={{ __html: qrSvg }} className="w-full h-full" />
                ) : (
                  <a
                    href={releaseUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-black text-center font-bold p-2"
                  >
                    {t.download_qr_fallback}
                  </a>
                )}
              </div>
              <span className="text-[11px] font-mono text-cyber-muted tracking-tight">
                {t.download_qr_label}
              </span>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
};
