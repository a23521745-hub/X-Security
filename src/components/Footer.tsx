import React from 'react';
import { Shield, Github, ExternalLink, Heart } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const Footer: React.FC = () => {
  const { t } = useLanguage();

  return (
    <footer className="border-t border-white/10 py-12 relative z-10 bg-background/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8">
        
        <div className="flex flex-col md:flex-row items-center justify-between gap-6 text-center md:text-left">
          
          {/* Brand */}
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl border border-cyan/30 bg-cyan/10 text-cyan">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <span className="font-display font-bold text-base text-white tracking-wider">
                X-SECURITY
              </span>
              <p className="text-xs text-cyber-muted font-mono">
                Open Source On-Device Android Threat Intelligence
              </p>
            </div>
          </div>

          {/* Links & Attributions */}
          <div className="flex flex-wrap items-center justify-center gap-6 text-xs font-mono text-cyber-slate">
            <a
              href="https://github.com/a23521745-hub/X-Security"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 hover:text-cyan transition-colors"
            >
              <Github className="w-4 h-4" />
              <span>{t.footer_open_source}</span>
            </a>

            <span className="text-white/20">•</span>

            <a
              href="https://github.com/AssoEchap/stalkerware-indicators"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 hover:text-emerald transition-colors"
            >
              <span>{t.footer_attribution}</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

        </div>

        {/* Love Note & Honest Disclaimer */}
        <div className="pt-6 border-t border-white/5 flex flex-col items-center justify-center gap-3 text-center text-xs text-cyber-muted font-mono">
          <div className="flex items-center gap-1.5">
            <span>Made with</span>
            <Heart className="w-3.5 h-3.5 text-danger fill-current" />
            <span>for Privacy — Free Forever</span>
          </div>

          <p className="max-w-2xl text-[11px] leading-relaxed text-cyber-muted/80">
            {t.footer_disclaimer}
          </p>
        </div>

      </div>
    </footer>
  );
};
