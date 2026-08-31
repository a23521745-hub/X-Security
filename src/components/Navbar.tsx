import React, { useState, useEffect } from 'react';
import { Shield, Github, Globe, Menu, X, Download } from 'lucide-react';
import { useLanguage } from '../hooks/useLanguage';

export const Navbar: React.FC = () => {
  const { lang, toggleLang, t } = useLanguage();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 30);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { href: '#threat', label: t.nav_threat },
    { href: '#engine', label: t.nav_engine },
    { href: '#privacy', label: t.nav_privacy },
    { href: '#pipeline', label: t.nav_pipeline },
    { href: '#roadmap', label: t.nav_roadmap },
    { href: '#faq', label: t.nav_faq },
  ];

  return (
    <header className={`fixed top-0 left-0 right-0 z-40 transition-all duration-300 ${
      scrolled 
        ? 'py-3 bg-background/80 backdrop-blur-xl border-b border-white/10 shadow-2xl' 
        : 'py-5 bg-transparent'
    }`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        
        {/* Brand Logo */}
        <a href="#hero" className="flex items-center gap-3 group" aria-label="X-Security Home">
          <div className="relative p-2 rounded-xl border border-cyan/30 bg-cyan/10 text-cyan group-hover:shadow-cyber-cyan transition-all duration-300">
            <Shield className="w-5 h-5" />
            <div className="absolute inset-0 rounded-xl bg-cyan/20 opacity-0 group-hover:opacity-100 blur transition-opacity" />
          </div>
          <div className="flex flex-col">
            <span className="font-display font-bold text-lg tracking-wider text-white group-hover:text-cyan transition-colors">
              X-SECURITY
            </span>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald animate-ping" />
              <span className="text-[10px] font-mono tracking-widest text-emerald uppercase font-medium">
                {t.nav_status}
              </span>
            </div>
          </div>
        </a>

        {/* Desktop Nav Links */}
        <nav className="hidden lg:flex items-center gap-6" aria-label="Primary Navigation">
          {navLinks.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="text-xs font-mono uppercase tracking-wider text-cyber-slate hover:text-cyan transition-colors relative py-1 group"
            >
              {link.label}
              <span className="absolute bottom-0 left-0 w-0 h-0.5 bg-gradient-to-r from-cyan to-emerald group-hover:w-full transition-all duration-300" />
            </a>
          ))}
        </nav>

        {/* Action Controls */}
        <div className="hidden sm:flex items-center gap-3">
          {/* Language Toggle */}
          <button
            onClick={toggleLang}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-white/10 bg-white/5 hover:border-cyan/40 text-xs font-mono text-cyber-light hover:text-cyan transition-all duration-200"
            aria-label={lang === 'tr' ? 'Switch language to English' : 'Dili Türkçeye çevir'}
          >
            <Globe className="w-3.5 h-3.5 text-cyan" />
            <span>{t.nav_lang_toggle}</span>
          </button>

          {/* GitHub Source Link */}
          <a
            href="https://github.com/a23521745-hub/X-Security"
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 rounded-lg border border-white/10 bg-white/5 hover:border-white/30 text-cyber-light hover:text-white transition-all duration-200"
            aria-label="View source repository on GitHub"
          >
            <Github className="w-4 h-4" />
          </a>

          {/* Download CTA Button */}
          <a
            href="#download"
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg font-display text-xs font-bold tracking-wider uppercase text-background bg-gradient-to-r from-cyan to-emerald hover:shadow-cyber-cyan hover:scale-[1.02] active:scale-[0.98] transition-all duration-200"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{t.nav_download}</span>
          </a>
        </div>

        {/* Mobile Hamburger Button */}
        <div className="flex sm:hidden items-center gap-2">
          <button
            onClick={toggleLang}
            className="px-2.5 py-1 rounded border border-white/10 text-xs font-mono text-cyan"
          >
            {t.nav_lang_toggle}
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-lg border border-white/10 text-cyber-light"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="sm:hidden border-b border-white/10 bg-background/95 backdrop-blur-2xl px-6 py-6 space-y-4 animate-in fade-in slide-in-from-top-4">
          <nav className="flex flex-col gap-3">
            {navLinks.map((link) => (
              <a
                key={link.href}
                href={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className="text-sm font-mono tracking-wider text-cyber-slate hover:text-cyan py-2 border-b border-white/5"
              >
                {link.label}
              </a>
            ))}
          </nav>
          <div className="pt-2 flex flex-col gap-3">
            <a
              href="https://github.com/a23521745-hub/X-Security"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg border border-white/10 text-sm font-mono text-cyber-light hover:bg-white/5"
            >
              <Github className="w-4 h-4" />
              <span>GitHub</span>
            </a>
            <a
              href="#download"
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-center gap-2 w-full py-2.5 rounded-lg text-sm font-bold uppercase text-background bg-gradient-to-r from-cyan to-emerald"
            >
              <Download className="w-4 h-4" />
              <span>{t.nav_download}</span>
            </a>
          </div>
        </div>
      )}
    </header>
  );
};
