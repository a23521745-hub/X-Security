/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#05070d',
        surface: {
          DEFAULT: '#0a0f1a',
          card: 'rgba(255, 255, 255, 0.03)',
          cardHover: 'rgba(255, 255, 255, 0.06)',
          elevated: '#0f172a',
        },
        cyan: {
          DEFAULT: '#22d3ee',
          dim: 'rgba(34, 211, 238, 0.15)',
          glow: 'rgba(34, 211, 238, 0.25)',
          border: 'rgba(34, 211, 238, 0.12)',
        },
        emerald: {
          DEFAULT: '#34d399',
          dim: 'rgba(52, 211, 153, 0.15)',
          glow: 'rgba(52, 211, 153, 0.25)',
          border: 'rgba(52, 211, 153, 0.15)',
        },
        danger: {
          DEFAULT: '#f43f5e',
          dim: 'rgba(244, 63, 94, 0.15)',
          glow: 'rgba(244, 63, 94, 0.25)',
          border: 'rgba(244, 63, 94, 0.2)',
        },
        cyber: {
          slate: '#94a3b8',
          muted: '#64748b',
          light: '#e2e8f0',
        }
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
        body: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 20s linear infinite',
        'float': 'float 6s ease-in-out infinite',
        'radar-sweep': 'sweep 3s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        sweep: {
          'from': { transform: 'rotate(0deg)' },
          'to': { transform: 'rotate(360deg)' },
        }
      },
      boxShadow: {
        'cyber-cyan': '0 0 30px rgba(34, 211, 238, 0.25)',
        'cyber-emerald': '0 0 30px rgba(52, 211, 153, 0.25)',
        'cyber-danger': '0 0 30px rgba(244, 63, 94, 0.25)',
      },
    },
  },
  plugins: [],
}
