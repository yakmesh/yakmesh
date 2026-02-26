/**
 * YAKMESH Documentation - Interactive JavaScript
 * 
 * Handles:
 * - Sidebar toggle (desktop & mobile)
 * - Theme initialization
 * - Active link highlighting
 * - Dashboard button visibility (localhost only)
 */

document.addEventListener('DOMContentLoaded', function() {
  initDashboardButton();
  initSidebar();
  initActiveLinks();
  initParticles();
});

/**
 * Dashboard Button - Only show on localhost (self-hosted docs)
 * Hide on production website (yakmesh.dev)
 */
function initDashboardButton() {
  const dashboardLink = document.querySelector('.sidebar-dashboard-link');
  if (!dashboardLink) return;
  
  const isLocalhost = window.location.hostname === 'localhost' || 
                      window.location.hostname === '127.0.0.1' ||
                      window.location.hostname.startsWith('192.168.') ||
                      window.location.hostname.startsWith('10.') ||
                      window.location.protocol === 'file:';
  
  if (!isLocalhost) {
    dashboardLink.style.display = 'none';
  }
}

/**
 * Sidebar Toggle (works on all screen sizes)
 * Desktop: icon-only collapsed mode
 * Mobile: slide-in overlay mode
 */
function initSidebar() {
  const sidebar = document.getElementById('sidebar') || document.querySelector('.docs-sidebar');
  const toggle = document.getElementById('sidebarToggle') || document.querySelector('.sidebar-toggle');
  const overlay = document.getElementById('sidebarOverlay') || document.querySelector('.sidebar-overlay');
  const main = document.getElementById('mainContent') || document.querySelector('.docs-main');
  
  if (!sidebar || !toggle) return;
  
  // Check if we're on mobile
  const isMobile = () => window.innerWidth <= 900;
  
  // Desktop: check for saved preference
  if (!isMobile()) {
    const savedState = localStorage.getItem('sidebar-collapsed');
    if (savedState === 'true') {
      sidebar.classList.add('icon-only');
      toggle.classList.add('collapsed');
      if (main) main.classList.add('sidebar-collapsed');
    }
  }
  
  // Toggle sidebar
  toggle.addEventListener('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    
    if (isMobile()) {
      // Mobile: slide in/out overlay style
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('open');
      toggle.classList.toggle('sidebar-open');
      document.body.classList.toggle('sidebar-mobile-open');
    } else {
      // Desktop: icon-only collapse/expand
      sidebar.classList.toggle('icon-only');
      toggle.classList.toggle('collapsed');
      if (main) main.classList.toggle('sidebar-collapsed');
      
      // Save preference
      localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('icon-only'));
    }
  });
  
  // Close on overlay click (mobile only)
  if (overlay) {
    overlay.addEventListener('click', function() {
      closeMobileSidebar();
    });
  }
  
  // Close on escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && sidebar.classList.contains('open')) {
      closeMobileSidebar();
    }
  });
  
  // Close sidebar when clicking a link (mobile only)
  sidebar.querySelectorAll('a').forEach(function(link) {
    link.addEventListener('click', function() {
      if (isMobile() && sidebar.classList.contains('open')) {
        closeMobileSidebar();
      }
    });
  });
  
  // Handle resize - close mobile sidebar if resizing to desktop
  window.addEventListener('resize', function() {
    if (!isMobile() && sidebar.classList.contains('open')) {
      closeMobileSidebar();
    }
  });
  
  function closeMobileSidebar() {
    sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('open');
    toggle.classList.remove('sidebar-open');
    document.body.classList.remove('sidebar-mobile-open');
  }
}

/**
 * Highlight current page in sidebar
 */
function initActiveLinks() {
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  const links = document.querySelectorAll('.docs-sidebar a');
  
  links.forEach(function(link) {
    const href = link.getAttribute('href');
    if (href === currentPage || (currentPage === '' && href === 'index.html')) {
      link.classList.add('active');
    }
  });
}

/**
 * SVG Icons
 */
function getMenuIcon() {
  return '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>';
}

function getCloseIcon() {
  return '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>';
}

/**
 * Smooth scroll for anchor links
 */
document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
  anchor.addEventListener('click', function(e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

/* ============================================
   PARTICLE SYSTEM — Themed floating particles
   Reads data-theme and spawns unique particles.
   ============================================ */

/**
 * Theme → Particle configuration map.
 * shape: CSS class suffix (dot default, snowflake, ring, ember, smoke, leaf, spark, hex, triangle)
 * count: number of particles (6-12)
 * colors: array of CSS color strings
 * glows: matching glow rgba
 * sizes: [min, max] px
 * pulse: [min, max] seconds
 * drift: 'drift'|'fall'|'rise'|'orbit' — animation family
 * max: max opacity (0-1)
 */
var PARTICLE_THEMES = {
  // ─── Protocol Stack ────────────────────────────────────

  'jhilke': {
    shape: '', count: 12,
    colors: ['#a3e635', '#4ade80', '#86efac'],
    glows: ['rgba(163,230,53,0.3)', 'rgba(74,222,128,0.3)', 'rgba(134,239,172,0.3)'],
    sizes: [4, 8], pulse: [2.5, 5], drift: 'drift', max: 0.9
  },
  'annex': {
    shape: '', count: 8,
    colors: ['#60a5fa', '#93c5fd', '#3b82f6'],
    glows: ['rgba(96,165,250,0.3)', 'rgba(147,197,253,0.25)', 'rgba(59,130,246,0.3)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'drift', max: 0.8
  },
  'nakpak': {
    shape: 'ym-ring', count: 8,
    colors: ['#a78bfa', '#c4b5fd', '#8b5cf6'],
    glows: ['rgba(167,139,250,0.3)', 'rgba(196,181,253,0.25)', 'rgba(139,92,246,0.3)'],
    sizes: [6, 10], pulse: [3, 5], drift: 'drift', max: 0.7
  },
  'sherpa': {
    shape: 'ym-snowflake', count: 10,
    colors: ['#22d3ee', '#67e8f9', '#a5f3fc'],
    glows: ['rgba(34,211,238,0.3)', 'rgba(103,232,249,0.25)', 'rgba(165,243,252,0.2)'],
    sizes: [6, 10], pulse: [4, 7], drift: 'fall', max: 0.75
  },
  'doko': {
    shape: 'ym-leaf', count: 7,
    colors: ['#fbbf24', '#a16207', '#d97706'],
    glows: ['rgba(251,191,36,0.25)', 'rgba(161,98,7,0.2)', 'rgba(217,119,6,0.25)'],
    sizes: [5, 9], pulse: [4, 7], drift: 'fall', max: 0.7
  },
  'mandala': {
    shape: '', count: 10,
    colors: ['#2dd4bf', '#14b8a6', '#5eead4'],
    glows: ['rgba(45,212,191,0.3)', 'rgba(20,184,166,0.25)', 'rgba(94,234,212,0.2)'],
    sizes: [4, 6], pulse: [3, 5], drift: 'orbit', max: 0.8
  },
  'mantra': {
    shape: 'ym-ember', count: 9,
    colors: ['#fdba74', '#f97316', '#fb923c'],
    glows: ['rgba(253,186,116,0.3)', 'rgba(249,115,22,0.25)', 'rgba(251,146,60,0.3)'],
    sizes: [3, 7], pulse: [1.5, 3], drift: 'rise', max: 0.85
  },
  'gumba': {
    shape: 'ym-smoke', count: 7,
    colors: ['rgba(251,191,36,0.35)', 'rgba(217,119,6,0.3)', 'rgba(245,158,11,0.25)'],
    glows: ['rgba(251,191,36,0.08)'],
    sizes: [10, 20], pulse: [5, 9], drift: 'rise', max: 0.35
  },
  'yurt': {
    shape: 'ym-ember', count: 10,
    colors: ['#fb923c', '#ef4444', '#f97316'],
    glows: ['rgba(251,146,60,0.3)', 'rgba(239,68,68,0.25)', 'rgba(249,115,22,0.3)'],
    sizes: [3, 6], pulse: [1, 2.5], drift: 'rise', max: 0.9
  },
  'katha': {
    shape: '', count: 7,
    colors: ['#facc15', '#fde68a', '#eab308'],
    glows: ['rgba(250,204,21,0.25)', 'rgba(253,230,138,0.2)', 'rgba(234,179,8,0.25)'],
    sizes: [3, 6], pulse: [4, 7], drift: 'drift', max: 0.6
  },
  'vani': {
    shape: 'ym-ring', count: 8,
    colors: ['#f472b6', '#ec4899', '#f9a8d4'],
    glows: ['rgba(244,114,182,0.3)', 'rgba(236,72,153,0.25)', 'rgba(249,168,212,0.2)'],
    sizes: [8, 14], pulse: [2, 4], drift: 'drift', max: 0.5
  },
  'darshan': {
    shape: 'ym-spark', count: 7,
    colors: ['#c4b5fd', '#a78bfa', '#ddd6fe'],
    glows: ['rgba(196,181,253,0.3)', 'rgba(167,139,250,0.25)', 'rgba(221,214,254,0.2)'],
    sizes: [3, 6], pulse: [1, 2], drift: 'drift', max: 0.85
  },
  'stupa': {
    shape: 'ym-ember', count: 8,
    colors: ['#fde68a', '#fbbf24', '#f59e0b'],
    glows: ['rgba(253,230,138,0.3)', 'rgba(251,191,36,0.25)', 'rgba(245,158,11,0.3)'],
    sizes: [3, 7], pulse: [2, 4], drift: 'rise', max: 0.8
  },
  'lama': {
    shape: '', count: 7,
    colors: ['#c084fc', '#a855f7', '#d8b4fe'],
    glows: ['rgba(192,132,252,0.3)', 'rgba(168,85,247,0.25)', 'rgba(216,180,254,0.2)'],
    sizes: [5, 9], pulse: [4, 7], drift: 'drift', max: 0.7
  },
  'mani': {
    shape: 'ym-spark', count: 8,
    colors: ['#facc15', '#eab308', '#fde047'],
    glows: ['rgba(250,204,21,0.3)', 'rgba(234,179,8,0.25)', 'rgba(253,224,71,0.2)'],
    sizes: [3, 5], pulse: [1, 2.5], drift: 'drift', max: 0.8
  },
  'karma': {
    shape: '', count: 8,
    colors: ['#fb7185', '#e11d48', '#fda4af'],
    glows: ['rgba(251,113,133,0.3)', 'rgba(225,29,72,0.25)', 'rgba(253,164,175,0.2)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'drift', max: 0.7
  },
  'tattva': {
    shape: '', count: 9,
    colors: ['#c084fc', '#a855f7', '#e9d5ff'],
    glows: ['rgba(192,132,252,0.3)', 'rgba(168,85,247,0.25)', 'rgba(233,213,255,0.2)'],
    sizes: [3, 5], pulse: [2, 4], drift: 'drift', max: 0.85
  },
  'tribhuj': {
    shape: 'ym-triangle', count: 8,
    colors: ['#2dd4bf', '#14b8a6', '#5eead4'],
    glows: ['rgba(45,212,191,0.3)', 'rgba(20,184,166,0.25)', 'rgba(94,234,212,0.2)'],
    sizes: [6, 10], pulse: [3, 5], drift: 'drift', max: 0.7
  },
  'ypc27': {
    shape: '', count: 10,
    colors: ['#4ade80', '#22c55e', '#86efac'],
    glows: ['rgba(74,222,128,0.3)', 'rgba(34,197,94,0.25)', 'rgba(134,239,172,0.2)'],
    sizes: [2, 4], pulse: [0.8, 2], drift: 'fall', max: 0.9
  },
  'sakshi': {
    shape: 'ym-spark', count: 7,
    colors: ['#cbd5e1', '#94a3b8', '#e2e8f0'],
    glows: ['rgba(203,213,225,0.25)', 'rgba(148,163,184,0.2)', 'rgba(226,232,240,0.15)'],
    sizes: [3, 5], pulse: [1.5, 3], drift: 'drift', max: 0.7
  },
  'tivra': {
    shape: 'ym-spark', count: 9,
    colors: ['#22d3ee', '#06b6d4', '#67e8f9'],
    glows: ['rgba(34,211,238,0.35)', 'rgba(6,182,212,0.3)', 'rgba(103,232,249,0.25)'],
    sizes: [3, 6], pulse: [0.8, 1.8], drift: 'drift', max: 0.95
  },
  'prahari': {
    shape: '', count: 6,
    colors: ['#a78bfa', '#7c3aed', '#c4b5fd'],
    glows: ['rgba(167,139,250,0.3)', 'rgba(124,58,237,0.25)', 'rgba(196,181,253,0.2)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'drift', max: 0.65
  },
  'dharma': {
    shape: '', count: 7,
    colors: ['#fbbf24', '#d97706', '#fde68a'],
    glows: ['rgba(251,191,36,0.25)', 'rgba(217,119,6,0.2)', 'rgba(253,230,138,0.15)'],
    sizes: [5, 8], pulse: [4, 7], drift: 'drift', max: 0.6
  },
  'seva': {
    shape: '', count: 8,
    colors: ['#34d399', '#059669', '#6ee7b7'],
    glows: ['rgba(52,211,153,0.3)', 'rgba(5,150,105,0.25)', 'rgba(110,231,183,0.2)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'rise', max: 0.7
  },

  // ─── Applications & Reference ──────────────────────────

  'yakapp': {
    shape: '', count: 7,
    colors: ['#22d3ee', '#0891b2', '#67e8f9'],
    glows: ['rgba(34,211,238,0.3)', 'rgba(8,145,178,0.25)', 'rgba(103,232,249,0.2)'],
    sizes: [4, 7], pulse: [3, 5], drift: 'drift', max: 0.7
  },
  'c2c': {
    shape: 'ym-spark', count: 8,
    colors: ['#fb923c', '#ea580c', '#fdba74'],
    glows: ['rgba(251,146,60,0.3)', 'rgba(234,88,12,0.25)', 'rgba(253,186,116,0.2)'],
    sizes: [3, 5], pulse: [1, 2], drift: 'drift', max: 0.85
  },
  'studio': {
    shape: '', count: 8,
    colors: ['#f472b6', '#db2777', '#f9a8d4'],
    glows: ['rgba(244,114,182,0.3)', 'rgba(219,39,119,0.25)', 'rgba(249,168,212,0.2)'],
    sizes: [4, 7], pulse: [3, 5], drift: 'drift', max: 0.7
  },
  'thangka': {
    shape: '', count: 7,
    colors: ['#a78bfa', '#8b5cf6', '#c4b5fd'],
    glows: ['rgba(167,139,250,0.3)', 'rgba(139,92,246,0.25)', 'rgba(196,181,253,0.2)'],
    sizes: [4, 7], pulse: [4, 7], drift: 'drift', max: 0.65
  },

  // ─── Infrastructure & Utility ──────────────────────────

  'namche': {
    shape: '', count: 7,
    colors: ['#fde047', '#eab308', '#facc15'],
    glows: ['rgba(253,224,71,0.3)', 'rgba(234,179,8,0.25)', 'rgba(250,204,21,0.2)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'drift', max: 0.7
  },
  'getting-started': {
    shape: 'ym-ember', count: 7,
    colors: ['#fbbf24', '#f59e0b', '#fcd34d'],
    glows: ['rgba(251,191,36,0.3)', 'rgba(245,158,11,0.25)', 'rgba(252,211,77,0.2)'],
    sizes: [3, 6], pulse: [2, 4], drift: 'rise', max: 0.7
  },
  'yak-protocol': {
    shape: '', count: 6,
    colors: ['#f59e0b', '#b45309', '#fbbf24'],
    glows: ['rgba(245,158,11,0.3)', 'rgba(180,83,9,0.25)', 'rgba(251,191,36,0.2)'],
    sizes: [5, 8], pulse: [4, 7], drift: 'drift', max: 0.6
  },
  'geo-proof': {
    shape: 'ym-ring', count: 6,
    colors: ['#34d399', '#10b981', '#6ee7b7'],
    glows: ['rgba(52,211,153,0.25)', 'rgba(16,185,129,0.2)', 'rgba(110,231,183,0.15)'],
    sizes: [8, 14], pulse: [3, 5], drift: 'drift', max: 0.5
  },
  'mesh': {
    shape: '', count: 8,
    colors: ['#2dd4bf', '#14b8a6', '#5eead4'],
    glows: ['rgba(45,212,191,0.3)', 'rgba(20,184,166,0.25)', 'rgba(94,234,212,0.2)'],
    sizes: [3, 5], pulse: [2, 4], drift: 'drift', max: 0.75
  },
  'trust-security': {
    shape: 'ym-hex', count: 7,
    colors: ['#10b981', '#047857', '#34d399'],
    glows: ['rgba(16,185,129,0.3)', 'rgba(4,120,87,0.25)', 'rgba(52,211,153,0.2)'],
    sizes: [6, 10], pulse: [3, 5], drift: 'drift', max: 0.6
  },
  'advanced-systems': {
    shape: 'ym-spark', count: 8,
    colors: ['#22d3ee', '#a78bfa', '#67e8f9'],
    glows: ['rgba(34,211,238,0.3)', 'rgba(167,139,250,0.25)', 'rgba(103,232,249,0.2)'],
    sizes: [3, 5], pulse: [1, 2.5], drift: 'drift', max: 0.8
  },
  'cli': {
    shape: '', count: 6,
    colors: ['#4ade80', '#22c55e', '#86efac'],
    glows: ['rgba(74,222,128,0.3)', 'rgba(34,197,94,0.25)', 'rgba(134,239,172,0.2)'],
    sizes: [2, 4], pulse: [1, 3], drift: 'fall', max: 0.8
  },
  'time-sources': {
    shape: 'ym-ring', count: 6,
    colors: ['#fcd34d', '#fbbf24', '#fde68a'],
    glows: ['rgba(252,211,77,0.25)', 'rgba(251,191,36,0.2)', 'rgba(253,230,138,0.15)'],
    sizes: [8, 12], pulse: [2, 4], drift: 'drift', max: 0.5
  },
  'configuration': {
    shape: '', count: 5,
    colors: ['#d4d4d8', '#a1a1aa', '#e4e4e7'],
    glows: ['rgba(212,212,216,0.2)', 'rgba(161,161,170,0.15)', 'rgba(228,228,231,0.1)'],
    sizes: [3, 5], pulse: [4, 8], drift: 'drift', max: 0.45
  },
  'adapters': {
    shape: '', count: 7,
    colors: ['#fb923c', '#f97316', '#fdba74'],
    glows: ['rgba(251,146,60,0.3)', 'rgba(249,115,22,0.25)', 'rgba(253,186,116,0.2)'],
    sizes: [4, 7], pulse: [3, 5], drift: 'drift', max: 0.7
  },
  'webserver': {
    shape: '', count: 6,
    colors: ['#38bdf8', '#0ea5e9', '#7dd3fc'],
    glows: ['rgba(56,189,248,0.3)', 'rgba(14,165,233,0.25)', 'rgba(125,211,252,0.2)'],
    sizes: [4, 6], pulse: [3, 5], drift: 'drift', max: 0.65
  },
  'api': {
    shape: '', count: 5,
    colors: ['#94a3b8', '#64748b', '#cbd5e1'],
    glows: ['rgba(148,163,184,0.2)', 'rgba(100,116,139,0.15)', 'rgba(203,213,225,0.1)'],
    sizes: [3, 5], pulse: [4, 8], drift: 'drift', max: 0.4
  },
  'tutorials': {
    shape: '', count: 6,
    colors: ['#34d399', '#10b981', '#6ee7b7'],
    glows: ['rgba(52,211,153,0.25)', 'rgba(16,185,129,0.2)', 'rgba(110,231,183,0.15)'],
    sizes: [4, 7], pulse: [3, 6], drift: 'drift', max: 0.6
  },
  'reference': {
    shape: 'ym-spark', count: 6,
    colors: ['#fbbf24', '#f59e0b', '#fcd34d'],
    glows: ['rgba(251,191,36,0.3)', 'rgba(245,158,11,0.25)', 'rgba(252,211,77,0.2)'],
    sizes: [3, 5], pulse: [1.5, 3], drift: 'drift', max: 0.7
  },
  'docs-bundle': {
    shape: '', count: 6,
    colors: ['#fbbf24', '#f59e0b', '#fcd34d'],
    glows: ['rgba(251,191,36,0.25)', 'rgba(245,158,11,0.2)', 'rgba(252,211,77,0.15)'],
    sizes: [4, 7], pulse: [4, 7], drift: 'drift', max: 0.55
  }
};

/**
 * Spawn themed particles based on page data-theme.
 * Reads the <html data-theme="xxx"> attribute.
 */
function initParticles() {
  // Respect reduced-motion preference
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    return;
  }

  var theme = document.documentElement.getAttribute('data-theme') || '';
  var config = PARTICLE_THEMES[theme];
  if (!config) return;

  // Build container
  var container = document.createElement('div');
  container.className = 'ym-particles-container';
  container.setAttribute('aria-hidden', 'true');

  var driftCount = 8;
  var fallCount = 3;
  var riseCount = 3;

  for (var i = 0; i < config.count; i++) {
    var el = document.createElement('div');
    var classes = 'ym-particle';
    if (config.shape) classes += ' ' + config.shape;
    el.className = classes;

    // Randomize from palette
    var ci = i % config.colors.length;
    var color = config.colors[ci];
    var glow = config.glows[ci % config.glows.length];
    var size = randBetween(config.sizes[0], config.sizes[1]);
    var pulse = randBetween(config.pulse[0], config.pulse[1]).toFixed(1);
    var delay = (Math.random() * parseFloat(pulse)).toFixed(1);
    var maxOpacity = (config.max * (0.6 + Math.random() * 0.4)).toFixed(2);

    // Position
    el.style.left = randBetween(5, 95) + '%';
    el.style.top = randBetween(10, 90) + '%';

    // CSS custom props
    el.style.setProperty('--p-size', size + 'px');
    el.style.setProperty('--p-color', color);
    el.style.setProperty('--p-glow', glow);
    el.style.setProperty('--p-glow-far', glow.replace(/[\d.]+\)$/, '0.08)'));
    el.style.setProperty('--p-pulse', pulse + 's');
    el.style.setProperty('--p-max', maxOpacity);

    // Drift animation
    var driftDuration = randBetween(15, 35).toFixed(0);
    var driftDelay = randBetween(0, 10).toFixed(1);
    var animName;
    if (config.drift === 'fall') {
      animName = 'ym-fall-' + ((i % fallCount) + 1);
      el.style.top = '-5%';
      driftDuration = randBetween(12, 25).toFixed(0);
    } else if (config.drift === 'rise') {
      animName = 'ym-rise-' + ((i % riseCount) + 1);
      el.style.top = '100%';
      driftDuration = randBetween(14, 28).toFixed(0);
    } else if (config.drift === 'orbit') {
      animName = 'ym-orbit';
      el.style.left = '50%';
      el.style.top = '50%';
      driftDuration = randBetween(20, 40).toFixed(0);
    } else {
      animName = 'ym-drift-' + ((i % driftCount) + 1);
    }
    el.style.animation = animName + ' ' + driftDuration + 's ease-in-out ' + driftDelay + 's infinite';

    // Inner dot
    var dot = document.createElement('span');
    dot.className = 'ym-dot';
    dot.style.animationDelay = delay + 's';
    el.appendChild(dot);

    // Halo (skip for smoke & some shapes)
    if (config.shape !== 'ym-smoke' && config.shape !== 'ym-ring') {
      var halo = document.createElement('span');
      halo.className = 'ym-halo';
      halo.style.animationDelay = delay + 's';
      el.appendChild(halo);
    }

    container.appendChild(el);
  }

  document.body.appendChild(container);
}

/** Random float between min and max */
function randBetween(min, max) {
  return min + Math.random() * (max - min);
}
