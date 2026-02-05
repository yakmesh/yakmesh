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
