#!/usr/bin/env node
/**
 * update-docs-nav.cjs - Update documentation navigation & sidebar
 * 
 * Reads docs/nav-order.json and updates:
 * 1. Sidebar navigation (consistent entries + section dividers)
 * 2. Journey Navigation cards (prev/next with icons and descriptions)
 * 3. Simple nav-footer links (fallback)
 * 
 * Usage: node scripts/update-docs-nav.cjs [--dry-run] [--verbose] [--sidebar-only] [--nav-only]
 */

const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'docs');
const NAV_ORDER_FILE = path.join(DOCS_DIR, 'nav-order.json');

// Parse args
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const VERBOSE = args.includes('--verbose');
const SIDEBAR_ONLY = args.includes('--sidebar-only');
const NAV_ONLY = args.includes('--nav-only');

function log(...msg) {
  if (VERBOSE) console.log(...msg);
}

function loadNavOrder() {
  const content = fs.readFileSync(NAV_ORDER_FILE, 'utf8');
  return JSON.parse(content).pages;
}

// Section labels for sidebar dividers
const SECTION_LABELS = {
  guide: '📘 Guides',
  protocol: '🐃 Protocol Stack',
  applications: '🚀 Applications',
  reference: '📋 Reference'
};

/**
 * Generate the canonical sidebar <li> entries from nav-order.json
 */
function generateSidebarEntries(pages, activeFile) {
  const lines = [];
  for (const page of pages) {
    // Section divider
    if (page.section && SECTION_LABELS[page.section]) {
      lines.push('      <li class="sidebar-section"><span>' + SECTION_LABELS[page.section] + '</span></li>');
    }
    // Active class
    const activeClass = (page.file === activeFile) ? ' class="active"' : '';
    // Special icon handling for yak-protocol (uses CSS class instead of emoji)
    const iconSpan = (page.file === 'yak-protocol.html')
      ? '<span class="yak-icon"></span>'
      : '<span>' + page.icon + '</span>';
    lines.push('      <li><a href="' + page.file + '"' + activeClass + '>' + iconSpan + ' <span>' + page.title + '</span></a></li>');
  }
  return lines.join('\n');
}

/**
 * Update sidebar navigation in a file
 */
function updateFileSidebar(filePath, pages) {
  let content = fs.readFileSync(filePath, 'utf8');
  const fileName = path.basename(filePath);
  
  // Match <ul class="sidebar-nav"> ... </ul>
  const sidebarPattern = /<ul class="sidebar-nav">\s*[\s\S]*?<\/ul>/;
  const match = content.match(sidebarPattern);
  if (!match) {
    log('  No sidebar-nav found in', fileName);
    return false;
  }
  
  const newSidebar = '<ul class="sidebar-nav">\n' + generateSidebarEntries(pages, fileName) + '\n    </ul>';
  content = content.replace(sidebarPattern, newSidebar);
  
  if (!DRY_RUN) {
    fs.writeFileSync(filePath, content, 'utf8');
  }
  return true;
}

/**
 * Generate Journey Navigation card HTML
 */
function generateJourneyCard(page, direction) {
  if (!page) return '';
  
  const borderClass = direction === 'prev' 
    ? 'border-mountain-700' 
    : 'border-theme-primary';
  const label = direction === 'prev' ? '← Previous' : 'Next →';
  
  return [
    '          <a href="' + page.file + '" class="flex-1 block bg-mountain-800 border ' + borderClass + ' rounded-xl p-4 hover:border-theme-accent transition group">',
    '            <div class="text-xs text-mountain-400 mb-1">' + label + '</div>',
    '            <div class="flex items-center gap-2">',
    '              <span class="text-xl">' + page.icon + '</span>',
    '              <span class="font-semibold group-hover:text-theme-accent">' + page.title + '</span>',
    '            </div>',
    '            <p class="text-mountain-400 text-sm mt-1">' + page.description + '</p>',
    '          </a>'
  ].join('\n');
}

/**
 * Generate Journey Navigation section
 */
function generateJourneyNav(prevPage, nextPage) {
  const cards = [];
  if (prevPage) cards.push(generateJourneyCard(prevPage, 'prev'));
  if (nextPage) cards.push(generateJourneyCard(nextPage, 'next'));
  
  return [
    '      <!-- Journey Navigation -->',
    '      <div class="border-t border-mountain-700 mt-12 pt-8">',
    '        <h2 class="text-xl font-bold mb-6">Continue the Journey</h2>',
    '        <div class="flex flex-col sm:flex-row gap-4">',
    cards.join('\n'),
    '        </div>',
    '      </div>'
  ].join('\n');
}

/**
 * Generate simple nav-footer HTML
 */
function generateNavFooter(prevPage, nextPage) {
  const links = [];
  if (prevPage) {
    links.push('        <a href="' + prevPage.file + '">← ' + prevPage.title + '</a>');
  }
  if (nextPage) {
    const mlAuto = prevPage ? ' class="ml-auto"' : '';
    links.push('        <a href="' + nextPage.file + '"' + mlAuto + '>' + nextPage.title + ' →</a>');
  }
  
  return [
    '      <!-- Navigation -->',
    '      <nav class="docs-nav-footer">',
    links.join('\n'),
    '      </nav>'
  ].join('\n');
}

/**
 * Update navigation in a single file
 */
function updateFileNav(filePath, prevPage, nextPage) {
  let content = fs.readFileSync(filePath, 'utf8');
  const fileName = path.basename(filePath);
  let modified = false;
  
  // Pattern 1: Journey Navigation cards
  const journeyPattern = /<!-- Journey Navigation -->.*?<\/div>\s*<\/div>\s*<\/div>/s;
  if (journeyPattern.test(content)) {
    const newNav = generateJourneyNav(prevPage, nextPage);
    content = content.replace(journeyPattern, newNav);
    modified = true;
    log('  Updated Journey Navigation in', fileName);
  }
  
  // Pattern 2: Simple nav-footer (if no Journey Navigation)
  const navFooterPattern = /<!-- Navigation -->\s*<nav class="docs-nav-footer">.*?<\/nav>/s;
  if (!modified && navFooterPattern.test(content)) {
    const newNav = generateNavFooter(prevPage, nextPage);
    content = content.replace(navFooterPattern, newNav);
    modified = true;
    log('  Updated nav-footer in', fileName);
  }
  
  // Pattern 3: Alternative Journey Navigation format (closing with </div></div>)
  const altJourneyPattern = /<div class="border-t border-mountain-700 mt-12 pt-8">\s*<h2 class="text-xl font-bold mb-6">Continue the Journey<\/h2>.*?<\/div>\s*<\/div>/s;
  if (!modified && altJourneyPattern.test(content)) {
    const newNav = generateJourneyNav(prevPage, nextPage);
    content = content.replace(altJourneyPattern, newNav.replace('      <!-- Journey Navigation -->\n', ''));
    modified = true;
    log('  Updated alt Journey Navigation in', fileName);
  }
  
  if (modified) {
    if (!DRY_RUN) {
      fs.writeFileSync(filePath, content, 'utf8');
    }
    return true;
  }
  
  log('  No navigation section found in', fileName);
  return false;
}

/**
 * Main update function
 */
function updateAllNavigation() {
  console.log('📚 Updating documentation navigation...');
  if (DRY_RUN) console.log('   (DRY RUN - no files will be modified)');
  console.log('');
  
  const pages = loadNavOrder();
  console.log('Found', pages.length, 'pages in nav-order.json');
  console.log('');
  
  // --- Phase 1: Sidebar sync (all HTML files in docs/) ---
  if (!NAV_ONLY) {
    console.log('--- Sidebar Sync ---');
    const allHtml = fs.readdirSync(DOCS_DIR).filter(f => f.endsWith('.html'));
    let sidebarUpdated = 0;
    let sidebarSkipped = 0;
    
    for (const htmlFile of allHtml) {
      const filePath = path.join(DOCS_DIR, htmlFile);
      if (updateFileSidebar(filePath, pages)) {
        log('  ✅ Sidebar:', htmlFile);
        sidebarUpdated++;
      } else {
        sidebarSkipped++;
      }
    }
    
    console.log('  Sidebar updated:', sidebarUpdated, 'files');
    console.log('  Sidebar skipped:', sidebarSkipped, '(no sidebar-nav)');
    console.log('');
  }
  
  // --- Phase 2: Journey/footer nav (only nav-order pages) ---
  if (!SIDEBAR_ONLY) {
    console.log('--- Journey Navigation ---');
    let navUpdated = 0;
    let navSkipped = 0;
    let navNotFound = 0;
    
    for (let i = 0; i < pages.length; i++) {
      const current = pages[i];
      const prev = i > 0 ? pages[i - 1] : null;
      const next = i < pages.length - 1 ? pages[i + 1] : null;
      
      const filePath = path.join(DOCS_DIR, current.file);
      
      if (!fs.existsSync(filePath)) {
        console.log('  ⚠️  File not found:', current.file);
        navNotFound++;
        continue;
      }
      
      if (updateFileNav(filePath, prev, next)) {
        console.log('  ✅', current.file, '→', 
          prev ? '← ' + prev.file : '(no prev)',
          next ? '→ ' + next.file : '(no next)');
        navUpdated++;
      } else {
        navSkipped++;
      }
    }
    
    console.log('');
    console.log('  Nav updated:', navUpdated);
    console.log('  Nav skipped:', navSkipped, '(no nav section)');
    console.log('  Not found:', navNotFound);
  }
  
  console.log('');
  console.log('✅ Done.');
  
  if (DRY_RUN) {
    console.log('Run without --dry-run to apply changes.');
  }
}

// Run
updateAllNavigation();
