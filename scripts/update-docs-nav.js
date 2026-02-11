#!/usr/bin/env node
/**
 * update-docs-nav.js - Update documentation navigation links
 * 
 * Reads docs/nav-order.json and updates prev/next links in all doc pages.
 * Handles two navigation formats:
 * 1. Journey Navigation cards (with icons and descriptions)
 * 2. Simple nav-footer links
 * 
 * Usage: node scripts/update-docs-nav.js [--dry-run] [--verbose]
 */

const fs = require('fs');
const path = require('path');

const DOCS_DIR = path.join(__dirname, '..', 'docs');
const NAV_ORDER_FILE = path.join(DOCS_DIR, 'nav-order.json');

// Parse args
const args = process.argv.slice(2);
const DRY_RUN = args.includes('--dry-run');
const VERBOSE = args.includes('--verbose');

function log(...msg) {
  if (VERBOSE) console.log(...msg);
}

function loadNavOrder() {
  const content = fs.readFileSync(NAV_ORDER_FILE, 'utf8');
  return JSON.parse(content).pages;
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
  console.log('📚 Updating documentation navigation links...');
  if (DRY_RUN) console.log('   (DRY RUN - no files will be modified)');
  console.log('');
  
  const pages = loadNavOrder();
  console.log('Found', pages.length, 'pages in nav-order.json');
  console.log('');
  
  let updated = 0;
  let skipped = 0;
  let notFound = 0;
  
  for (let i = 0; i < pages.length; i++) {
    const current = pages[i];
    const prev = i > 0 ? pages[i - 1] : null;
    const next = i < pages.length - 1 ? pages[i + 1] : null;
    
    const filePath = path.join(DOCS_DIR, current.file);
    
    if (!fs.existsSync(filePath)) {
      console.log('⚠️  File not found:', current.file);
      notFound++;
      continue;
    }
    
    if (updateFileNav(filePath, prev, next)) {
      console.log('✅', current.file, '→', 
        prev ? '← ' + prev.file : '(no prev)',
        next ? '→ ' + next.file : '(no next)');
      updated++;
    } else {
      skipped++;
    }
  }
  
  console.log('');
  console.log('Summary:');
  console.log('  Updated:', updated);
  console.log('  Skipped:', skipped, '(no nav section)');
  console.log('  Not found:', notFound);
  
  if (DRY_RUN) {
    console.log('');
    console.log('Run without --dry-run to apply changes.');
  }
}

// Run
updateAllNavigation();
