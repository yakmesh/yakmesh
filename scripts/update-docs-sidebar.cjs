#!/usr/bin/env node
/**
 * update-docs-sidebar.cjs - Update sidebar navigation in all doc pages
 * 
 * Reads docs/nav-order.json and updates the <ul class="sidebar-nav"> section
 * in all HTML files to match the canonical navigation order.
 * 
 * Usage: node scripts/update-docs-sidebar.cjs [--dry-run] [--verbose]
 * 
 * This ensures all pages have consistent sidebar navigation without manual updates.
 */

const fs = require('fs');
const path = require('path');

// Support both /docs and /website/docs
const SCRIPTS_DIR = __dirname;
const ROOT_DIR = path.join(SCRIPTS_DIR, '..');
const NAV_ORDER_FILE = path.join(ROOT_DIR, 'docs', 'nav-order.json');

// Target directories to scan
const DOCS_DIRS = [
  path.join(ROOT_DIR, 'docs'),
  path.join(ROOT_DIR, 'website', 'docs'),
  path.join(ROOT_DIR, 'website', 'docs', 'tutorials')
];

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
 * Generate sidebar nav list items from nav-order.json
 * @param {string} currentFile - The current file name (for "active" class)
 * @param {string} prefix - Path prefix (e.g., "../" for subdirectory pages)
 */
function generateSidebarNavItems(currentFile, prefix = '') {
  const pages = loadNavOrder();
  
  const items = pages.map(page => {
    const isActive = page.file === currentFile;
    const activeClass = isActive ? ' class="active"' : '';
    const href = prefix + page.file;
    
    // Icon handling - some use classes like yak-icon
    let iconHtml;
    if (page.title === 'YAK://') {
      iconHtml = '<span class="yak-icon"></span>';
    } else {
      iconHtml = `<span>${page.icon}</span>`;
    }
    
    return `      <li><a href="${href}"${activeClass}>${iconHtml} <span>${page.title}</span></a></li>`;
  });
  
  return items.join('\n');
}

/**
 * Update sidebar in a single file
 */
function updateFileSidebar(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  const fileName = path.basename(filePath);
  
  // Determine prefix for subdirectory pages (tutorials/)
  const inSubdir = filePath.includes(path.sep + 'tutorials' + path.sep);
  const prefix = inSubdir ? '../' : '';
  
  // Match the sidebar-nav ul section
  const sidebarPattern = /<ul class="sidebar-nav">\s*(?:<li>.*?<\/li>\s*)+<\/ul>/s;
  
  if (!sidebarPattern.test(content)) {
    log('  No sidebar-nav found in', fileName);
    return false;
  }
  
  const newNavItems = generateSidebarNavItems(fileName, prefix);
  const newSidebar = `<ul class="sidebar-nav">\n${newNavItems}\n    </ul>`;
  
  const newContent = content.replace(sidebarPattern, newSidebar);
  
  if (newContent === content) {
    log('  No changes needed in', fileName);
    return false;
  }
  
  if (!DRY_RUN) {
    fs.writeFileSync(filePath, newContent, 'utf8');
  }
  
  return true;
}

/**
 * Get all HTML files in a directory
 */
function getHtmlFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.html'))
    .map(f => path.join(dir, f));
}

/**
 * Main update function
 */
function updateAllSidebars() {
  console.log('🧭 Updating documentation sidebars...');
  if (DRY_RUN) console.log('   (DRY RUN - no files will be modified)');
  console.log('');
  
  const pages = loadNavOrder();
  console.log(`Loaded ${pages.length} pages from nav-order.json`);
  console.log('');
  
  let updated = 0;
  let skipped = 0;
  
  // Collect all HTML files from all directories
  const allFiles = [];
  for (const dir of DOCS_DIRS) {
    allFiles.push(...getHtmlFiles(dir));
  }
  
  console.log(`Found ${allFiles.length} HTML files to process`);
  console.log('');
  
  for (const filePath of allFiles) {
    const relativePath = path.relative(ROOT_DIR, filePath);
    
    if (updateFileSidebar(filePath)) {
      console.log('✅', relativePath);
      updated++;
    } else {
      log('⏭️ ', relativePath);
      skipped++;
    }
  }
  
  console.log('');
  console.log('Summary:');
  console.log('  Updated:', updated);
  console.log('  Skipped:', skipped);
  
  if (DRY_RUN) {
    console.log('');
    console.log('Run without --dry-run to apply changes.');
  }
}

// Run
updateAllSidebars();
