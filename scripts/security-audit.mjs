#!/usr/bin/env node
/**
 * Security Audit Script
 * 
 * Runs dependency security checks and generates SBOM.
 * Run before deployment or as part of CI/CD.
 * 
 * Usage:
 *   node scripts/security-audit.mjs
 *   node scripts/security-audit.mjs --fix       # Auto-fix where possible
 *   node scripts/security-audit.mjs --sbom      # Generate SBOM only
 *   node scripts/security-audit.mjs --json      # JSON output for CI
 * 
 * @module scripts/security-audit
 * @version 1.0.0
 */

import { spawnSync } from 'child_process';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { createHash } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

const args = process.argv.slice(2);
const FIX_MODE = args.includes('--fix');
const SBOM_ONLY = args.includes('--sbom');
const JSON_OUTPUT = args.includes('--json');

const results = {
  timestamp: new Date().toISOString(),
  audit: null,
  lockfileIntegrity: null,
  sbom: null,
  recommendations: [],
};

/**
 * Run npm audit
 */
function runAudit() {
  console.log('\n📦 Running npm audit...\n');
  
  try {
    const cmdArgs = FIX_MODE 
      ? ['audit', 'fix', '--audit-level=moderate']
      : ['audit', '--json'];
    
    const result = spawnSync('npm', cmdArgs, {
      cwd: ROOT_DIR,
      encoding: 'utf-8',
      shell: true,
    });
    
    if (JSON_OUTPUT || !FIX_MODE) {
      try {
        const auditData = JSON.parse(result.stdout);
        results.audit = {
          vulnerabilities: auditData.metadata?.vulnerabilities || {},
          totalDependencies: auditData.metadata?.dependencies?.total || 0,
          advisories: Object.keys(auditData.advisories || {}).length,
        };
        
        const vulns = results.audit.vulnerabilities;
        const total = (vulns.critical || 0) + (vulns.high || 0) + (vulns.moderate || 0) + (vulns.low || 0);
        
        if (vulns.critical > 0) {
          results.recommendations.push(`🔴 CRITICAL: ${vulns.critical} critical vulnerabilities found!`);
        }
        if (vulns.high > 0) {
          results.recommendations.push(`🟠 HIGH: ${vulns.high} high severity vulnerabilities`);
        }
        
        console.log(`   Total dependencies: ${results.audit.totalDependencies}`);
        console.log(`   Vulnerabilities: ${total} (${vulns.critical || 0} critical, ${vulns.high || 0} high)`);
        
        return total === 0;
      } catch (e) {
        // npm audit returns non-zero on vulnerabilities, output may not be valid JSON
        if (result.stderr) {
          console.log('   Audit stderr:', result.stderr.slice(0, 200));
        }
        results.audit = { raw: result.stdout?.slice(0, 500) };
        return false;
      }
    } else {
      console.log(result.stdout);
      return result.status === 0;
    }
  } catch (e) {
    console.error('   Audit failed:', e.message);
    results.audit = { error: e.message };
    return false;
  }
}

/**
 * Verify package-lock.json integrity
 */
function verifyLockfile() {
  console.log('\n🔒 Verifying lockfile integrity...\n');
  
  const lockPath = join(ROOT_DIR, 'package-lock.json');
  
  if (!existsSync(lockPath)) {
    console.log('   ⚠️ No package-lock.json found');
    results.lockfileIntegrity = { exists: false };
    results.recommendations.push('Generate package-lock.json with npm install');
    return false;
  }
  
  try {
    const lockContent = readFileSync(lockPath, 'utf-8');
    const lockData = JSON.parse(lockContent);
    
    // Calculate hash of lockfile
    const hash = createHash('sha256').update(lockContent).digest('hex');
    
    results.lockfileIntegrity = {
      exists: true,
      hash: hash.slice(0, 16),
      lockfileVersion: lockData.lockfileVersion,
      packageCount: Object.keys(lockData.packages || {}).length,
    };
    
    console.log(`   Lockfile version: ${lockData.lockfileVersion}`);
    console.log(`   Packages locked: ${results.lockfileIntegrity.packageCount}`);
    console.log(`   Lockfile hash: ${hash.slice(0, 16)}...`);
    
    // Verify with npm ci (dry run)
    const verifyResult = spawnSync('npm', ['ci', '--dry-run'], {
      cwd: ROOT_DIR,
      encoding: 'utf-8',
      shell: true,
    });
    
    if (verifyResult.status === 0) {
      console.log('   ✓ Lockfile is valid and consistent');
      return true;
    } else {
      console.log('   ⚠️ Lockfile may be out of sync with package.json');
      results.recommendations.push('Run npm install to regenerate lockfile');
      return false;
    }
  } catch (e) {
    console.error('   Lockfile verification failed:', e.message);
    results.lockfileIntegrity = { error: e.message };
    return false;
  }
}

/**
 * Generate Software Bill of Materials (SBOM)
 */
function generateSBOM() {
  console.log('\n📋 Generating SBOM...\n');
  
  const packagePath = join(ROOT_DIR, 'package.json');
  const lockPath = join(ROOT_DIR, 'package-lock.json');
  
  try {
    const pkg = JSON.parse(readFileSync(packagePath, 'utf-8'));
    const lock = existsSync(lockPath) ? JSON.parse(readFileSync(lockPath, 'utf-8')) : null;
    
    const sbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          type: 'application',
          name: pkg.name,
          version: pkg.version,
        },
      },
      components: [],
    };
    
    // Add direct dependencies
    for (const [name, version] of Object.entries(pkg.dependencies || {})) {
      sbom.components.push({
        type: 'library',
        name,
        version: version.replace(/^[\^~]/, ''),
        scope: 'required',
      });
    }
    
    // Add dev dependencies
    for (const [name, version] of Object.entries(pkg.devDependencies || {})) {
      sbom.components.push({
        type: 'library',
        name,
        version: version.replace(/^[\^~]/, ''),
        scope: 'optional',
      });
    }
    
    const sbomPath = join(ROOT_DIR, 'sbom.json');
    writeFileSync(sbomPath, JSON.stringify(sbom, null, 2));
    
    results.sbom = {
      generated: true,
      path: 'sbom.json',
      componentCount: sbom.components.length,
    };
    
    console.log(`   Generated sbom.json with ${sbom.components.length} components`);
    console.log(`   Direct deps: ${Object.keys(pkg.dependencies || {}).length}`);
    console.log(`   Dev deps: ${Object.keys(pkg.devDependencies || {}).length}`);
    
    return true;
  } catch (e) {
    console.error('   SBOM generation failed:', e.message);
    results.sbom = { error: e.message };
    return false;
  }
}

/**
 * Main
 */
async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║           YAKMESH SECURITY AUDIT                           ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  
  let allPassed = true;
  
  if (SBOM_ONLY) {
    generateSBOM();
  } else {
    allPassed = runAudit() && allPassed;
    allPassed = verifyLockfile() && allPassed;
    generateSBOM();
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  
  if (results.recommendations.length > 0) {
    console.log('\n📝 Recommendations:\n');
    for (const rec of results.recommendations) {
      console.log(`   ${rec}`);
    }
  }
  
  if (JSON_OUTPUT) {
    console.log('\n📊 JSON Results:\n');
    console.log(JSON.stringify(results, null, 2));
  }
  
  console.log('\n' + (allPassed ? '✅ Security audit passed' : '⚠️ Security issues detected'));
  
  process.exit(allPassed ? 0 : 1);
}

main().catch(e => {
  console.error('Audit failed:', e);
  process.exit(1);
});
