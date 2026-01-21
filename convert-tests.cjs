/**
 * Convert node:test format tests to vitest format
 */

const fs = require('fs');

function convertNodeTestToVitest(content) {
  // Replace imports
  content = content.replace(
    /import \{ describe, it, beforeEach(?:, mock)? \} from 'node:test';/g,
    "import { describe, it, expect, beforeEach, vi } from 'vitest';"
  );
  content = content.replace(
    /import \{ describe, it, beforeEach \} from 'node:test';/g,
    "import { describe, it, expect, beforeEach, vi } from 'vitest';"
  );
  content = content.replace(/import assert from 'node:assert';\n?/g, '');
  
  // Replace assert patterns - order matters!
  content = content.replace(/assert\.strictEqual\(([^,]+),\s*true\)/g, 'expect($1).toBe(true)');
  content = content.replace(/assert\.strictEqual\(([^,]+),\s*false\)/g, 'expect($1).toBe(false)');
  content = content.replace(/assert\.strictEqual\(([^,]+),\s*null\)/g, 'expect($1).toBeNull()');
  content = content.replace(/assert\.strictEqual\(([^,]+),\s*undefined\)/g, 'expect($1).toBeUndefined()');
  
  // Generic strictEqual with complex second args
  content = content.replace(/assert\.strictEqual\(([^,]+),\s*([^)]+)\)/g, 'expect($1).toBe($2)');
  content = content.replace(/assert\.notStrictEqual\(([^,]+),\s*([^)]+)\)/g, 'expect($1).not.toBe($2)');
  content = content.replace(/assert\.deepStrictEqual\(([^,]+),\s*([^)]+)\)/g, 'expect($1).toEqual($2)');
  content = content.replace(/assert\.ok\(([^)]+)\)/g, 'expect($1).toBeTruthy()');
  
  // assert.throws with regex
  content = content.replace(/assert\.throws\(\(\) => \{\s*\n?\s*([^}]+)\s*\},\s*\/([^\/]+)\/\)/g, 
    'expect(() => {\n      $1\n    }).toThrow(/$2/)');
  content = content.replace(/assert\.throws\(([^,]+),\s*\/([^\/]+)\/\)/g, 'expect($1).toThrow(/$2/)');
  
  // Remove trailing console.log test load messages
  content = content.replace(/\nconsole\.log\('[^']+tests loaded'\);?\s*$/g, '');
  
  return content;
}

const files = [
  'C:/Users/ABL/Desktop/Yakmesh/yakmesh-node/security/tests/mesh-revocation.test.js',
  'C:/Users/ABL/Desktop/Yakmesh/yakmesh-node/security/tests/trust-tier.test.js'
];

files.forEach(file => {
  let content = fs.readFileSync(file, 'utf8');
  content = convertNodeTestToVitest(content);
  fs.writeFileSync(file, content);
  console.log('Converted:', file.split('/').pop());
});

console.log('Done!');
