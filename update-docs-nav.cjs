const fs = require('fs');
const path = require('path');
const docsDir = './docs';
const files = fs.readdirSync(docsDir).filter(f => f.endsWith('.html'));
const oldNav = '<li><a href="annex.html"><span>\u{1F309}</span> <span>ANNEX</span></a></li>\n      <li><a href="yak-protocol.html">';
const newNav = '<li><a href="annex.html"><span>\u{1F309}</span> <span>ANNEX</span></a></li>\n      <li><a href="gumba.html"><span>\u{1F6D5}</span> <span>GUMBA</span></a></li>\n      <li><a href="yak-protocol.html">';
let count = 0;
files.forEach(file => {
  const fp = path.join(docsDir, file);
  let content = fs.readFileSync(fp, 'utf8');
  if (!content.includes('gumba.html') && content.includes(oldNav)) {
    content = content.replace(oldNav, newNav);
    fs.writeFileSync(fp, content, 'utf8');
    count++;
    console.log('Updated:', file);
  }
});
console.log('Total updated:', count);
