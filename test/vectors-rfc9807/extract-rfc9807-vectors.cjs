// Node.js CommonJS script to extract RFC 9807 test vectors from rfc9807.txt
// Usage: node extract-rfc9807-vectors.cjs rfc9807.txt C.2.1


const fs = require('fs');

function extractSection(rfcText, section) {
  // Find section header
  const sectionHeader = new RegExp(`^${section}\\.\\s+`, 'm');
  const startMatch = rfcText.match(sectionHeader);
  if (!startMatch) {
    throw new Error(`Section ${section} not found`);
  }
  const startIdx = startMatch.index;
  // Find next section or end
  const nextSectionHeader = new RegExp(`^C\\.\\d+\\.\\d+\\.\\s+`, 'm');
  const rest = rfcText.slice(startIdx);
  const nextMatch = rest.match(nextSectionHeader);
  const endIdx = nextMatch && nextMatch.index > 0 ? startIdx + nextMatch.index : rfcText.length;
  return rfcText.slice(startIdx, endIdx);
}

function extractFields(sectionText) {
  const lines = sectionText.split(/\r?\n/);
  const fields = {};
  let currentField = null;
  let buffer = '';
  for (let line of lines) {
    // Field label: 3+ spaces, label, colon, value
    const fieldMatch = line.match(/^\s{3}([a-zA-Z0-9_]+):\s*(.*)$/);
    if (fieldMatch) {
      // Save previous field
      if (currentField && buffer) {
        fields[currentField] = buffer.replace(/\s+/g, '');
      }
      currentField = fieldMatch[1];
      buffer = fieldMatch[2];
      continue;
    }
    // Continuation line: at least 3 spaces, not a new field
    if (currentField && line.match(/^\s{3,}\S/)) {
      buffer += line.trim();
      continue;
    }
    // End of field
    if (currentField && buffer) {
      fields[currentField] = buffer.replace(/\s+/g, '');
      currentField = null;
      buffer = '';
    }
  }
  // Save last field
  if (currentField && buffer) {
    fields[currentField] = buffer.replace(/\s+/g, '');
  }
  return fields;
}

if (process.argv.length < 4) {
  console.log('Usage: node extract-rfc9807-vectors.cjs rfc9807.txt C.1.1.3');
  process.exit(1);
}

const rfcPath = process.argv[2];
const section = process.argv[3];
const rfcText = fs.readFileSync(rfcPath, 'utf8');
const sectionText = extractSection(rfcText, section);
const fields = extractFields(sectionText);
console.log(JSON.stringify(fields, null, 2));
