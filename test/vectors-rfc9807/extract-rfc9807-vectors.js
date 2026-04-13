// Node.js script to extract RFC 9807 test vectors from rfc9807.txt
// Usage: node extract-rfc9807-vectors.js rfc9807.txt C.2.1

const fs = require('fs')

function extractSection(rfcText, section) {
  // Find section header
  const sectionHeader = new RegExp(`^${section}\\.\\s+`, 'm')
  const startMatch = rfcText.match(sectionHeader)
  if (!startMatch) {
    throw new Error(`Section ${section} not found`)
  }
  const startIdx = startMatch.index
  // Find next section or end
  const nextSectionHeader = new RegExp(`^C\\.\\d+\\.\\d+\\.\\s+`, 'm')
  const rest = rfcText.slice(startIdx)
  const nextMatch = rest.match(nextSectionHeader)
  const endIdx = nextMatch && nextMatch.index > 0 ? startIdx + nextMatch.index : rfcText.length
  return rfcText.slice(startIdx, endIdx)
}

function extractFields(sectionText) {
  // Extract fields and concatenate lines
  const fieldRegex = /^\s{3}([a-zA-Z0-9_]+):\s*(.*)$/gm
  let match
  const fields = {}
  let currentField = null
  while ((match = fieldRegex.exec(sectionText))) {
    currentField = match[1]
    fields[currentField] = match[2].replace(/\s+/g, '')
    // Now, grab any subsequent lines that are indented and not a new field
    let nextLineIdx = fieldRegex.lastIndex
    while (true) {
      const nextLineMatch = sectionText.slice(nextLineIdx).match(/^\s{6,}(\S.*)$/m)
      if (!nextLineMatch) break
      fields[currentField] += nextLineMatch[1].replace(/\s+/g, '')
      nextLineIdx += nextLineMatch.index + nextLineMatch[0].length
    }
  }
  return fields
}

if (process.argv.length < 4) {
  console.log('Usage: node extract-rfc9807-vectors.js rfc9807.txt C.2.1')
  process.exit(1)
}

const rfcPath = process.argv[2]
const section = process.argv[3]
const rfcText = fs.readFileSync(rfcPath, 'utf8')
const sectionText = extractSection(rfcText, section)
const fields = extractFields(sectionText)
console.log(JSON.stringify(fields, null, 2))
