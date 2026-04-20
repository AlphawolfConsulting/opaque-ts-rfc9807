// Node.js script to extract all C.1.X and C.2.X sections from RFC 9807
// Usage: node extract-all-rfc9807-vectors.cjs rfc9807.txt

const fs = require('fs')

function extractAllSections(rfcText) {
    // Find all C.1.X and C.2.X section headers
    const sectionHeaderRegex = /^C\.(1|2)\.(\d+)\.\s+.*$/gm
    let match
    const sections = []
    while ((match = sectionHeaderRegex.exec(rfcText))) {
        sections.push({
            name: `C.${match[1]}.${match[2]}`,
            start: match.index
        })
    }
    // Add end index for each section
    for (let i = 0; i < sections.length; i++) {
        sections[i].end = i + 1 < sections.length ? sections[i + 1].start : rfcText.length
    }
    return sections
}

function extractSubsections(sectionText, sectionName) {
    // Find all C.X.X.Y subsection headers
    const subsectionRegex = new RegExp(`^C\\.(1|2)\\.(\\d+)\\.(\\d+)\\.\\s+(.*)$`, 'gm')
    let match
    const subsections = []
    while ((match = subsectionRegex.exec(sectionText))) {
        subsections.push({
            key: `C.${match[1]}.${match[2]}.${match[3]}`,
            label: match[4].replace(/\s+/g, ''),
            start: match.index
        })
    }
    // Add end index for each subsection
    for (let i = 0; i < subsections.length; i++) {
        subsections[i].end =
            i + 1 < subsections.length ? subsections[i + 1].start : sectionText.length
    }
    return subsections
}

function extractFields(subsectionText) {
    const lines = subsectionText.split(/\r?\n/)
    const fields = {}
    let currentField = null
    let buffer = ''
    for (const line of lines) {
        const fieldMatch = line.match(/^\s{3}([a-zA-Z0-9_]+):\s*(.*)$/)
        if (fieldMatch) {
            if (currentField && buffer) {
                fields[currentField] = buffer.replace(/\s+/g, '')
            }
            currentField = fieldMatch[1]
            buffer = fieldMatch[2]
            continue
        }
        if (currentField && line.match(/^\s{3,}\S/)) {
            buffer += line.trim()
            continue
        }
        if (currentField && buffer) {
            fields[currentField] = buffer.replace(/\s+/g, '')
            currentField = null
            buffer = ''
        }
    }
    if (currentField && buffer) {
        fields[currentField] = buffer.replace(/\s+/g, '')
    }
    return fields
}

if (process.argv.length < 3) {
    console.log('Usage: node extract-all-rfc9807-vectors.cjs rfc9807.txt')
    process.exit(1)
}

const rfcPath = process.argv[2]
const rfcText = fs.readFileSync(rfcPath, 'utf8')
const sections = extractAllSections(rfcText)
const result = {}
for (const sec of sections) {
    const sectionText = rfcText.slice(sec.start, sec.end)
    const subsections = extractSubsections(sectionText, sec.name)
    for (const sub of subsections) {
        const subsectionText = sectionText.slice(sub.start, sub.end)
        result[sub.key] = {
            label: sub.label,
            fields: extractFields(subsectionText)
        }
    }
}
console.log(JSON.stringify(result, null, 2))
