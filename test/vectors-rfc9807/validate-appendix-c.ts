import { readFileSync, existsSync } from 'fs'
import { join } from 'path'

type VectorSection = {
  comment: string
  config: Record<string, string | number>
  inputs: Record<string, string>
  intermediates: Record<string, string>
  outputs: Record<string, string>
}

type IndexEntry = { section: string; name: string; file: string }

type ParsedRFC = Record<string, VectorSection>

const DEFAULT_RFC_PATH = '/tmp/rfc9807.txt'
const BASE_DIR = 'test/vectors-rfc9807'
const INDEX_PATH = join(BASE_DIR, 'appendix-c-index.json')

const args = process.argv.slice(2)
const rfcPath = args[0] || DEFAULT_RFC_PATH

if (!existsSync(rfcPath)) {
  console.error(`Missing RFC text at ${rfcPath}`)
  console.error('Download with: curl -L https://www.rfc-editor.org/rfc/rfc9807.txt -o /tmp/rfc9807.txt')
  process.exit(1)
}

const index = JSON.parse(readFileSync(INDEX_PATH, 'utf8')) as { sections: IndexEntry[] }

const rfcText = readFileSync(rfcPath, 'utf8')
const rfc = parseRFCAppendixC(rfcText)

let failed = false

for (const entry of index.sections) {
  const sec = entry.section
  const file = entry.file
  const localPath = join(BASE_DIR, file)
  const local = JSON.parse(readFileSync(localPath, 'utf8')) as VectorSection
  const official = rfc[sec]

  if (!official) {
    report(`Missing RFC section ${sec} in parsed data`)
    failed = true
    continue
  }

  failed = compareSection(sec, local, official) || failed
  failed = validateLengths(sec, local) || failed
}

if (!failed) {
  console.log('All Appendix C vectors match RFC 9807 and length checks pass.')
}

process.exitCode = failed ? 1 : 0

function parseRFCAppendixC(text: string): ParsedRFC {
  const lines = text.split(/\r?\n/)
  const sections: ParsedRFC = {}

  let currentSection: string | null = null
  let currentArea: keyof VectorSection | null = null
  let currentField: string | null = null
  let currentHeader: string | null = null

  const ensureSection = (sec: string) => {
    if (!sections[sec]) {
      sections[sec] = {
        comment: '',
        config: {},
        inputs: {},
        intermediates: {},
        outputs: {}
      }
    }
  }

  for (const line of lines) {
    const secMatch = line.match(/^C\.(\d+)\.(\d+)\.\s+(.*)$/)
    if (secMatch) {
      const sec = `C.${secMatch[1]}.${secMatch[2]}`
      currentSection = sec
      currentHeader = secMatch[3].trim()
      currentArea = null
      currentField = null
      ensureSection(sec)
      sections[sec].comment = `RFC 9807 Appendix ${sec} - ${currentHeader}`
      continue
    }

    if (!currentSection) continue

    const areaMatch = line.match(/^C\.\d+\.\d+\.\d+\.\s+(Configuration|Input Values|Intermediate Values|Output Values)/)
    if (areaMatch) {
      const name = areaMatch[1]
      currentArea = name === 'Configuration' ? 'config'
        : name === 'Input Values' ? 'inputs'
        : name === 'Intermediate Values' ? 'intermediates'
        : 'outputs'
      currentField = null
      continue
    }

    if (!currentArea) continue

    const fieldMatch = line.match(/^\s{3}([a-zA-Z0-9_]+):\s*(.*)$/)
    if (fieldMatch) {
      const field = fieldMatch[1]
      let value = fieldMatch[2] || ''
      currentField = field
      if (currentArea === 'config') {
        ;(sections[currentSection][currentArea] as Record<string, string | number>)[field] =
          /^\d+$/.test(value) ? parseInt(value, 10) : value
      } else {
        ;(sections[currentSection][currentArea] as Record<string, string>)[field] = value.replace(/\s+/g, '')
      }
      continue
    }

    if (currentField && /^\s{3}\S+/.test(line)) {
      const cont = line.trim().replace(/\s+/g, '')
      if (currentArea !== 'config') {
        const areaObj = sections[currentSection][currentArea] as Record<string, string>
        areaObj[currentField] = (areaObj[currentField] || '') + cont
      }
    } else {
      currentField = null
    }
  }

  return sections
}

function compareSection(section: string, local: VectorSection, official: VectorSection): boolean {
  let failed = false
  for (const area of ['config', 'inputs', 'intermediates', 'outputs'] as const) {
    const a = official[area] || {}
    const b = local[area] || {}
    const keys = new Set([...Object.keys(a), ...Object.keys(b)])
    for (const key of keys) {
      const expected = (a as any)[key]
      const actual = (b as any)[key]
      if (expected === undefined) {
        report(`[${section}] extra local ${area}.${key}`)
        failed = true
        continue
      }
      if (actual === undefined) {
        report(`[${section}] missing local ${area}.${key}`)
        failed = true
        continue
      }
      if (typeof expected === 'number' || typeof actual === 'number') {
        if (expected !== actual) {
          report(`[${section}] ${area}.${key} config mismatch: RFC=${expected} local=${actual}`)
          failed = true
        }
        continue
      }
      if (expected !== actual) {
        const idx = firstDiffIndex(expected, actual)
        report(`[${section}] ${area}.${key} mismatch (RFC len=${expected.length}, local len=${actual.length}, firstDiffIndex=${idx})`)
        failed = true
      }
    }
  }
  return failed
}

function validateLengths(section: string, vector: VectorSection): boolean {
  let failed = false
  const cfg = vector.config
  const Nh = cfg.Nh as number
  const Npk = cfg.Npk as number
  const Nm = cfg.Nm as number

  const outputs = vector.outputs || {}
  const inputs = vector.inputs || {}

  const lengthChecks: Array<[string, number | undefined]> = [
    ['outputs.registration_request', (outputs.registration_request || '').length / 2],
    ['outputs.registration_response', (outputs.registration_response || '').length / 2],
    ['outputs.registration_upload', (outputs.registration_upload || '').length / 2],
    ['outputs.KE1', (outputs.KE1 || '').length / 2],
    ['outputs.KE2', (outputs.KE2 || '').length / 2],
    ['outputs.KE3', (outputs.KE3 || '').length / 2],
    ['inputs.KE1', (inputs.KE1 || '').length / 2]
  ]

  const expected: Record<string, number> = {}

  if (cfg.Nh && cfg.Npk) {
    expected['outputs.KE1'] = Npk + Nh + Npk
    expected['inputs.KE1'] = Npk + Nh + Npk
  }
  if (cfg.Nh && cfg.Npk && cfg.Nm) {
    const credResponseLen = Npk + Nh + (Npk + Nh + Nm)
    const authResponseLen = Nh + Npk + Nm
    expected['outputs.KE2'] = credResponseLen + authResponseLen
    expected['outputs.KE3'] = Nm
  }

  if (cfg.Nh && cfg.Npk && cfg.Nm) {
    expected['outputs.registration_upload'] = Npk + Nh + (Nh + Nm)
  }

  for (const [label, actualLen] of lengthChecks) {
    if (expected[label] !== undefined) {
      if (!actualLen) {
        report(`[${section}] ${label} missing for length check`)
        failed = true
      } else if (actualLen !== expected[label]) {
        report(`[${section}] ${label} length mismatch: expected ${expected[label]} got ${actualLen}`)
        failed = true
      }
    }
  }

  return failed
}

function firstDiffIndex(a: string, b: string): number {
  const len = Math.min(a.length, b.length)
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return i
  }
  return a.length === b.length ? -1 : len
}

function report(msg: string) {
  console.log(msg)
}
