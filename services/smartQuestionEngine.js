import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { ISMS_QUESTION_BANK } from '../data/ismsQuestionBank.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const DATA_DIR = path.resolve(__dirname, '../data')

const SECTION_BLUEPRINTS = ISMS_QUESTION_BANK

const DROPDOWNS = {
  ownership: ['CISO', 'IT Manager', 'Security Committee', 'Compliance Lead', 'Operations Lead', 'External Consultant', 'Other'],
  process: ['Documented policy + SOP', 'Risk-based workflow', 'Ticket-driven workflow', 'Manual checklist', 'In development'],
  execution: ['Jira/ServiceNow', 'Excel Register', 'GRC Platform', 'Cloud-native controls', 'Email + approvals', 'Mixed tools'],
  scope: ['All business units', 'Specific divisions', 'Head office only', 'Production systems only', 'Cloud workloads only', 'Hybrid scope'],
  frequency: ['Real-time', 'Daily', 'Weekly', 'Monthly', 'Quarterly', 'Bi-annually', 'Annually', 'Event-driven']
}

const YES_NO_PARTIAL = ['Yes', 'No', 'Partially']

function humanizeQuestion(questionText) {
  const q = String(questionText || '').trim()
  if (!q) return q
  const lower = q.toLowerCase()
  if (lower.startsWith('do you ')) return q
  if (lower.startsWith('is there')) return q
  if (lower.startsWith('what is') || lower.startsWith('who ') || lower.startsWith('how ')) return q
  if (lower.includes('process') || lower.includes('policy') || lower.includes('control')) {
    return `In simple terms, ${q.charAt(0).toLowerCase()}${q.slice(1)}`
  }
  return q
}

function helperTextForNonTechnicalUsers(questionText) {
  const q = String(questionText || '').toLowerCase()
  if (q.includes('legal name')) return 'Use your registration/certificate legal name exactly. If unsure, ask HR or legal.'
  if (q.includes('scope')) return 'Scope means what is included and what is excluded. Mention teams, systems, and sites in plain words.'
  if (q.includes('stakeholder')) return 'Think of people affected by security: customers, regulators, partners, management, and employees.'
  if (q.includes('segregation')) return 'Segregation means one person should not request, approve, and complete the same sensitive action.'
  if (q.includes('privileged access')) return 'Privileged access means admin or root rights. Mention who approves and how often it is reviewed.'
  if (q.includes('rto') || q.includes('rpo')) return 'RTO = maximum downtime allowed. RPO = maximum data loss allowed. Give practical numbers.'
  if (q.includes('root cause')) return 'Root cause means the actual reason, not symptoms. Explain how you prevent repeat incidents.'
  if (q.includes('retention')) return 'Retention means how long records are kept and when/how they are securely deleted.'
  if (q.includes('vulnerability') || q.includes('patch')) return 'Mention how issues are found, who owns fixes, and target closure timeline.'
  if (q.includes('encryption')) return 'State where encryption is used (in transit/at rest), which standard/tool, and who manages keys.'
  if (q.includes('risk')) return 'Use business language: what can go wrong, impact, owner, and current mitigation.'
  return 'Answer in simple business language: who owns this, how it works, how often it is reviewed, and where evidence is kept.'
}

function buildAdaptiveField(questionText, sectionKey) {
  const q = questionText.toLowerCase()
  const base = { key: 'answer', label: 'Answer', required: true }

  if (q.includes('rto/rpo')) {
    return {
      ...base,
      type: 'fill_blanks',
      blanks: [
        { key: 'rto', label: 'RTO', placeholder: 'e.g. 4 hours' },
        { key: 'rpo', label: 'RPO', placeholder: 'e.g. 1 hour' }
      ]
    }
  }

  if (q.includes('define classification levels')) {
    return {
      ...base,
      type: 'rank_order',
      options: ['Public', 'Internal', 'Confidential', 'Restricted']
    }
  }

  if (q.includes('background verification') || q.includes('fire protection systems') || q.includes('communication methods')) {
    return {
      ...base,
      type: 'checkbox_group',
      options: q.includes('background verification')
        ? ['Identity check', 'Criminal check', 'Education check', 'Employment reference', 'Address verification']
        : q.includes('fire protection systems')
          ? ['Smoke detectors', 'Fire extinguishers', 'Sprinklers', 'Fire alarm', 'Emergency exits']
          : ['Email', 'Teams/Slack', 'Townhall', 'Portal', 'Policy circular']
    }
  }

  if (q.startsWith('do ') || q.startsWith('is ') || q.includes('exists?') || q.includes('availability?') || q.includes('installed?') || q.includes('maintained?')) {
    return { ...base, type: 'single_choice', options: YES_NO_PARTIAL }
  }

  if (q.startsWith('who ') || q.includes('who is') || q.includes('who handles') || q.includes('who approves')) {
    return { ...base, type: 'short_text', minChars: 8, placeholder: 'Role / person name' }
  }

  if (q.includes('how often') || q.includes('frequency') || q.includes('count') || q.includes('how long')) {
    return { ...base, type: 'short_text', minChars: 4, placeholder: 'Cadence / count / timeline' }
  }

  if (q.includes('list') || q.includes('which') || q.includes('what types') || q.includes('applicable laws') || q.includes('entry points')) {
    return { ...base, type: 'tag_list', placeholder: 'Comma separated list' }
  }

  if (
    q.includes('process') ||
    q.includes('how ') ||
    q.includes('handled') ||
    q.includes('method') ||
    q.includes('policy') ||
    q.includes('rules') ||
    q.includes('expectations') ||
    sectionKey === 'incident_management' ||
    sectionKey === 'business_continuity'
  ) {
    return { ...base, type: 'long_text', minChars: 35, placeholder: 'Provide control-level implementation details' }
  }

  return { ...base, type: 'short_text', minChars: 12, placeholder: 'Provide concise factual answer' }
}

function needsControlMeta(questionText) {
  const q = questionText.toLowerCase()
  return (
    q.includes('process') ||
    q.includes('policy') ||
    q.includes('control') ||
    q.includes('how ') ||
    q.includes('handled') ||
    q.includes('method') ||
    q.includes('frequency') ||
    q.includes('review') ||
    q.includes('approve') ||
    q.includes('escalation') ||
    q.includes('documentation') ||
    q.includes('managed')
  )
}

function loadPolicySourceText() {
  const candidates = [
    path.join(DATA_DIR, 'ISMS policy DEMO.docx'),
    path.join(DATA_DIR, 'isms_doc_extracted.txt'),
    path.join(DATA_DIR, 'strings_raw.txt'),
    path.join(DATA_DIR, 'isms_text.txt')
  ]

  for (const filePath of candidates) {
    if (!fs.existsSync(filePath)) continue
    const ext = path.extname(filePath).toLowerCase()
    if (ext === '.txt') {
      return fs.readFileSync(filePath, 'utf8')
    }
  }
  return ''
}

function normalizePolicyText(rawText) {
  if (!rawText) return ''
  return rawText
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

function getFieldSchema(sectionKey) {
  return [
    { key: 'owner_role', label: 'Owner (role)', type: 'select', options: DROPDOWNS.ownership, required: true },
    { key: 'tooling', label: 'Primary tool', type: 'select', options: DROPDOWNS.execution, required: true },
    { key: 'control_frequency', label: 'Control frequency', type: 'select', options: DROPDOWNS.frequency, required: true },
    { key: 'evidence_ref', label: 'Evidence reference', type: 'short_text', minChars: 8, placeholder: 'Policy/SOP/Register/Log reference', required: true },
    {
      key: 'risk_link',
      label: 'Risk linkage',
      type: 'short_text',
      minChars: 6,
      placeholder: 'Risk ID or treatment plan reference',
      required: ['incident_management', 'business_continuity', 'access_control', 'asset_management', 'operations_communication'].includes(sectionKey)
    }
  ]
}

function extractSnippets(text, keywords, limit = 3) {
  if (!text) return []
  const lowered = text.toLowerCase()
  const snippets = []
  for (const keyword of keywords) {
    const idx = lowered.indexOf(keyword.toLowerCase())
    if (idx < 0) continue
    const start = Math.max(0, idx - 80)
    const end = Math.min(text.length, idx + 220)
    const snippet = text.slice(start, end).trim()
    if (snippet && !snippets.includes(snippet)) snippets.push(snippet)
    if (snippets.length >= limit) break
  }
  return snippets
}

function buildQuestionsForSection(section, sourceText) {
  const sourceSnippets = extractSnippets(sourceText, section.keywords)
  return (section.questions || []).map((prompt, index) => ({
    id: `${section.key}_${String(index + 1).padStart(3, '0')}`,
    section: section.key,
    sectionTitle: section.title,
    treePath: section.treePath,
    question: humanizeQuestion(prompt),
    helperText: helperTextForNonTechnicalUsers(prompt),
    questionType: 'structured_w',
    fields: needsControlMeta(prompt)
      ? [buildAdaptiveField(prompt, section.key), ...getFieldSchema(section.key)]
      : [buildAdaptiveField(prompt, section.key)],
    sourceSnippets
  }))
}

let cachedQuestionPack = null

export function buildSmartQuestionPack() {
  if (cachedQuestionPack) return cachedQuestionPack
  const sourceText = normalizePolicyText(loadPolicySourceText())
  const sections = SECTION_BLUEPRINTS.map((section) => ({
    key: section.key,
    title: section.title,
    questions: buildQuestionsForSection(section, sourceText)
  }))

  cachedQuestionPack = {
    generatedAt: new Date().toISOString(),
    source: 'backend/data demo ISMS policy',
    totalSections: sections.length,
    totalQuestions: sections.reduce((acc, sec) => acc + sec.questions.length, 0),
    sections
  }
  return cachedQuestionPack
}

export function flattenQuestions(questionPack) {
  return questionPack.sections.flatMap((section) => section.questions)
}

export function buildPreviewFromAnswers(questionPack, answerMap = {}) {
  const sections = questionPack.sections.map((section) => {
    const answers = section.questions.map((q) => ({
      questionId: q.id,
      question: q.question,
      answer: answerMap[q.id] || {},
      generatedText: buildGeneratedParagraph(answerMap[q.id] || {})
    }))
    return { section: section.key, sectionTitle: section.title, answers }
  })
  return {
    generatedAt: new Date().toISOString(),
    note: 'Low-cost preview generated without OpenAI.',
    sections
  }
}

function getWordStats(text) {
  const cleaned = String(text || '').toLowerCase().replace(/[^a-z0-9\s]/g, ' ')
  const words = cleaned.split(/\s+/).filter(Boolean)
  const unique = new Set(words)
  return { words, uniqueCount: unique.size }
}

function hasMeaningfulKeywords(text) {
  const keywords = ['policy', 'control', 'risk', 'incident', 'access', 'asset', 'audit', 'backup', 'recovery', 'supplier', 'compliance']
  const lowered = String(text || '').toLowerCase()
  return keywords.some((k) => lowered.includes(k))
}

export function detectWeakAnswer(text) {
  const normalized = String(text || '').trim()
  if (!normalized) return true
  const { words, uniqueCount } = getWordStats(normalized)
  if (normalized.length < 20) return true
  if (words.length > 0 && uniqueCount <= Math.max(2, Math.floor(words.length * 0.35))) return true
  if (!hasMeaningfulKeywords(normalized)) return true
  return false
}

export function buildGeneratedParagraph(structured = {}) {
  const answer = typeof structured.answer === 'object'
    ? Object.entries(structured.answer).map(([k, v]) => `${k.toUpperCase()}: ${v}`).join(', ')
    : structured.answer
  const owner = String(structured.owner_role || '').trim()
  const tool = String(structured.tooling || '').trim()
  const freq = String(structured.control_frequency || '').trim()
  const evidence = String(structured.evidence_ref || '').trim()
  const answerText = String(answer || '').trim()
  if (!owner || !tool || !freq || !evidence || !answerText) {
    return `Hint: answer in simple business language. Include: who owns it, how it is done, tool used, review frequency, and where evidence is stored.`
  }
  return `${structured.sectionTitle || 'This section'}: ${answerText}. Owner: ${owner}. Execution tool: ${tool}. Review frequency: ${freq}. Evidence: ${evidence}.`.trim()
}

function hasValue(value, field) {
  if (value === null || value === undefined) return false
  if (Array.isArray(value)) return value.length > 0
  if (typeof value === 'object') return Object.values(value).some((v) => String(v || '').trim().length > 0)
  const text = String(value).trim()
  if (!text) return false
  if (field?.minChars && text.length < field.minChars) return false
  return true
}

export function validateStructuredAnswers(questionPack, answerMap = {}) {
  const errors = []
  const weakWarnings = []
  for (const section of questionPack.sections) {
    for (const question of section.questions) {
      const answer = answerMap[question.id] || {}
      for (const field of question.fields || []) {
        if (!field.required) continue
        const rawValue = answer[field.key]
        if (!hasValue(rawValue, field)) {
          errors.push({
            section: section.key,
            questionId: question.id,
            field: field.key,
            message: `${section.title}: ${field.label} is required`
          })
          continue
        }
        if (['long_text', 'tag_list'].includes(field.type) && detectWeakAnswer(rawValue)) {
          weakWarnings.push({
            section: section.key,
            questionId: question.id,
            field: field.key,
            message: 'Answer too weak for policy generation'
          })
        }
      }
    }
  }
  return {
    valid: errors.length === 0,
    errors,
    weakWarnings
  }
}

export function computeSectionCompletion(question, answer = {}) {
  const fields = question.fields || []
  if (fields.length === 0) return 0
  const completed = fields.filter((field) => {
    if (!field.required) return true
    const value = answer[field.key]
    if (!hasValue(value, field)) return false
    if (['long_text', 'tag_list'].includes(field.type) && detectWeakAnswer(value)) return false
    return true
  }).length
  return Math.round((completed / fields.length) * 100)
}
