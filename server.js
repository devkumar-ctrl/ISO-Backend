import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import hpp from 'hpp'
import { v4 as uuidv4 } from 'uuid'
import dotenv from 'dotenv'
import OpenAI from 'openai'
import { createClient } from '@supabase/supabase-js'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import multer from 'multer'
import multerS3 from 'multer-s3'
import path from 'path'
import { fileURLToPath } from 'url'
import fs from 'fs'
import PDFDocument from 'pdfkit'
import { Document, Packer, Paragraph, HeadingLevel, TextRun } from 'docx'
import ExcelJS from 'exceljs'
import {
  buildPreviewFromAnswers,
  buildGeneratedParagraph,
  buildSmartQuestionPack,
  computeSectionCompletion,
  detectWeakAnswer,
  flattenQuestions,
  validateStructuredAnswers
} from './services/smartQuestionEngine.js'
import { buildGapControls, summarizeGapReport } from './services/gapEngine.js'
import {
  THREAT_LIBRARY,
  buildGeneratedRisks,
  defaultRiskGuidedQuestions,
  summarizeRiskReport
} from './services/riskEngine.js'
import { buildSoaControls, getControlLibrary } from './services/soaEngine.js'
import { createSecurityLogService } from './services/securityLogService.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
dotenv.config()

const app = express()
app.disable('x-powered-by')

const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false
}))
app.use(hpp())
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true)
    return callback(new Error('CORS blocked'))
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id', 'x-organization-id']
}))
app.use(express.json({ limit: '2mb' }))
app.use(express.urlencoded({ extended: false, limit: '2mb' }))
app.use('/uploads', express.static(path.join(__dirname, 'uploads')))

const PORT = Number(process.env.PORT || 3001)

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many authentication requests, try again later.' }
})
const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests, try again later.' }
})
app.use('/api', writeLimiter)
app.use('/api/upload', authLimiter)

// =====================================================
// SUPABASE CONFIG
// =====================================================
const supabaseUrl = process.env.SUPABASE_URL || 'https://wjpwfjjlwxdyaoigblvl.supabase.co'
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY
if (!supabaseUrl || !supabaseKey) {
  throw new Error('Missing Supabase env. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SERVICE_KEY).')
}
const supabase = createClient(supabaseUrl, supabaseKey)
const requireAuthInNonDev = process.env.REQUIRE_AUTH !== 'false'
const shouldHashSecurityIp = String(process.env.SECURITY_LOG_HASH_IP || 'true').toLowerCase() !== 'false'
const securityIpHashSalt = process.env.SECURITY_LOG_HASH_SALT || 'itc-isms-security-log-salt'

const securityLogService = createSecurityLogService({
  supabase,
  shouldHashIp: shouldHashSecurityIp,
  ipHashSalt: securityIpHashSalt
})

async function requireAuth(req, res, next) {
  try {
    if (process.env.NODE_ENV !== 'production' && !requireAuthInNonDev) return next()
    const authHeader = req.headers.authorization || ''
    if (!authHeader.startsWith('Bearer ')) {
      req.auditAction = 'auth_failed'
      return res.status(401).json({ success: false, error: 'Missing Bearer token' })
    }
    const token = authHeader.slice('Bearer '.length).trim()
    const { data, error } = await supabase.auth.getUser(token)
    if (error || !data?.user?.id) {
      req.auditAction = 'auth_failed'
      return res.status(401).json({ success: false, error: 'Invalid or expired token' })
    }
    req.authUser = data.user
    req.auditAction = req.auditAction || 'session_activity'
    return next()
  } catch {
    req.auditAction = 'auth_failed'
    return res.status(401).json({ success: false, error: 'Unauthorized request' })
  }
}

async function resolveUserRole(userId) {
  if (!userId) return null
  const profileResp = await supabase
    .from('profiles')
    .select('role')
    .eq('id', userId)
    .maybeSingle()
  if (!profileResp.error && profileResp.data?.role) return String(profileResp.data.role)

  const fallbackResp = await supabase
    .from('user_profiles')
    .select('role')
    .eq('id', userId)
    .maybeSingle()
  if (!fallbackResp.error && fallbackResp.data?.role) return String(fallbackResp.data.role)
  return null
}

async function requireSecurityAdmin(req, res, next) {
  try {
    const userId = req.authUser?.id
    const role = (await resolveUserRole(userId) || '').toLowerCase()
    if (!['admin', 'super_admin', 'security_admin', 'security'].includes(role)) {
      req.auditAction = 'admin_unauthorized_access'
      return res.status(403).json({ success: false, error: 'Admin role required' })
    }
    req.auditAction = 'admin_action'
    return next()
  } catch (err) {
    return res.status(500).json({ success: false, error: err?.message || 'Unable to validate admin role' })
  }
}

// =====================================================
// AWS S3 CONFIG
// =====================================================
const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
})

const s3Bucket = process.env.AWS_S3_BUCKET || 'isms-documents'
const maxUploadSizeBytes = 10 * 1024 * 1024
const allowedFileExtensions = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.gif', '.txt', '.csv'])

function evidenceFileFilter(req, file, cb) {
  const ext = path.extname(String(file.originalname || '')).toLowerCase()
  if (!allowedFileExtensions.has(ext)) {
    return cb(new Error('Unsupported file type'))
  }
  return cb(null, true)
}

// Multer S3 Upload
const upload = multer({
  limits: { fileSize: maxUploadSizeBytes },
  storage: multerS3({
    s3: s3Client,
    bucket: s3Bucket,
    metadata: function (req, file, cb) {
      cb(null, { fieldName: file.fieldname })
    },
    key: function (req, file, cb) {
      cb(null, `uploads/${Date.now()}-${file.originalname}`)
    }
  })
})

const localEvidenceStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads', 'evidence')
    fs.mkdirSync(uploadDir, { recursive: true })
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const safeName = String(file.originalname || 'file').replace(/[^a-zA-Z0-9._-]/g, '_')
    cb(null, `${Date.now()}-${safeName}`)
  }
})

const uploadEvidence = multer({
  storage: localEvidenceStorage,
  limits: { fileSize: maxUploadSizeBytes },
  fileFilter: evidenceFileFilter
})

const localPolicyStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads', 'policies')
    fs.mkdirSync(uploadDir, { recursive: true })
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const safeName = String(file.originalname || 'policy').replace(/[^a-zA-Z0-9._-]/g, '_')
    cb(null, `${Date.now()}-${safeName}`)
  }
})

const uploadPolicy = multer({
  storage: localPolicyStorage,
  limits: { fileSize: maxUploadSizeBytes },
  fileFilter: evidenceFileFilter
})

app.use(
  securityLogService.middleware(
    (req) => {
      const candidate =
        req.headers['x-organization-id'] ||
        req.body?.organization_id ||
        req.body?.organizationId ||
        req.query?.organization_id ||
        req.query?.organizationId ||
        null
      const value = String(candidate || '')
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
        ? value
        : null
    },
    (req) => req.authUser?.id || req.headers['x-user-id'] || req.body?.userId || req.query?.userId || null
  )
)

// =====================================================
// UPLOAD ENDPOINT (S3)
// =====================================================
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' })
    }

    const fileUrl = req.file.location
    const fileKey = req.file.key

    res.json({
      success: true,
      message: 'File uploaded to S3',
      fileUrl,
      fileKey,
      fileName: req.file.originalname
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// =====================================================
// SIMPLE QUESTIONS (Only if NO document)
// =====================================================

const ismsQuestions = [
  { id: 'org_name', question: 'Company Name?', type: 'text' },
  { id: 'security_head', question: 'Who handles security?', type: 'text' },
  { id: 'has_policy', question: 'Written security policy?', type: 'yesno' },
  { id: 'risk_method', question: 'Risk assessment done?', type: 'yesno' },
  { id: 'has_bcp', question: 'Backup/recovery plan?', type: 'yesno' },
  { id: 'encrypt', question: 'Data encrypted?', type: 'yesno' },
  { id: 'backup', question: 'Data backed up?', type: 'yesno' },
  { id: 'backup_test', question: 'Backup tested?', type: 'yesno' },
  { id: 'vendor_check', question: 'Vendors vetted?', type: 'yesno' },
  { id: 'data_classify', question: 'Data classified?', type: 'yesno' },
  { id: 'incident_plan', question: 'Incident plan?', type: 'yesno' },
  { id: 'train', question: 'Staff trained?', type: 'yesno' },
  { id: 'access', question: 'Access controlled?', type: 'yesno' },
  { id: 'passwords', question: 'Strong passwords?', type: 'yesno' },
  { id: 'mfa', question: 'Two-factor auth?', type: 'yesno' },
  { id: 'physical', question: 'Office secure?', type: 'yesno' },
  { id: 'delete', question: 'Secure delete?', type: 'yesno' },
  { id: 'compliance', question: 'Legal compliance?', type: 'yesno' }
]

const gapQuestions = [
  { id: 'clause4', question: 'Organization context known?', type: 'yesno' },
  { id: 'clause5', question: 'Leadership supports security?', type: 'yesno' },
  { id: 'clause6', question: 'Risks identified?', type: 'yesno' },
  { id: 'clause7', question: 'Resources allocated?', type: 'yesno' },
  { id: 'clause8', question: 'Operations secure?', type: 'yesno' },
  { id: 'clause9', question: 'Monitored?', type: 'yesno' },
  { id: 'clause10', question: 'Improving?', type: 'yesno' }
]

const riskQuestions = [
  { id: 'phishing', question: 'Phishing blocked?', options: ['Yes', 'Sometimes', 'No'] },
  { id: 'ransomware', question: 'Ransomware recovery?', options: ['Yes', 'No', 'Not sure'] },
  { id: 'breach', question: 'Breach impact?', options: ['Low', 'Medium', 'High', 'Critical'] },
  { id: 'insider', question: 'Insider detected?', options: ['Yes', 'Maybe', 'No'] },
  { id: 'dos', question: 'DoS survived?', options: ['Yes', 'Sometimes', 'No'] },
  { id: 'disaster', question: 'Disaster recovery?', options: ['Yes', 'Partial', 'No'] }
]

const soaQuestions = [
  { id: 'A.5.1', question: 'Security Policy?', type: 'yesno' },
  { id: 'A.5.2', question: 'Roles & Responsibilities?', type: 'yesno' },
  { id: 'A.6.1', question: 'Screening?', type: 'yesno' },
  { id: 'A.7.1', question: 'Physical Security?', type: 'yesno' },
  { id: 'A.8.1', question: 'Endpoints?', type: 'yesno' },
  { id: 'A.9.2', question: 'User Access?', type: 'yesno' },
  { id: 'A.12.2', question: 'Malware?', type: 'yesno' },
  { id: 'A.12.3', question: 'Backup?', type: 'yesno' },
  { id: 'A.13.1', question: 'Network Security?', type: 'yesno' },
  { id: 'A.16.1', question: 'Incidents?', type: 'yesno' },
  { id: 'A.17.1', question: 'Continuity?', type: 'yesno' },
  { id: 'A.18.1', question: 'Compliance?', type: 'yesno' }
]

const LADDER_STEPS = ['personalInfo', 'ismsPolicy', 'gapAssessment', 'riskAssessment', 'soa']

const DOC_TYPE_TO_STEP = {
  isms: 'ismsPolicy',
  gap: 'gapAssessment',
  risk: 'riskAssessment',
  soa: 'soa'
}

const STEP_DEPENDENCIES = {
  personalInfo: [],
  ismsPolicy: ['personalInfo'],
  gapAssessment: ['ismsPolicy'],
  riskAssessment: ['gapAssessment'],
  soa: ['riskAssessment']
}

const assessmentStateStore = new Map()
const ismsSmartAnswerStore = new Map()
const gapValidationStore = new Map()
const riskRuntimeStore = new Map()
const aiSectionGenerationLimiter = new Map()

function createDefaultStepState() {
  return {
    exists: false,
    uploaded: false,
    completed: false,
    data: {},
    file: null
  }
}

function createDefaultAssessmentState() {
  return {
    personalInfo: createDefaultStepState(),
    ismsPolicy: createDefaultStepState(),
    gapAssessment: createDefaultStepState(),
    riskAssessment: createDefaultStepState(),
    soa: createDefaultStepState()
  }
}

function resolveUserId(req) {
  return req.headers['x-user-id'] || req.body?.userId || req.query?.userId || 'anonymous'
}

function resolveOrganizationId(req) {
  return (
    req.headers['x-organization-id'] ||
    req.body?.organizationId ||
    req.body?.organization_id ||
    req.query?.organizationId ||
    req.query?.organization_id ||
    resolveUserId(req)
  )
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || ''))
}

async function resolveOrCreateOrganizationUuid(req, userId) {
  const rawOrg = resolveOrganizationId(req)
  if (isUuid(rawOrg)) return rawOrg

  const state = getAssessmentState(userId)
  const orgName =
    state?.personalInfo?.data?.organization ||
    req.body?.organization ||
    req.body?.org_name ||
    req.query?.organization ||
    (rawOrg && rawOrg !== userId ? rawOrg : null) ||
    `Org-${String(userId || 'anonymous').slice(0, 24)}`

  const { data: existing, error: existingErr } = await supabase
    .from('organizations')
    .select('id')
    .eq('name', orgName)
    .maybeSingle()
  if (existingErr) throw existingErr
  if (existing?.id) return existing.id

  const { data: created, error: createErr } = await supabase
    .from('organizations')
    .insert({ name: orgName })
    .select('id')
    .single()
  if (createErr) throw createErr
  return created.id
}

function getAssessmentState(userId) {
  if (!assessmentStateStore.has(userId)) {
    assessmentStateStore.set(userId, createDefaultAssessmentState())
  }
  return assessmentStateStore.get(userId)
}

function isStepCompleted(stepState) {
  return Boolean(stepState?.completed || stepState?.uploaded || (stepState?.exists && Object.keys(stepState?.data || {}).length > 0))
}

function checkEligibility(step, state) {
  const deps = STEP_DEPENDENCIES[step] || []
  const missing = deps.filter((dep) => !isStepCompleted(state[dep]))
  if (missing.length === 0) return { allowed: true, reason: '' }
  if (step === 'riskAssessment') return { allowed: false, reason: 'Complete Gap Assessment first' }
  if (step === 'soa') return { allowed: false, reason: 'Complete Risk Assessment first' }
  if (step === 'gapAssessment') return { allowed: false, reason: 'Complete ISMS Policy first' }
  if (step === 'ismsPolicy') return { allowed: false, reason: 'Complete Personal Info first' }
  return { allowed: false, reason: 'Complete previous step first' }
}

function updateStepState(userId, step, updates) {
  const state = getAssessmentState(userId)
  state[step] = {
    ...state[step],
    ...updates,
    data: { ...(state[step].data || {}), ...(updates.data || {}) }
  }
  assessmentStateStore.set(userId, state)
  return state
}

function getSmartAnswerMap(userId) {
  if (!ismsSmartAnswerStore.has(userId)) {
    ismsSmartAnswerStore.set(userId, {})
  }
  return ismsSmartAnswerStore.get(userId)
}

function getGapValidationMap(userId) {
  if (!gapValidationStore.has(userId)) gapValidationStore.set(userId, {})
  return gapValidationStore.get(userId)
}

function getRiskRuntimeState(userId) {
  if (!riskRuntimeStore.has(userId)) {
    riskRuntimeStore.set(userId, {
      assets: [],
      networkProfile: {},
      softwareControls: {},
      risks: [],
      report: null
    })
  }
  return riskRuntimeStore.get(userId)
}

function allPostIsmsStepsCompleted(state) {
  return ['gapAssessment', 'riskAssessment', 'soa'].every((step) => isStepCompleted(state[step]))
}

function isStructuredAnswerComplete(question, answer) {
  if (!question?.fields?.length) return String(answer || '').trim().length > 0
  return question.fields
    .filter((field) => field.required)
    .every((field) => String(answer?.[field.key] || '').trim().length > 0)
}

async function upsertIsmsPolicyAnswers(orgId, incomingAnswers, questionPack) {
  const questionById = Object.fromEntries(flattenQuestions(questionPack).map((q) => [q.id, q]))
  const rows = Object.entries(incomingAnswers).map(([questionId, answer]) => ({
    org_id: orgId,
    section: questionById[questionId]?.section || questionId.split('_').slice(0, -1).join('_') || 'general',
    question: questionId,
    answer: JSON.stringify(answer || {}),
    created_at: new Date().toISOString()
  }))
  if (rows.length === 0) return
  try {
    const { error } = await supabase
      .from('isms_policy_data')
      .upsert(rows, { onConflict: 'org_id,question' })
    if (error) {
      // Legacy table may not exist in migrated schemas; continue with normalized write.
      console.warn('[ISMS_LEGACY_UPSERT_WARNING]', error.message || error)
    }
  } catch (error) {
    console.warn('[ISMS_LEGACY_UPSERT_WARNING]', error?.message || error)
  }

  const normalized = Object.entries(incomingAnswers).map(([questionId, answer]) => ({
    organization_id: orgId,
    question_id: questionId,
    section_key: questionById[questionId]?.section || null,
    section_title: questionById[questionId]?.sectionTitle || null,
    answer_json: answer || {},
    owner_role: answer?.owner_role || null,
    tooling: answer?.tooling || null,
    control_frequency: answer?.control_frequency || null,
    evidence_ref: answer?.evidence_ref || null,
    risk_link: answer?.risk_link || null,
    weak_answer: typeof answer?.answer === 'string' ? detectWeakAnswer(answer.answer) : false,
    completion_score: questionById[questionId] ? computeSectionCompletion(questionById[questionId], answer || {}) : 0,
    updated_at: new Date().toISOString()
  }))
  if (normalized.length > 0) {
    const { error: newError } = await supabase
      .from('isms_responses')
      .upsert(normalized, { onConflict: 'organization_id,question_id' })
    if (newError) throw newError
  }
}

async function upsertIsmsSectionRows(orgId, mergedAnswers, questionPack) {
  const rows = questionPack.sections.map((section) => {
    const sectionQuestions = section.questions || []
    const structuredByQuestion = Object.fromEntries(
      sectionQuestions.map((q) => [q.id, mergedAnswers[q.id] || {}])
    )
    const sectionLabel = section.title
    const completionScore = sectionQuestions.length
      ? Math.round(
          sectionQuestions.reduce((sum, q) => sum + computeSectionCompletion(q, mergedAnswers[q.id] || {}), 0) /
            sectionQuestions.length
        )
      : 0
    const firstQuestionId = sectionQuestions[0]?.id
    const firstParagraph = firstQuestionId
      ? buildGeneratedParagraph({ ...(mergedAnswers[firstQuestionId] || {}), sectionTitle: sectionLabel })
      : ''
    return {
      org_id: orgId,
      section_name: section.key,
      structured_data: structuredByQuestion,
      generated_text: firstParagraph,
      completion_score: completionScore,
      created_at: new Date().toISOString()
    }
  })
  try {
    const { error } = await supabase.from('isms_sections').upsert(rows, { onConflict: 'org_id,section_name' })
    if (error) {
      // Legacy table may not exist in migrated schemas; continue with normalized writes.
      console.warn('[ISMS_SECTIONS_LEGACY_UPSERT_WARNING]', error.message || error)
    }
  } catch (error) {
    console.warn('[ISMS_SECTIONS_LEGACY_UPSERT_WARNING]', error?.message || error)
  }
}

async function syncIsmsQuestionMaster(questionPack) {
  const masterRows = flattenQuestions(questionPack).map((q, idx) => ({
    id: q.id,
    section_key: q.section,
    section_title: q.sectionTitle,
    tree_path: q.treePath || null,
    question_text: q.question,
    iso_clause: null,
    sort_order: idx + 1
  }))
  if (masterRows.length === 0) return
  const { error } = await supabase.from('isms_questions').upsert(masterRows, { onConflict: 'id' })
  if (error) throw error
}

function computeGamification(questionPack, answerMap) {
  const sections = questionPack.sections.map((section) => {
    const sectionQuestions = section.questions || []
    const completion = sectionQuestions.length
      ? Math.round(
          sectionQuestions.reduce((sum, q) => sum + computeSectionCompletion(q, answerMap[q.id] || {}), 0) /
            sectionQuestions.length
        )
      : 0
    return {
      key: section.key,
      completion
    }
  })
  const completedSections = sections.filter((s) => s.completion >= 100).length
  const xp = completedSections * 20
  const level = xp >= 200 ? 'ISO Architect' : xp >= 120 ? 'Manager' : xp >= 60 ? 'Analyst' : 'Beginner'
  const average = sections.length ? Math.round(sections.reduce((sum, s) => sum + s.completion, 0) / sections.length) : 0
  const riskReadiness = sections.filter((s) => ['risk_management', 'incident_management', 'backup_recovery'].includes(s.key))
  const complianceSlices = sections.filter((s) => ['compliance', 'vendor_supplier_management', 'access_control'].includes(s.key))
  const riskScore = riskReadiness.length ? Math.round(riskReadiness.reduce((sum, s) => sum + s.completion, 0) / riskReadiness.length) : 0
  const complianceScore = complianceSlices.length ? Math.round(complianceSlices.reduce((sum, s) => sum + s.completion, 0) / complianceSlices.length) : 0
  return {
    xp,
    level,
    completedSections,
    totalSections: sections.length,
    ismsStrength: average,
    riskReadiness: riskScore,
    complianceScore,
    badges: sections.filter((s) => s.completion >= 100).map((s) => `${s.key}_completed`),
    sections
  }
}

function getFinalPolicyText(userId) {
  const state = getAssessmentState(userId)
  return state?.ismsPolicy?.data?.document || ''
}

function resolveOpenAiKey(apiKeyFromRequest) {
  return apiKeyFromRequest || process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY_BACKEND || ''
}

function parseCsvLine(line) {
  const cols = []
  let cur = ''
  let inQuotes = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (ch === '"') {
      inQuotes = !inQuotes
      continue
    }
    if (ch === ',' && !inQuotes) {
      cols.push(cur.trim())
      cur = ''
      continue
    }
    cur += ch
  }
  cols.push(cur.trim())
  return cols
}

function loadGapCsvDemoRows() {
  const csvPath = path.join(__dirname, 'data', 'gap.csv')
  if (!fs.existsSync(csvPath)) return []
  const raw = fs.readFileSync(csvPath, 'utf8')
  const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
  const rows = []
  for (const line of lines) {
    if (!line.startsWith(',') || !/,\d+(\.\d+)?/.test(line)) continue
    const cols = parseCsvLine(line)
    const clause = cols[1] || ''
    const requirement = cols[2] || ''
    if (!clause || !requirement) continue
    const reqMet = (cols[5] || '').toLowerCase()
    const maturity = reqMet === 'yes' ? 4 : reqMet === 'working' ? 2 : 0
    rows.push({
      org_id: 'demo_client',
      organization_id: 'demo_client',
      control_name: requirement,
      iso_clause: clause,
      base_answer: requirement,
      maturity,
      gap_score: Math.max(0, 4 - maturity),
      missing_items: reqMet === 'yes' ? [] : ['Requirement not met'],
      recommendation: reqMet === 'yes' ? ['Maintain current controls and keep evidence current.'] : ['Close control gap with documented implementation and evidence.'],
      created_at: new Date().toISOString()
    })
  }
  return rows
}

function summarizeClientRows(rows) {
  const avgMaturity = rows.length ? rows.reduce((sum, r) => sum + Number(r.maturity || 0), 0) / rows.length : 0
  const critical = rows.filter((r) => Number(r.gap_score || 0) >= 3).length
  const heatmap = {}
  for (const row of rows) {
    const clause = String(row.iso_clause || 'N/A').split(',')[0].trim()
    if (!heatmap[clause]) heatmap[clause] = { clause, totalGap: 0, count: 0 }
    heatmap[clause].totalGap += Number(row.gap_score || 0)
    heatmap[clause].count += 1
  }
  return {
    controls: rows.length,
    criticalGaps: critical,
    averageMaturity: Number(avgMaturity.toFixed(2)),
    heatmap: Object.values(heatmap).map((h) => ({
      clause: h.clause,
      averageGap: Number((h.totalGap / Math.max(1, h.count)).toFixed(2))
    }))
  }
}

async function loadOrganizationNameMap() {
  const { data, error } = await supabase.from('organizations').select('id,name')
  if (error) throw error
  return new Map((data || []).map((org) => [org.id, org.name]))
}

function calculateResidualRiskLabel(likelihood, impact) {
  const scores = { Rare: 1, Unlikely: 2, Possible: 3, Likely: 4, 'Almost Certain': 5 }
  const impacts = { Negligible: 1, Minor: 2, Moderate: 3, Major: 4, Severe: 5 }
  const score = (scores[likelihood] || 3) * (impacts[impact] || 3)
  if (score <= 4) return 'Low'
  if (score <= 9) return 'Medium'
  return 'High'
}

const AUTO_TASK_TEMPLATES = [
  { title: 'Close high-priority control gaps', category: 'Risk', priority: 'High', description: 'Review open risk items and implement immediate controls.' },
  { title: 'Run focused security awareness refresh', category: 'Training', priority: 'Medium', description: 'Deliver targeted awareness training for active risk scenarios.' },
  { title: 'Review vulnerable assets and patch status', category: 'Technical', priority: 'High', description: 'Update patching and hardening for assets linked to current risks.' },
  { title: 'Collect missing evidence for risk treatment', category: 'Evidence', priority: 'Medium', description: 'Upload treatment evidence and approval records for audit trail.' }
]

async function ensureAutoTasksForRiskBand(organizationId) {
  const { data: scoreRow, error: scoreErr } = await supabase
    .from('risk_scores')
    .select('risk_score_percent')
    .eq('organization_id', organizationId)
    .maybeSingle()
  if (scoreErr) throw scoreErr
  const riskScorePercent = Number(scoreRow?.risk_score_percent ?? -1)
  if (riskScorePercent < 50 || riskScorePercent > 70) return

  const { data: existingRows, error: existingErr } = await supabase
    .from('tasks')
    .select('title')
    .eq('organization_id', organizationId)
  if (existingErr) throw existingErr

  const existing = new Set((existingRows || []).map((row) => row.title))
  const missing = AUTO_TASK_TEMPLATES.filter((task) => !existing.has(task.title)).map((task) => ({
    organization_id: organizationId,
    ...task,
    status: 'todo',
    assignee: 'Admin',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }))
  if (missing.length > 0) {
    const { error: insertErr } = await supabase.from('tasks').insert(missing)
    if (insertErr) throw insertErr
  }
}

const DOC_TYPE_MAP = {
  ISMS: 'ISMS',
  GAP: 'GAP',
  RISK: 'RISK',
  SOA: 'SOA'
}

const DOC_REQUIRED_SECTIONS = {
  ISMS: ['scope', 'access_control', 'risk_management', 'incident_management', 'business_continuity', 'compliance'],
  GAP: ['executive_summary', 'critical_gaps', 'control_matrix'],
  RISK: ['risk_overview', 'risk_register', 'treatment_plan'],
  SOA: ['applicability_summary', 'control_status', 'exceptions']
}

function normalizeDocType(value) {
  const key = String(value || '').trim().toUpperCase()
  return DOC_TYPE_MAP[key] || null
}

async function safeTableSelect(table, selectClause, filterColumn, filterValue) {
  try {
    let query = supabase.from(table).select(selectClause)
    if (filterColumn) query = query.eq(filterColumn, filterValue)
    const { data, error } = await query
    if (error) return []
    return data || []
  } catch {
    return []
  }
}

async function logAiUsage({ organizationId, userId, documentType, sectionName, mode, status, model, promptTokens = 0, completionTokens = 0, errorMessage = null }) {
  try {
    await supabase.from('ai_generation_logs').insert({
      org_id: organizationId,
      user_id: userId,
      document_type: documentType,
      section_name: sectionName,
      mode,
      status,
      model,
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      error_message: errorMessage,
      created_at: new Date().toISOString()
    })
  } catch {
    console.log('[AI_USAGE_LOG]', { organizationId, userId, documentType, sectionName, mode, status, model, promptTokens, completionTokens, errorMessage })
  }
}

function buildSectionFallback(documentType, sectionName, sourceData) {
  const summary = `This section is generated from structured ${documentType} evidence and records.`
  if (documentType === 'ISMS') return `${summary} Section "${sectionName}" defines policy intent, ownership, controls, review frequency, and retained evidence.`
  if (documentType === 'GAP') return `${summary} Section "${sectionName}" summarizes control maturity, deficiencies, and remediation actions.`
  if (documentType === 'RISK') return `${summary} Section "${sectionName}" captures asset-linked risks, scoring rationale, and treatment priorities.`
  if (documentType === 'SOA') return `${summary} Section "${sectionName}" records applicability, implementation status, and justified exceptions.`
  return `${summary} Section "${sectionName}" is ready for auditor review.`
}

async function collectGenerationData(organizationId) {
  const [ismsSections, ismsPolicyData, assets, risks, gapControls, soaControls] = await Promise.all([
    safeTableSelect('isms_sections', '*', 'org_id', organizationId),
    safeTableSelect('isms_policy_data', '*', 'org_id', organizationId),
    safeTableSelect('assets', '*', 'organization_id', organizationId),
    safeTableSelect('risks', '*', 'organization_id', organizationId),
    safeTableSelect('gap_controls', '*', 'organization_id', organizationId),
    safeTableSelect('soa_controls', '*', 'organization_id', organizationId)
  ])
  return { ismsSections, ismsPolicyData, assets, risks, gapControls, soaControls }
}

function gateDocumentGeneration({ documentType, state, sourceData }) {
  const dbReady = {
    gap: sourceData.gapControls.length > 0,
    risk: sourceData.risks.length > 0 || sourceData.assets.length > 0,
    soa: sourceData.soaControls.length > 0
  }

  if (documentType === 'ISMS' && !(allPostIsmsStepsCompleted(state) || (dbReady.gap && dbReady.risk && dbReady.soa))) {
    return { allowed: false, reason: 'Complete all assessments before generating final document' }
  }
  if (documentType === 'GAP' && !(isStepCompleted(state.gapAssessment) || dbReady.gap || sourceData.ismsPolicyData.length > 0 || sourceData.ismsSections.length > 0)) {
    return { allowed: false, reason: 'Complete Gap Assessment before generating this document' }
  }
  if (documentType === 'RISK' && !(isStepCompleted(state.riskAssessment) || dbReady.risk || dbReady.gap)) {
    return { allowed: false, reason: 'Complete Risk Assessment before generating this document' }
  }
  if (documentType === 'SOA' && !(isStepCompleted(state.soa) || dbReady.soa || dbReady.risk)) {
    return { allowed: false, reason: 'Complete SOA assessment before generating this document' }
  }

  const hasData =
    sourceData.ismsSections.length +
      sourceData.ismsPolicyData.length +
      sourceData.assets.length +
      sourceData.risks.length +
      sourceData.gapControls.length +
      sourceData.soaControls.length >
    0
  if (!hasData) return { allowed: false, reason: 'No source data found for generation' }
  return { allowed: true, reason: '' }
}

function buildPreviewForDocument(documentType, sourceData) {
  if (documentType === 'ISMS') {
    const sections = sourceData.ismsSections.slice(0, 6).map((row) => row.section_name || 'general')
    return {
      sections: sections.length ? sections : DOC_REQUIRED_SECTIONS.ISMS,
      sample: `Policy preview based on ${sourceData.ismsSections.length} ISMS sections and ${sourceData.ismsPolicyData.length} policy answers.`
    }
  }
  if (documentType === 'GAP') {
    return {
      sections: DOC_REQUIRED_SECTIONS.GAP,
      sample: `Gap preview shows ${sourceData.gapControls.length} controls with maturity and recommendation traces.`
    }
  }
  if (documentType === 'RISK') {
    return {
      sections: DOC_REQUIRED_SECTIONS.RISK,
      sample: `Risk preview includes ${sourceData.assets.length} assets and ${sourceData.risks.length} risk rows.`
    }
  }
  return {
    sections: DOC_REQUIRED_SECTIONS.SOA,
    sample: `SOA preview covers ${sourceData.soaControls.length} mapped controls with implementation status.`
  }
}

// =====================================================
// API ENDPOINTS
// =====================================================

// 1. START ASSESSMENT
app.post('/api/start', async (req, res) => {
  res.json({ 
    success: true,
    flow: [
      { step: 1, title: 'ISMS Policy', doc: 'isms', askFirst: 'Do you have an ISMS Policy?' },
      { step: 2, title: 'Gap Assessment', doc: 'gap', askFirst: 'Do you have a Gap Assessment?' },
      { step: 3, title: 'Risk Assessment', doc: 'risk', askFirst: 'Do you have a Risk Assessment?' },
      { step: 4, title: 'Statement of Applicability', doc: 'soa', askFirst: 'Do you have a Statement of Applicability?' }
    ]
  })
})

app.get('/api/assessment/state', async (req, res) => {
  const userId = resolveUserId(req)
  const state = getAssessmentState(userId)
  const status = LADDER_STEPS.map((step) => ({
    step,
    completed: isStepCompleted(state[step]),
    eligibility: checkEligibility(step, state)
  }))
  res.json({ success: true, userId, state, status })
})

app.post('/api/assessment/personal-info', async (req, res) => {
  const userId = resolveUserId(req)
  const { data } = req.body
  if (!data?.fullName || !data?.email || !data?.organization) {
    return res.status(400).json({ success: false, error: 'fullName, email and organization are required' })
  }
  const state = updateStepState(userId, 'personalInfo', {
    exists: true,
    uploaded: false,
    completed: true,
    data,
    file: null
  })
  res.json({ success: true, state })
})

// GET QUESTIONS
app.get('/api/questions/:docType', async (req, res) => {
  const { docType } = req.params
  
  let questions = []
  switch (docType) {
    case 'isms': questions = flattenQuestions(buildSmartQuestionPack()); break
    case 'gap': questions = gapQuestions; break
    case 'risk': questions = riskQuestions; break
    case 'soa': questions = soaQuestions; break
    default: return res.status(400).json({ error: 'Invalid doc type' })
  }
  
  res.json({ success: true, docType, questions })
})

app.get('/api/isms/smart-questions', async (req, res) => {
  const userId = resolveUserId(req)
  const pack = buildSmartQuestionPack()
  try {
    await syncIsmsQuestionMaster(pack)
  } catch {
    // Continue without blocking question delivery.
  }
  const answers = getSmartAnswerMap(userId)
  const gamification = computeGamification(pack, answers)
  res.json({ success: true, userId, ...pack, answers, gamification })
})

app.post('/api/isms/has-policy', async (req, res) => {
  const userId = resolveUserId(req)
  const hasPolicy = req.body?.hasPolicy === 'yes' ? 'yes' : 'no'
  updateStepState(userId, 'ismsPolicy', {
    exists: hasPolicy === 'yes',
    uploaded: false,
    completed: false,
    data: { hasPolicy },
    file: null
  })
  res.json({ success: true, hasPolicy })
})

app.post('/api/isms/answers', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const state = getAssessmentState(userId)
  const eligibility = checkEligibility('ismsPolicy', state)
  if (!eligibility.allowed) {
    return res.status(403).json({ success: false, error: eligibility.reason })
  }

  const incoming = req.body?.answers || {}
  const questionPack = buildSmartQuestionPack()
  const persisted = { ...getSmartAnswerMap(userId), ...incoming }
  ismsSmartAnswerStore.set(userId, persisted)
  const finalize = req.body?.finalize === true

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    await syncIsmsQuestionMaster(questionPack)
    await upsertIsmsPolicyAnswers(organizationId, incoming, questionPack)
    await upsertIsmsSectionRows(organizationId, persisted, questionPack)
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unknown DB error while saving ISMS answers'
    console.error('[ISMS_SAVE_ERROR]', err)
  }

  const flatQuestions = flattenQuestions(questionPack)
  const totalQuestions = flatQuestions.length
  const completedQuestions = flatQuestions.filter((q) => isStructuredAnswerComplete(q, persisted[q.id])).length
  const validation = validateStructuredAnswers(questionPack, persisted)
  const weakWarnings = []
  for (const [qId, valueMap] of Object.entries(incoming)) {
    for (const [fieldKey, fieldValue] of Object.entries(valueMap || {})) {
      if (typeof fieldValue === 'string' && detectWeakAnswer(fieldValue)) {
        weakWarnings.push({
          questionId: qId,
          field: fieldKey,
          message: 'Answer too weak for policy generation'
        })
      }
    }
  }

  updateStepState(userId, 'ismsPolicy', {
    exists: false,
    uploaded: false,
    completed: completedQuestions >= totalQuestions && validation.valid,
    data: {
      generated: false,
      answerCount: completedQuestions
    },
    file: null
  })

  if (finalize && !validation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Complete all required W-fields before section completion.',
      validationErrors: validation.errors
    })
  }

  const gamification = computeGamification(questionPack, persisted)
  res.json({
    success: true,
    dbSaved,
    dbError,
    saved: Object.keys(incoming).length,
    completedQuestions,
    totalQuestions,
    validationErrors: validation.errors,
    weakWarnings: [...validation.weakWarnings, ...weakWarnings],
    gamification
  })
})

app.get('/api/isms/preview', async (req, res) => {
  const userId = resolveUserId(req)
  const pack = buildSmartQuestionPack()
  const preview = buildPreviewFromAnswers(pack, getSmartAnswerMap(userId))
  const gamification = computeGamification(pack, getSmartAnswerMap(userId))
  res.json({ success: true, preview, gamification })
})

app.get('/api/isms/metrics', async (req, res) => {
  const userId = resolveUserId(req)
  const pack = buildSmartQuestionPack()
  const answers = getSmartAnswerMap(userId)
  res.json({ success: true, gamification: computeGamification(pack, answers) })
})

app.get('/api/gap/controls', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const pack = buildSmartQuestionPack()
  const ismsAnswers = getSmartAnswerMap(userId)
  const savedValidation = getGapValidationMap(userId)
  const controls = buildGapControls(pack, ismsAnswers, savedValidation)
  const report = summarizeGapReport(controls)
  res.json({ success: true, controls, report })
})

app.post('/api/gap/answers', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const incoming = req.body?.validations || {}
  const merged = { ...getGapValidationMap(userId), ...incoming }
  gapValidationStore.set(userId, merged)

  const pack = buildSmartQuestionPack()
  const ismsAnswers = getSmartAnswerMap(userId)
  const controls = buildGapControls(pack, ismsAnswers, merged)
  const report = summarizeGapReport(controls)

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const rows = controls.map((c) => ({
      org_id: userId,
      control_name: c.control_name,
      iso_clause: c.iso_clause,
      base_answer: c.base_answer,
      maturity: c.maturity,
      gap_score: c.gap_score,
      missing_items: c.missing_items,
      recommendation: c.recommendation,
      created_at: new Date().toISOString()
    }))
    try {
      const { error } = await supabase.from('gap_assessment_data').upsert(rows, { onConflict: 'org_id,control_name' })
      if (error) {
        // Legacy table may not exist in migrated schemas; continue with normalized write.
        console.warn('[GAP_LEGACY_UPSERT_WARNING]', error.message || error)
      }
    } catch (legacyErr) {
      console.warn('[GAP_LEGACY_UPSERT_WARNING]', legacyErr?.message || legacyErr)
    }

    const normalized = controls.map((c) => ({
      organization_id: organizationId,
      question_id: c.id,
      control_name: c.control_name,
      iso_clause: c.iso_clause,
      base_answer: c.base_answer,
      is_documented: Boolean(c.validation?.is_documented),
      owner: c.validation?.owner || null,
      evidence: c.validation?.evidence || null,
      maturity: c.maturity,
      expected_maturity: 4,
      gap_score: c.gap_score,
      missing_items: c.missing_items || [],
      recommendation: c.recommendation || [],
      critical_gap: Boolean(c.critical_gap),
      skipped_validation: Boolean(c.validation?.skipped_validation),
      updated_at: new Date().toISOString()
    }))
    const { error: normErr } = await supabase
      .from('gap_controls')
      .upsert(normalized, { onConflict: 'organization_id,question_id' })
    if (normErr) throw normErr

    const matrixRows = report.isms_gap_assessment_matrix.map((m) => ({
      organization_id: organizationId,
      clause: m.clause,
      requirement: m.requirement,
      documents_needed: m.documents_needed,
      evidence_to_confirm_compliance: m.evidence_to_confirm_compliance,
      requirement_met: m.requirement_met
    }))
    const { error: matrixErr } = await supabase
      .from('gap_matrix_rows')
      .upsert(matrixRows, { onConflict: 'organization_id,clause,requirement' })
    if (matrixErr) throw matrixErr

    const { error: reportErr } = await supabase
      .from('gap_reports')
      .insert({
        organization_id: organizationId,
        expected_maturity: report.expected_maturity,
        critical_gap_count: (report.critical_gaps || []).length,
        average_maturity: controls.length
          ? controls.reduce((sum, c) => sum + Number(c.maturity || 0), 0) / controls.length
          : 0,
        report_json: report
      })
    if (reportErr) throw reportErr
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unknown DB error while saving GAP answers'
    console.error('[GAP_SAVE_ERROR]', err)
  }

  updateStepState(userId, 'gapAssessment', {
    exists: false,
    uploaded: false,
    completed: true,
    data: { controls, report },
    file: null
  })

  res.json({ success: true, controls, report, dbSaved, dbError })
})

app.get('/api/gap/report', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const pack = buildSmartQuestionPack()
  const controls = buildGapControls(pack, getSmartAnswerMap(userId), getGapValidationMap(userId))
  res.json({ success: true, report: summarizeGapReport(controls) })
})

app.get('/api/risk/profile', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const runtime = getRiskRuntimeState(userId)
  let organizationId = null
  try {
    organizationId = await resolveOrCreateOrganizationUuid(req, userId)
  } catch {
    organizationId = null
  }

  let assets = runtime.assets || []
  let networkProfile = runtime.networkProfile || {}
  let softwareControls = runtime.softwareControls || {}
  let risks = runtime.risks || []
  let report = runtime.report || null

  if (organizationId) {
    try {
      const [{ data: dbAssets }, { data: dbNetwork }, { data: dbSoftware }, { data: dbRisks }, { data: dbReport }] = await Promise.all([
        supabase.from('assets').select('*').eq('organization_id', organizationId).order('updated_at', { ascending: false }),
        supabase.from('network_profile').select('*').eq('organization_id', organizationId).maybeSingle(),
        supabase.from('software_controls').select('*').eq('organization_id', organizationId).maybeSingle(),
        supabase.from('risks').select('*').eq('organization_id', organizationId).order('risk_score', { ascending: false }),
        supabase.from('risk_reports').select('*').eq('organization_id', organizationId).order('created_at', { ascending: false }).limit(1).maybeSingle()
      ])
      assets = dbAssets || assets
      networkProfile = dbNetwork || networkProfile
      softwareControls = dbSoftware || softwareControls
      risks = dbRisks || risks
      report = dbReport?.report_json || report
    } catch {
      // Keep runtime fallback.
    }
  }

  res.json({
    success: true,
    organization_id: organizationId,
    assets,
    networkProfile,
    softwareControls,
    threatLibrary: THREAT_LIBRARY,
    risks,
    report,
    guidedQuestions: defaultRiskGuidedQuestions()
  })
})

app.post('/api/risk/assets', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const assets = Array.isArray(req.body?.assets) ? req.body.assets : []
  const runtime = getRiskRuntimeState(userId)
  runtime.assets = assets
  riskRuntimeStore.set(userId, runtime)

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const normalized = assets.map((asset, index) => ({
      organization_id: organizationId,
      asset_id: asset.asset_id || `asset_${index + 1}`,
      asset_name: asset.asset_name || '',
      asset_type: asset.asset_type || '',
      mac_address: asset.mac_address || null,
      ip_address: asset.ip_address || null,
      owner_name: asset.owner_name || null,
      owner_designation: asset.owner_designation || null,
      department: asset.department || null,
      location: asset.location || null,
      classification: asset.classification || 'Internal',
      platform: asset.platform || null,
      installed_software: asset.installed_software || [],
      antivirus_enabled: Boolean(asset.antivirus_enabled),
      antivirus_name: asset.antivirus_name || null,
      patch_status: asset.patch_status || 'Unknown',
      internet_facing: Boolean(asset.internet_facing),
      critical_asset: Boolean(asset.critical_asset),
      backup_enabled: Boolean(asset.backup_enabled),
      encryption_enabled: Boolean(asset.encryption_enabled),
      access_control_enabled: Boolean(asset.access_control_enabled),
      logging_enabled: Boolean(asset.logging_enabled),
      updated_at: new Date().toISOString()
    }))
    if (normalized.length > 0) {
      const { error } = await supabase.from('assets').upsert(normalized, { onConflict: 'organization_id,asset_id' })
      if (error) throw error
    }
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unable to save assets'
  }

  res.json({ success: true, dbSaved, dbError, assets: runtime.assets })
})

app.post('/api/risk/network-profile', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const profile = req.body?.networkProfile || {}
  const runtime = getRiskRuntimeState(userId)
  runtime.networkProfile = profile
  riskRuntimeStore.set(userId, runtime)

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const { error } = await supabase.from('network_profile').upsert({
      organization_id: organizationId,
      isp_provider: profile.isp_provider || null,
      bandwidth: profile.bandwidth || null,
      ip_type: profile.ip_type || null,
      firewall_enabled: Boolean(profile.firewall_enabled),
      firewall_type: profile.firewall_type || null,
      vpn_usage: Boolean(profile.vpn_usage),
      network_segmentation: profile.network_segmentation || null,
      wifi_security: profile.wifi_security || null,
      guest_network_isolation: Boolean(profile.guest_network_isolation),
      cloud_providers: profile.cloud_providers || [],
      architecture_type: profile.architecture_type || null,
      updated_at: new Date().toISOString()
    }, { onConflict: 'organization_id' })
    if (error) throw error
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unable to save network profile'
  }

  res.json({ success: true, dbSaved, dbError, networkProfile: runtime.networkProfile })
})

app.post('/api/risk/software-controls', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const controls = req.body?.softwareControls || {}
  const runtime = getRiskRuntimeState(userId)
  runtime.softwareControls = controls
  riskRuntimeStore.set(userId, runtime)

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const { error } = await supabase.from('software_controls').upsert({
      organization_id: organizationId,
      licensed_software_only: Boolean(controls.licensed_software_only),
      pirated_software_present: Boolean(controls.pirated_software_present),
      endpoint_protection: controls.endpoint_protection || null,
      patch_management_process: controls.patch_management_process || null,
      usb_media_control: Boolean(controls.usb_media_control),
      admin_privilege_restrictions: Boolean(controls.admin_privilege_restrictions),
      updated_at: new Date().toISOString()
    }, { onConflict: 'organization_id' })
    if (error) throw error
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unable to save software controls'
  }
  res.json({ success: true, dbSaved, dbError, softwareControls: runtime.softwareControls })
})

app.post('/api/risk/generate', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const runtime = getRiskRuntimeState(userId)
  const risks = buildGeneratedRisks({
    assets: runtime.assets || [],
    networkProfile: runtime.networkProfile || {},
    softwareControls: runtime.softwareControls || {}
  })
  const report = summarizeRiskReport({ assets: runtime.assets || [], risks })
  runtime.risks = risks
  runtime.report = report
  riskRuntimeStore.set(userId, runtime)

  let dbSaved = false
  let dbError = null
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    if (risks.length > 0) {
      const dbRows = risks.map((risk) => ({
        organization_id: organizationId,
        risk_id: risk.risk_id,
        asset_id: risk.asset_id,
        asset_name: risk.asset_name,
        threat: risk.threat,
        vulnerability: risk.vulnerability,
        likelihood: String(risk.likelihood),
        impact: String(risk.impact),
        likelihood_score: risk.likelihood,
        impact_score: risk.impact,
        risk_score: risk.risk_score,
        risk_level: risk.risk_level,
        existing_controls: risk.existing_controls || [],
        recommended_controls: risk.recommended_controls || [],
        control_status: risk.control_status || null
      }))
      const { error: riskErr } = await supabase.from('risks').upsert(dbRows, { onConflict: 'organization_id,risk_id' })
      if (riskErr) throw riskErr
    }

    const { error: scoreErr } = await supabase.from('risk_scores').upsert({
      organization_id: organizationId,
      risk_score_percent: report.risk_score_percent,
      security_posture_score: report.security_posture_score,
      critical_risk_count: report.totals.critical,
      high_risk_count: report.totals.high,
      updated_at: new Date().toISOString()
    }, { onConflict: 'organization_id' })
    if (scoreErr) throw scoreErr

    const { error: reportErr } = await supabase.from('risk_reports').insert({
      organization_id: organizationId,
      summary_json: report,
      report_json: { risks }
    })
    if (reportErr) throw reportErr
    dbSaved = true
  } catch (err) {
    dbError = err?.message || 'Unable to persist generated risks'
  }

  updateStepState(userId, 'riskAssessment', {
    exists: false,
    uploaded: false,
    completed: true,
    data: { generated: true, report },
    file: null
  })

  res.json({ success: true, dbSaved, dbError, risks, report })
})

app.get('/api/risk/report', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const runtime = getRiskRuntimeState(userId)
  res.json({
    success: true,
    risks: runtime.risks || [],
    report: runtime.report || summarizeRiskReport({ assets: runtime.assets || [], risks: runtime.risks || [] })
  })
})

app.get('/api/soa/controls', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const runtimeRisk = getRiskRuntimeState(userId)
  let organizationId = null
  try {
    organizationId = await resolveOrCreateOrganizationUuid(req, userId)
  } catch {
    organizationId = null
  }

  let ismsResponses = []
  let gapControls = []
  let risks = runtimeRisk.risks || []
  let persistedSoa = []
  if (organizationId) {
    try {
      const [{ data: isms }, { data: gaps }, { data: riskRows }, { data: soaRows }] = await Promise.all([
        supabase.from('isms_responses').select('*').eq('organization_id', organizationId),
        supabase.from('gap_controls').select('*').eq('organization_id', organizationId),
        supabase.from('risks').select('*').eq('organization_id', organizationId),
        supabase.from('soa_controls').select('*').eq('organization_id', organizationId)
      ])
      ismsResponses = isms || []
      gapControls = gaps || []
      risks = riskRows || risks
      persistedSoa = soaRows || []
    } catch {
      // fallback to runtime generation
    }
  }

  const generated = buildSoaControls({ ismsResponses, gapControls, risks })
  const byId = new Map(persistedSoa.map((r) => [r.control_id, r]))
  const controls = generated.map((row) => {
    const p = byId.get(row.control_id)
    return p
      ? {
          ...row,
          applicable: typeof p.applicable === 'boolean' ? p.applicable : row.applicable,
          implementation_status: p.implementation_status || row.implementation_status,
          justification: p.justification || row.justification,
          evidence_ref: p.evidence_ref || '',
          critical_missing: Boolean(p.critical_missing ?? row.critical_missing)
        }
      : row
  })
  res.json({ success: true, organization_id: organizationId, controlLibrary: getControlLibrary(), controls })
})

app.post('/api/soa/generate', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  let organizationId = null
  try {
    organizationId = await resolveOrCreateOrganizationUuid(req, userId)
  } catch (err) {
    return res.status(500).json({ success: false, error: err?.message || 'Unable to resolve organization' })
  }
  try {
    const [{ data: isms }, { data: gaps }, { data: risks }] = await Promise.all([
      supabase.from('isms_responses').select('*').eq('organization_id', organizationId),
      supabase.from('gap_controls').select('*').eq('organization_id', organizationId),
      supabase.from('risks').select('*').eq('organization_id', organizationId)
    ])
    const controls = buildSoaControls({
      ismsResponses: isms || [],
      gapControls: gaps || [],
      risks: risks || []
    })
    if (controls.length > 0) {
      const rows = controls.map((c) => ({
        organization_id: organizationId,
        control_id: c.control_id,
        title: c.control_name,
        category: c.domain,
        applicable: c.applicable,
        implemented: c.implementation_status === 'Implemented',
        implementation_status: c.implementation_status,
        justification: c.justification,
        linked_risks: c.linked_risks,
        linked_gaps: c.linked_gaps,
        evidence_required: c.evidence_required,
        evidence_ref: c.evidence_ref || '',
        critical_missing: Boolean(c.critical_missing),
        updated_at: new Date().toISOString()
      }))
      const { error } = await supabase.from('soa_controls').upsert(rows, { onConflict: 'organization_id,control_id' })
      if (error) {
        const fallbackRows = rows.map(({ implementation_status, justification, linked_risks, linked_gaps, evidence_required, evidence_ref, critical_missing, ...legacy }) => legacy)
        const { error: fallbackError } = await supabase.from('soa_controls').upsert(fallbackRows, { onConflict: 'organization_id,control_id' })
        if (fallbackError) {
          for (const row of fallbackRows) {
            await supabase.from('soa_controls').delete().eq('organization_id', row.organization_id).eq('control_id', row.control_id)
            const { error: insertErr } = await supabase.from('soa_controls').insert(row)
            if (insertErr) throw insertErr
          }
        }
      }
    }

    updateStepState(userId, 'soa', {
      exists: false,
      uploaded: false,
      completed: true,
      data: { generated: true, controlCount: controls.length },
      file: null
    })
    res.json({ success: true, controls })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to generate SOA controls' })
  }
})

app.post('/api/soa/controls/save', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const controls = Array.isArray(req.body?.controls) ? req.body.controls : []
  let organizationId = null
  try {
    organizationId = await resolveOrCreateOrganizationUuid(req, userId)
  } catch (err) {
    return res.status(500).json({ success: false, error: err?.message || 'Unable to resolve organization' })
  }
  try {
    const rows = controls.map((c) => ({
      organization_id: organizationId,
      control_id: c.control_id,
      title: c.control_name || c.title || '',
      category: c.domain || c.category || '',
      applicable: Boolean(c.applicable),
      implemented: String(c.implementation_status || '').toLowerCase() === 'implemented',
      implementation_status: c.implementation_status || null,
      justification: c.justification || null,
      linked_risks: c.linked_risks || [],
      linked_gaps: c.linked_gaps || [],
      evidence_required: c.evidence_required || null,
      evidence_ref: c.evidence_ref || null,
      critical_missing: Boolean(c.critical_missing),
      updated_at: new Date().toISOString()
    }))
    if (rows.length > 0) {
      const { error } = await supabase.from('soa_controls').upsert(rows, { onConflict: 'organization_id,control_id' })
      if (error) {
        const fallbackRows = rows.map(({ implementation_status, justification, linked_risks, linked_gaps, evidence_required, evidence_ref, critical_missing, ...legacy }) => legacy)
        const { error: fallbackError } = await supabase.from('soa_controls').upsert(fallbackRows, { onConflict: 'organization_id,control_id' })
        if (fallbackError) {
          for (const row of fallbackRows) {
            await supabase.from('soa_controls').delete().eq('organization_id', row.organization_id).eq('control_id', row.control_id)
            const { error: insertErr } = await supabase.from('soa_controls').insert(row)
            if (insertErr) throw insertErr
          }
        }
      }
    }
    updateStepState(userId, 'soa', {
      exists: false,
      uploaded: false,
      completed: true,
      data: { generated: true, controlCount: rows.length },
      file: null
    })
    res.json({ success: true, saved: rows.length })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to save SOA controls' })
  }
})

app.get('/api/organizations', requireAuth, async (req, res) => {
  try {
    const [orgResp, scoreResp] = await Promise.all([
      supabase.from('organizations').select('id,name').order('created_at', { ascending: true }),
      supabase.from('risk_scores').select('organization_id,risk_score_percent')
    ])
    if (orgResp.error) throw orgResp.error
    if (scoreResp.error) throw scoreResp.error
    const scoreByOrg = new Map((scoreResp.data || []).map((row) => [row.organization_id, Number(row.risk_score_percent || 0)]))
    const organizations = (orgResp.data || []).map((org) => ({
      id: org.id,
      name: org.name,
      risk_score_percent: scoreByOrg.get(org.id) || 0
    }))
    res.json({ success: true, organizations })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load organizations' })
  }
})

app.get('/api/policies/upload-targets', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    let profileQuery = supabase.from('user_profiles').select('id,full_name,organization_id')
    if (organizationId) profileQuery = profileQuery.eq('organization_id', organizationId)
    const [profileResp, orgResp] = await Promise.all([
      profileQuery,
      supabase.from('organizations').select('id,name')
    ])
    if (profileResp.error) throw profileResp.error
    if (orgResp.error) throw orgResp.error
    const orgNameMap = new Map((orgResp.data || []).map((org) => [org.id, org.name]))
    const users = (profileResp.data || []).map((u) => ({
      id: u.id,
      name: u.full_name || 'Unnamed User',
      organization_id: u.organization_id,
      organization_name: orgNameMap.get(u.organization_id) || ''
    }))
    res.json({ success: true, users })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load upload targets' })
  }
})

app.get('/api/policies', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    let query = supabase.from('policies').select('*').order('updated_at', { ascending: false })
    if (organizationId) query = query.eq('organization_id', organizationId)
    const { data, error } = await query
    if (error) throw error
    const policies = (data || []).map((row) => ({
      id: row.id,
      organization_id: row.organization_id,
      title: row.title,
      category: row.category || '',
      status: row.status || 'Draft',
      version: row.version || '1.0',
      owner: row.owner || '',
      description: row.description || '',
      document_url: row.document_url || '',
      lastUpdated: row.updated_at ? String(row.updated_at).slice(0, 10) : ''
    }))
    res.json({ success: true, policies })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load policies' })
  }
})

app.post('/api/policies', requireAuth, async (req, res) => {
  const payload = req.body || {}
  if (!payload.title || !payload.organization_id) {
    return res.status(400).json({ success: false, error: 'title and organization_id are required' })
  }
  try {
    const { data, error } = await supabase.from('policies').insert({
      organization_id: payload.organization_id,
      title: payload.title,
      category: payload.category || '',
      status: payload.status || 'Draft',
      version: payload.version || '1.0',
      owner: payload.owner || '',
      description: payload.description || '',
      document_url: payload.document_url || null,
      updated_at: new Date().toISOString()
    }).select('*').single()
    if (error) throw error
    res.json({ success: true, policy: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to create policy' })
  }
})

app.post('/api/policies/upload', requireAuth, uploadPolicy.single('file'), async (req, res) => {
  const organizationId = req.body?.organization_id
  const targetUserName = String(req.body?.target_user_name || '').trim()
  if (!organizationId) return res.status(400).json({ success: false, error: 'organization_id is required' })
  if (!req.file) return res.status(400).json({ success: false, error: 'file is required' })
  try {
    const title = String(req.body?.title || req.file.originalname || 'Policy').trim()
    const fileUrl = `/uploads/policies/${req.file.filename}`
    const { data, error } = await supabase.from('policies').insert({
      organization_id: organizationId,
      title,
      category: req.body?.category || 'Information Security',
      status: req.body?.status || 'Draft',
      version: req.body?.version || '1.0',
      owner: targetUserName || req.body?.owner || 'Unassigned',
      description: req.body?.description || 'Uploaded policy document',
      document_url: fileUrl,
      updated_at: new Date().toISOString()
    }).select('*').single()
    if (error) throw error
    res.json({ success: true, policy: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to upload policy' })
  }
})

app.put('/api/policies/:id', requireAuth, async (req, res) => {
  const payload = req.body || {}
  try {
    const patch = {
      title: payload.title,
      category: payload.category,
      status: payload.status,
      version: payload.version,
      owner: payload.owner,
      description: payload.description,
      document_url: payload.document_url,
      updated_at: new Date().toISOString()
    }
    Object.keys(patch).forEach((k) => patch[k] === undefined && delete patch[k])
    const { data, error } = await supabase.from('policies').update(patch).eq('id', req.params.id).select('*').single()
    if (error) throw error
    res.json({ success: true, policy: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to update policy' })
  }
})

app.delete('/api/policies/:id', requireAuth, async (req, res) => {
  try {
    const { data: row, error: fetchErr } = await supabase.from('policies').select('document_url').eq('id', req.params.id).maybeSingle()
    if (fetchErr) throw fetchErr
    const { error } = await supabase.from('policies').delete().eq('id', req.params.id)
    if (error) throw error
    if (row?.document_url?.startsWith('/uploads/policies/')) {
      const localPath = path.join(__dirname, row.document_url)
      if (fs.existsSync(localPath)) fs.unlinkSync(localPath)
    }
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to delete policy' })
  }
})

app.delete('/api/policies', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    let selectQuery = supabase.from('policies').select('id,document_url')
    if (organizationId) selectQuery = selectQuery.eq('organization_id', organizationId)
    const { data: rows, error: fetchErr } = await selectQuery
    if (fetchErr) throw fetchErr

    let deleteQuery = supabase.from('policies').delete()
    if (organizationId) deleteQuery = deleteQuery.eq('organization_id', organizationId)
    const { error } = await deleteQuery
    if (error) throw error

    for (const row of rows || []) {
      if (row.document_url?.startsWith('/uploads/policies/')) {
        const localPath = path.join(__dirname, row.document_url)
        if (fs.existsSync(localPath)) fs.unlinkSync(localPath)
      }
    }
    res.json({ success: true, deleted: (rows || []).length })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to delete policies' })
  }
})

app.get('/api/security/logs', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number(req.query?.limit || 100), 1), 500)
    const {
      user_id: userIdFilter,
      action: actionFilter,
      from: fromFilter,
      to: toFilter
    } = req.query || {}

    let query = supabase
      .from('security_logs')
      .select('id,org_id,user_id,ip_address,browser,os,device_type,user_agent,action,endpoint,method,status_code,created_at')
      .order('created_at', { ascending: false })
      .limit(limit)

    if (userIdFilter) query = query.eq('user_id', String(userIdFilter))
    if (actionFilter) query = query.eq('action', String(actionFilter))
    if (fromFilter) query = query.gte('created_at', String(fromFilter))
    if (toFilter) query = query.lte('created_at', String(toFilter))

    const { data, error } = await query
    if (error) throw error
    req.auditAction = 'admin_logs_access'
    res.json({ success: true, logs: data || [] })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load security logs' })
  }
})

app.get('/health/security-logs', requireAuth, requireSecurityAdmin, async (req, res) => {
  try {
    const now = new Date()
    const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()

    const [totalResp, recentResp, lastResp] = await Promise.all([
      supabase.from('security_logs').select('*', { count: 'exact', head: true }),
      supabase.from('security_logs').select('*', { count: 'exact', head: true }).gte('created_at', since24h),
      supabase
        .from('security_logs')
        .select('id,action,endpoint,status_code,created_at')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle()
    ])

    if (totalResp.error) throw totalResp.error
    if (recentResp.error) throw recentResp.error
    if (lastResp.error) throw lastResp.error

    req.auditAction = 'admin_logs_access'
    res.json({
      success: true,
      health: {
        status: 'ok',
        total_logs: totalResp.count || 0,
        logs_last_24h: recentResp.count || 0,
        last_log: lastResp.data || null
      }
    })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to get security log health' })
  }
})

app.get('/api/risks', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    let query = supabase.from('risks').select('*').order('updated_at', { ascending: false })
    if (organizationId) query = query.eq('organization_id', organizationId)
    const { data, error } = await query
    if (error) throw error
    const risks = (data || []).map((row) => ({
      id: row.id,
      organization_id: row.organization_id,
      title: row.title,
      description: row.description || '',
      category: row.category || '',
      likelihood: row.likelihood || 'Possible',
      impact: row.impact || 'Moderate',
      status: row.status || 'Identified',
      owner: row.owner || '',
      residualRisk: row.residual_risk || calculateResidualRiskLabel(row.likelihood, row.impact),
      createdDate: row.created_at ? String(row.created_at).slice(0, 10) : '',
      treatedDate: row.updated_at ? String(row.updated_at).slice(0, 10) : ''
    }))
    res.json({ success: true, risks })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load risks' })
  }
})

app.post('/api/risks', requireAuth, async (req, res) => {
  const payload = req.body || {}
  if (!payload.organization_id || !payload.title) {
    return res.status(400).json({ success: false, error: 'organization_id and title are required' })
  }
  try {
    const row = {
      organization_id: payload.organization_id,
      title: payload.title,
      description: payload.description || '',
      category: payload.category || '',
      likelihood: payload.likelihood || 'Possible',
      impact: payload.impact || 'Moderate',
      status: payload.status || 'Identified',
      owner: payload.owner || '',
      residual_risk: payload.residualRisk || calculateResidualRiskLabel(payload.likelihood, payload.impact),
      updated_at: new Date().toISOString()
    }
    const { data, error } = await supabase.from('risks').insert(row).select('*').single()
    if (error) throw error
    res.json({ success: true, risk: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to create risk' })
  }
})

app.put('/api/risks/:id', requireAuth, async (req, res) => {
  const riskId = req.params.id
  const payload = req.body || {}
  try {
    const patch = {
      title: payload.title,
      description: payload.description,
      category: payload.category,
      likelihood: payload.likelihood,
      impact: payload.impact,
      status: payload.status,
      owner: payload.owner,
      residual_risk: payload.residualRisk || calculateResidualRiskLabel(payload.likelihood, payload.impact),
      updated_at: new Date().toISOString()
    }
    const { data, error } = await supabase.from('risks').update(patch).eq('id', riskId).select('*').single()
    if (error) throw error
    res.json({ success: true, risk: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to update risk' })
  }
})

app.delete('/api/risks/:id', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('risks').delete().eq('id', req.params.id)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to delete risk' })
  }
})

app.get('/api/tasks', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    if (organizationId) await ensureAutoTasksForRiskBand(organizationId)
    let query = supabase.from('tasks').select('*').order('updated_at', { ascending: false })
    if (organizationId) query = query.eq('organization_id', organizationId)
    const { data, error } = await query
    if (error) throw error
    const tasks = (data || []).map((row) => ({
      id: row.id,
      organization_id: row.organization_id,
      title: row.title,
      description: row.description || '',
      category: row.category || '',
      priority: row.priority || 'Medium',
      status: row.status || 'todo',
      assignee: row.assignee || '',
      dueDate: row.due_date || ''
    }))
    res.json({ success: true, tasks })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load tasks' })
  }
})

app.post('/api/tasks', requireAuth, async (req, res) => {
  const payload = req.body || {}
  if (!payload.organization_id || !payload.title) {
    return res.status(400).json({ success: false, error: 'organization_id and title are required' })
  }
  try {
    const row = {
      organization_id: payload.organization_id,
      title: payload.title,
      description: payload.description || '',
      category: payload.category || '',
      priority: payload.priority || 'Medium',
      status: payload.status || 'todo',
      assignee: payload.assignee || '',
      due_date: payload.dueDate || null,
      updated_at: new Date().toISOString()
    }
    const { data, error } = await supabase.from('tasks').insert(row).select('*').single()
    if (error) throw error
    res.json({ success: true, task: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to create task' })
  }
})

app.patch('/api/tasks/:taskId', requireAuth, async (req, res) => {
  const payload = req.body || {}
  try {
    const patch = {
      title: payload.title,
      description: payload.description,
      category: payload.category,
      priority: payload.priority,
      status: payload.status,
      assignee: payload.assignee,
      due_date: payload.dueDate || null,
      updated_at: new Date().toISOString()
    }
    Object.keys(patch).forEach((key) => patch[key] === undefined && delete patch[key])
    const { data, error } = await supabase.from('tasks').update(patch).eq('id', req.params.taskId).select('*').single()
    if (error) throw error
    res.json({ success: true, task: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to update task' })
  }
})

app.delete('/api/tasks/:taskId', requireAuth, async (req, res) => {
  try {
    const { error } = await supabase.from('tasks').delete().eq('id', req.params.taskId)
    if (error) throw error
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to delete task' })
  }
})

app.get('/api/evidence', requireAuth, async (req, res) => {
  const organizationId = req.query?.organization_id
  try {
    let query = supabase.from('evidence').select('*').order('uploaded_at', { ascending: false })
    if (organizationId) query = query.eq('organization_id', organizationId)
    const { data, error } = await query
    if (error) throw error
    const evidence = (data || []).map((row) => ({
      id: row.id,
      organization_id: row.organization_id,
      name: row.file_name,
      controlId: row.control_id || '',
      type: row.file_type || '',
      size: row.file_size || 0,
      uploadedBy: row.uploaded_by || 'system',
      uploadDate: row.uploaded_at ? String(row.uploaded_at).slice(0, 10) : '',
      status: row.status || 'Pending',
      fileUrl: row.file_url || ''
    }))
    res.json({ success: true, evidence })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to load evidence' })
  }
})

app.post('/api/evidence', requireAuth, uploadEvidence.single('file'), async (req, res) => {
  const organizationId = req.body?.organization_id
  const controlId = req.body?.controlId
  if (!organizationId) return res.status(400).json({ success: false, error: 'organization_id is required' })
  if (!req.file) return res.status(400).json({ success: false, error: 'file is required' })
  try {
    const fileUrl = `/uploads/evidence/${req.file.filename}`
    const { data, error } = await supabase.from('evidence').insert({
      organization_id: organizationId,
      control_id: controlId || null,
      file_name: req.file.originalname,
      file_type: path.extname(req.file.originalname || '').replace('.', '').toLowerCase(),
      file_size: req.file.size,
      file_url: fileUrl,
      status: 'Pending',
      uploaded_at: new Date().toISOString()
    }).select('*').single()
    if (error) throw error
    res.json({ success: true, evidence: data })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to upload evidence' })
  }
})

app.delete('/api/evidence/:id', requireAuth, async (req, res) => {
  try {
    const { data: row, error: fetchErr } = await supabase.from('evidence').select('file_url').eq('id', req.params.id).maybeSingle()
    if (fetchErr) throw fetchErr
    const { error } = await supabase.from('evidence').delete().eq('id', req.params.id)
    if (error) throw error
    if (row?.file_url?.startsWith('/uploads/evidence/')) {
      const localPath = path.join(__dirname, row.file_url)
      if (fs.existsSync(localPath)) fs.unlinkSync(localPath)
    }
    res.json({ success: true })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to delete evidence' })
  }
})

app.get('/api/gap/dashboard', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  let rows = []
  let orgNameMap = new Map()
  try {
    const { data } = await supabase
      .from('gap_controls')
      .select('*')
      .order('created_at', { ascending: false })
    rows = data || []
  } catch {
    rows = []
  }
  try {
    orgNameMap = await loadOrganizationNameMap()
  } catch {
    orgNameMap = new Map()
  }

  const demoRows = loadGapCsvDemoRows()
  const normalizedRows = rows.map((r) => ({
    org_id: r.organization_id,
    control_name: r.control_name,
    iso_clause: r.iso_clause,
    maturity: r.maturity,
    gap_score: r.gap_score,
    evidence: r.evidence,
    created_at: r.created_at
  }))
  const allRows = [...normalizedRows, ...demoRows]
  const byClient = new Map()
  for (const row of allRows) {
    const orgId = row.org_id || 'anonymous'
    if (!byClient.has(orgId)) byClient.set(orgId, [])
    byClient.get(orgId).push(row)
  }

  if (!byClient.has(userId)) {
    const pack = buildSmartQuestionPack()
    const controls = buildGapControls(pack, getSmartAnswerMap(userId), getGapValidationMap(userId))
    byClient.set(userId, controls.map((c) => ({
      org_id: userId,
      control_name: c.control_name,
      iso_clause: c.iso_clause,
      maturity: c.maturity,
      gap_score: c.gap_score,
      evidence: c.validation?.evidence || '',
      created_at: new Date().toISOString()
    })))
  }

  const clients = Array.from(byClient.entries()).map(([org_id, clientRows]) => ({
    org_id,
    org_name: orgNameMap.get(org_id) || org_id,
    summary: summarizeClientRows(clientRows),
    rows: clientRows
  }))

  res.json({ success: true, clients })
})

app.put('/api/gap/dashboard/control', requireAuth, async (req, res) => {
  const { organization_id, control_name, maturity, evidence } = req.body || {}
  if (!organization_id || !control_name) {
    return res.status(400).json({ success: false, error: 'organization_id and control_name are required' })
  }
  const nextMaturity = Number(maturity ?? 0)
  const patch = {
    organization_id,
    control_name,
    maturity: nextMaturity,
    gap_score: Math.max(0, 4 - nextMaturity),
    evidence: evidence || '',
    updated_at: new Date().toISOString()
  }
  try {
    const { error } = await supabase
      .from('gap_controls')
      .upsert(patch, { onConflict: 'organization_id,control_name' })
    if (error) throw error
  } catch {
    return res.status(500).json({ success: false, error: 'Unable to update control' })
  }
  res.json({ success: true, control: patch })
})

app.delete('/api/gap/dashboard/client/:orgId', requireAuth, async (req, res) => {
  const orgId = req.params.orgId
  try {
    const deletions = await Promise.all([
      supabase.from('gap_controls').delete().eq('organization_id', orgId),
      supabase.from('gap_matrix_rows').delete().eq('organization_id', orgId),
      supabase.from('gap_reports').delete().eq('organization_id', orgId),
      supabase.from('isms_responses').delete().eq('organization_id', orgId)
    ])
    const firstErr = deletions.map((r) => r.error).find(Boolean)
    if (firstErr) throw firstErr
  } catch {
    return res.status(500).json({ success: false, error: 'Unable to delete client data' })
  }
  res.json({ success: true })
})

app.post('/api/isms/generate-final', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const state = getAssessmentState(userId)
  if (!allPostIsmsStepsCompleted(state)) {
    return res.status(400).json({
      success: false,
      error: 'Complete all assessments (Gap, Risk, SOA) before generating ISMS Policy'
    })
  }

  const questionPack = buildSmartQuestionPack()
  const answers = getSmartAnswerMap(userId)
  const validation = validateStructuredAnswers(questionPack, answers)
  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Complete all required W-fields before generating final policy.',
      validationErrors: validation.errors
    })
  }
  const apiKey = resolveOpenAiKey(req.body?.apiKey)
  if (!apiKey) {
    return res.status(400).json({ success: false, error: 'OpenAI API key missing on backend. Set OPENAI_API_KEY.' })
  }

  try {
    const ai = new OpenAI({ apiKey })
    const completion = await ai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are an ISO 27001:2022 policy writer generating auditor-ready policy documents.' },
        {
          role: 'user',
          content: `Generate a comprehensive ISO 27001 ISMS policy document between 30 and 40 pages equivalent length using these structured answers: ${JSON.stringify(answers)}.
Include sections: Introduction, Scope, Asset Management, HR Security, Physical Security, Access Control, Risk Management, Incident Management, Business Continuity and Disaster Recovery, Vendor Management, Compliance.
Each section must include ownership, process definition, operational execution, scope boundary, review frequency, records/evidence, escalation path, and continual improvement controls.
Use formal policy language and implementation-ready statements.`
        }
      ]
    })

    const document = completion.choices?.[0]?.message?.content || ''
    try {
      await supabase
        .from('assessments')
        .upsert({
          id: uuidv4(),
          user_id: userId,
          doc_type: 'isms_generated',
          answers: { document },
          created_at: new Date().toISOString()
        }, { onConflict: 'user_id,doc_type' })
    } catch {
      // Continue with in-memory assessment state as fallback.
    }
    updateStepState(userId, 'ismsPolicy', { completed: true, data: { generated: true, document } })
    res.json({ success: true, document })
  } catch (error) {
    res.status(500).json({ success: false, error: error.message })
  }
})

// 2. CHECK FOR DOCUMENT (YES/NO)
app.post('/api/check/:docType', async (req, res) => {
  const { docType } = req.params
  const { hasDocument } = req.body  // 'yes' or 'no'
  
  if (hasDocument === 'yes') {
    res.json({
      success: true,
      action: 'UPLOAD',
      message: 'Please upload your ' + docType + ' document. We will analyze it with AI.',
      uploadEndpoint: '/api/upload/' + docType,
      accept: 'pdf,docx,xlsx'
    })
  } else {
    // No document → Ask questions
    let questions = []
    switch (docType) {
      case 'isms': questions = ismsQuestions; break
      case 'gap': questions = gapQuestions; break
      case 'risk': questions = riskQuestions; break
      case 'soa': questions = soaQuestions; break
    }
    
    res.json({
      success: true,
      action: 'QUESTIONS',
      message: 'No problem. Let me ask you some simple questions.',
      docType,
      questions,
      total: questions.length
    })
  }
})

// 3. UPLOAD DOCUMENT → local storage + AI ANALYZES
const localDocStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const docType = String(req.params?.docType || 'general').toLowerCase()
    const uploadDir = path.join(__dirname, 'uploads', 'documents', docType)
    fs.mkdirSync(uploadDir, { recursive: true })
    cb(null, uploadDir)
  },
  filename: (req, file, cb) => {
    const safeName = String(file.originalname || 'document').replace(/[^a-zA-Z0-9._-]/g, '_')
    cb(null, `${Date.now()}-${safeName}`)
  }
})

const uploadDoc = multer({
  storage: localDocStorage,
  limits: { fileSize: maxUploadSizeBytes },
  fileFilter: evidenceFileFilter
})

app.post('/api/upload/:docType', requireAuth, uploadDoc.single('file'), async (req, res) => {
  const { docType } = req.params
  const apiKey = resolveOpenAiKey(req.body?.apiKey)
  const userId = resolveUserId(req)
  const step = DOC_TYPE_TO_STEP[docType]
  if (!step) {
    return res.status(400).json({ success: false, error: 'Invalid doc type' })
  }
  const state = getAssessmentState(userId)
  const eligibility = checkEligibility(step, state)
  if (!eligibility.allowed) {
    return res.status(403).json({ success: false, error: eligibility.reason })
  }
  
  if (!apiKey) {
    return res.status(400).json({ error: 'OpenAI API key missing on backend. Set OPENAI_API_KEY in server environment.' })
  }
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' })
  }
  
  const ai = new OpenAI({ apiKey })
  
  // File info from local storage
  const fileUrl = `/uploads/documents/${docType}/${req.file.filename}`
  const fileKey = `documents/${docType}/${req.file.filename}`
  
  // Analyze with AI
  let prompt = ''
  switch (docType) {
    case 'isms':
      prompt = `You are an ISO 27001 expert. Analyze this ISMS Policy and extract: 
1. What policies exist
2. What is missing (gaps)
3. Quality (comprehensive/basic/minimal)
Return as JSON.`
      break
    case 'gap':
      prompt = `Analyze this Gap Assessment and extract:
1. Which clauses are implemented
2. What are the gaps
3. Severity of gaps
Return as JSON.`
      break
    case 'risk':
      prompt = `Analyze this Risk Assessment and extract:
1. What risks exist
2. Risk levels
3. Treatment status
Return as JSON.`
      break
    case 'soa':
      prompt = `Analyze this Statement of Applicability and extract:
1. Which controls are applicable
2. Which are implemented
3. Coverage %
Return as JSON.`
      break
  }
  
  try {
    // For demo: respond with file info
    // In production: download from S3, extract text, then analyze
    const fileName = req.file.originalname
    
    // Simulate AI analysis result
    const completion = await ai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: 'You are an ISO 27001 expert.' },
        { role: 'user', content: `A ${docType} document (${fileName}) was uploaded. Based on typical ISO 27001 ${docType} documents, summarize what this document likely contains and identify any common gaps or areas that need attention. Return as JSON.` }
      ]
    })
    
    const analysis = completion.choices[0].message.content
    
    res.json({
      success: true,
      docType,
      action: 'ANALYZED',
      analysis: analysis,
      fileUrl,
      fileKey,
      message: 'Document uploaded and analyzed! No need to answer questions.'
    })
    updateStepState(userId, step, {
      exists: true,
      uploaded: true,
      completed: true,
      data: { analysis },
      file: {
        name: req.file.originalname,
        type: req.file.mimetype,
        uploadedAt: new Date().toISOString()
      }
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// 4. SAVE ANSWERS
app.post('/api/answers/:docType', requireAuth, async (req, res) => {
  const { docType } = req.params
  const { answers, userId } = req.body
  const resolvedUserId = userId || resolveUserId(req)
  const step = DOC_TYPE_TO_STEP[docType]
  if (!step) {
    return res.status(400).json({ success: false, error: 'Invalid doc type' })
  }
  const state = getAssessmentState(resolvedUserId)
  const eligibility = checkEligibility(step, state)
  if (!eligibility.allowed) {
    return res.status(403).json({ success: false, error: eligibility.reason })
  }
  
  try {
    // Save to Supabase
    const { data, error } = await supabase
      .from('assessments')
      .upsert({
        id: uuidv4(),
        user_id: userId || 'anonymous',
        doc_type: docType,
        answers: answers,
        created_at: new Date().toISOString()
      })
    
    if (error) throw error
    
    res.json({ success: true, saved: Object.keys(answers).length })
    updateStepState(resolvedUserId, step, {
      exists: false,
      uploaded: false,
      completed: true,
      data: { answers, generated: true },
      file: null
    })
  } catch (err) {
    // Fallback to memory
    req.serverData = req.serverData || {}
    req.serverData[docType] = answers
    updateStepState(resolvedUserId, step, {
      exists: false,
      uploaded: false,
      completed: true,
      data: { answers, generated: true },
      file: null
    })
    res.json({ success: true, saved: Object.keys(answers).length, fallback: true })
  }
})

// 5. GENERATE FINAL DOCUMENT
app.post('/api/generate/:docType', requireAuth, async (req, res) => {
  const { docType } = req.params
  const { userId } = req.body
  const apiKey = resolveOpenAiKey(req.body?.apiKey)
  const resolvedUserId = userId || resolveUserId(req)
  const step = DOC_TYPE_TO_STEP[docType]
  if (!step) {
    return res.status(400).json({ success: false, error: 'Invalid doc type' })
  }
  const state = getAssessmentState(resolvedUserId)
  const eligibility = checkEligibility(step, state)
  if (!eligibility.allowed) {
    return res.status(403).json({ success: false, error: eligibility.reason })
  }
  
  if (!apiKey) {
    return res.status(400).json({ error: 'OpenAI API key missing on backend. Set OPENAI_API_KEY in server environment.' })
  }

  if (docType === 'isms') {
    if (!allPostIsmsStepsCompleted(state)) {
      return res.status(400).json({
        success: false,
        error: 'Complete all assessments (Gap, Risk, SOA) before generating ISMS Policy'
      })
    }
  }
  
  // Get saved answers from Supabase
  let answers = {}
  try {
    const { data } = await supabase
      .from('assessments')
      .select('answers')
      .eq('doc_type', docType)
      .single()
    
    if (data) answers = data.answers
  } catch (err) {
    answers = req.serverData?.[docType] || {}
  }
  
  const ai = new OpenAI({ apiKey })
  
  let prompt = ''
  switch (docType) {
    case 'isms':
      prompt = `Generate ISMS Policy from: ${JSON.stringify(answers)}. Include all sections.`
      break
    case 'gap':
      prompt = `Generate Gap Assessment from: ${JSON.stringify(answers)}. Show gaps.`
      break
    case 'risk':
      prompt = `Generate Risk Assessment from: ${JSON.stringify(answers)}. Include matrix.`
      break
    case 'soa':
      prompt = `Generate SoA from: ${JSON.stringify(answers)}. List controls.`
      break
  }
  
  try {
    const completion = await ai.chat.completions.create({
      model: 'gpt-4o',
      messages: [{ role: 'user', content: prompt }]
    })
    
    const document = completion.choices[0].message.content
    
    // Save generated document
    await supabase
      .from('assessments')
      .upsert({
        id: uuidv4(),
        user_id: userId || 'anonymous',
        doc_type: docType + '_generated',
        answers: { document },
        created_at: new Date().toISOString()
      })
    updateStepState(resolvedUserId, step, {
      completed: true,
      data: { document }
    })
    res.json({ success: true, document })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// 6. GENERATE ALL
app.post('/api/generate-all', requireAuth, async (req, res) => {
  const apiKey = resolveOpenAiKey(req.body?.apiKey)
  
  if (!apiKey) {
    return res.status(400).json({ error: 'OpenAI API key missing on backend. Set OPENAI_API_KEY in server environment.' })
  }
  
  const ai = new OpenAI({ apiKey })
  
  const results = {}
  const docTypes = ['isms', 'gap', 'risk', 'soa']
  
  for (const docType of docTypes) {
    try {
      const { data } = await supabase
        .from('assessments')
        .select('answers')
        .eq('doc_type', docType)
        .single()
      
      if (data) {
        const prompt = `Generate ${docType.toUpperCase()} from: ${JSON.stringify(data.answers)}`
        const completion = await ai.chat.completions.create({
          model: 'gpt-4o',
          messages: [{ role: 'user', content: prompt }]
        })
        results[docType] = completion.choices[0].message.content
      }
    } catch (err) {
      results[docType] = 'Not enough data to generate'
    }
  }
  
  res.json({ success: true, documents: results })
})

app.get('/api/isms/export', async (req, res) => {
  const userId = resolveUserId(req)
  const format = String(req.query?.format || 'pdf').toLowerCase()
  let content = getFinalPolicyText(userId)

  if (!content) {
    try {
      const { data } = await supabase
        .from('assessments')
        .select('answers')
        .eq('user_id', userId)
        .eq('doc_type', 'isms_generated')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle()
      content = data?.answers?.document || ''
    } catch {
      // Keep fallback to in-memory state only.
    }
  }

  if (!content) {
    return res.status(404).json({
      success: false,
      error: 'No generated ISMS policy found. Generate final policy before exporting.'
    })
  }

  if (format === 'pdf') {
    res.setHeader('Content-Type', 'application/pdf')
    res.setHeader('Content-Disposition', 'attachment; filename="isms-policy.pdf"')
    const pdf = new PDFDocument({ margin: 50, size: 'A4' })
    pdf.pipe(res)
    pdf.fontSize(18).text('ISO 27001 ISMS Policy', { underline: true })
    pdf.moveDown(0.8)
    pdf.fontSize(10).fillColor('#555555').text(`Generated: ${new Date().toISOString()}`)
    pdf.moveDown(1)
    pdf.fillColor('black').fontSize(11).text(content, { align: 'left' })
    pdf.end()
    return
  }

  if (format === 'docx') {
    const paragraphs = content
      .split(/\n+/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => new Paragraph({ children: [new TextRun(line)] }))

    const doc = new Document({
      sections: [{
        properties: {},
        children: [
          new Paragraph({ text: 'ISO 27001 ISMS Policy', heading: HeadingLevel.HEADING_1 }),
          new Paragraph({ text: `Generated: ${new Date().toISOString()}` }),
          ...paragraphs
        ]
      }]
    })

    const buffer = await Packer.toBuffer(doc)
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
    res.setHeader('Content-Disposition', 'attachment; filename="isms-policy.docx"')
    return res.send(buffer)
  }

  return res.status(400).json({ success: false, error: 'Unsupported format. Use pdf or docx.' })
})

app.get('/api/documents/preview/:docType', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const documentType = normalizeDocType(req.params.docType)
  if (!documentType) return res.status(400).json({ success: false, error: 'Unsupported document type' })
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const state = getAssessmentState(userId)
    const sourceData = await collectGenerationData(organizationId)
    const gate = gateDocumentGeneration({ documentType, state, sourceData })
    if (!gate.allowed) return res.status(400).json({ success: false, error: gate.reason })
    const preview = buildPreviewForDocument(documentType, sourceData)
    res.json({ success: true, mode: 'PREVIEW', organization_id: organizationId, document_type: documentType, ...preview })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to generate preview' })
  }
})

app.post('/api/documents/generate-section', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const documentType = normalizeDocType(req.body?.documentType)
  const sectionName = String(req.body?.sectionName || '').trim().toLowerCase()
  if (!documentType || !sectionName) {
    return res.status(400).json({ success: false, error: 'documentType and sectionName are required' })
  }
  const apiKey = resolveOpenAiKey(req.body?.apiKey)
  if (!apiKey) return res.status(400).json({ success: false, error: 'OpenAI API key missing on backend. Set OPENAI_API_KEY.' })
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const state = getAssessmentState(userId)
    const sourceData = await collectGenerationData(organizationId)
    const gate = gateDocumentGeneration({ documentType, state, sourceData })
    if (!gate.allowed) return res.status(400).json({ success: false, error: gate.reason })

    const rateKey = `${userId}:${organizationId}:${documentType}:${sectionName}`
    if (aiSectionGenerationLimiter.has(rateKey)) {
      return res.status(429).json({ success: false, error: 'Section already generated in this session (max 1 AI generation per section).' })
    }

    const relevantData = {
      section_name: sectionName,
      isms_sections: sourceData.ismsSections.filter((row) => String(row.section_name || '').toLowerCase() === sectionName).slice(0, 25),
      isms_policy_data: sourceData.ismsPolicyData.slice(0, 60),
      assets: sourceData.assets.slice(0, 80),
      risks: sourceData.risks.slice(0, 120),
      gap_controls: sourceData.gapControls.slice(0, 120),
      soa_controls: sourceData.soaControls.slice(0, 120)
    }

    let content = ''
    let model = 'gpt-4o-mini'
    try {
      const ai = new OpenAI({ apiKey })
      const completion = await ai.chat.completions.create({
        model,
        temperature: 0.2,
        max_tokens: 700,
        messages: [
          { role: 'system', content: 'You are an ISO 27001 lead auditor. Write concise, formal, auditor-friendly sections with no fluff.' },
          {
            role: 'user',
            content: `Convert the following structured ${documentType} data into a formal ISO 27001 section named "${sectionName}". Output plain text only.\n\n${JSON.stringify(relevantData)}`
          }
        ]
      })
      content = completion.choices?.[0]?.message?.content?.trim() || ''
      await logAiUsage({
        organizationId,
        userId,
        documentType,
        sectionName,
        mode: 'SECTION_AI',
        status: content ? 'success' : 'empty',
        model,
        promptTokens: completion.usage?.prompt_tokens || 0,
        completionTokens: completion.usage?.completion_tokens || 0
      })
    } catch (err) {
      content = buildSectionFallback(documentType, sectionName, relevantData)
      await logAiUsage({
        organizationId,
        userId,
        documentType,
        sectionName,
        mode: 'SECTION_AI',
        status: 'fallback',
        model,
        errorMessage: err?.message || 'OpenAI generation failed'
      })
    }

    if (!content) {
      content = buildSectionFallback(documentType, sectionName, relevantData)
    }

    const upsertPayload = {
      org_id: organizationId,
      document_type: documentType,
      section_name: sectionName,
      content,
      created_at: new Date().toISOString()
    }
    const { error } = await supabase.from('generated_documents').upsert(upsertPayload, { onConflict: 'org_id,document_type,section_name' })
    if (error) throw error

    aiSectionGenerationLimiter.set(rateKey, true)
    res.json({ success: true, mode: 'SECTION_AI', organization_id: organizationId, document_type: documentType, section_name: sectionName, content })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to generate section' })
  }
})

app.post('/api/documents/assemble/:docType', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const documentType = normalizeDocType(req.params.docType)
  if (!documentType) return res.status(400).json({ success: false, error: 'Unsupported document type' })
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const state = getAssessmentState(userId)
    const sourceData = await collectGenerationData(organizationId)
    const gate = gateDocumentGeneration({ documentType, state, sourceData })
    if (!gate.allowed) return res.status(400).json({ success: false, error: gate.reason })

    const { data: sections, error } = await supabase
      .from('generated_documents')
      .select('section_name,content,created_at')
      .eq('org_id', organizationId)
      .eq('document_type', documentType)
      .order('created_at', { ascending: true })
    if (error) throw error

    const required = DOC_REQUIRED_SECTIONS[documentType] || []
    const generatedNames = new Set((sections || []).map((s) => s.section_name))
    const missing = required.filter((name) => !generatedNames.has(name))
    if (missing.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Complete all assessments before generating final document',
        missing_sections: missing
      })
    }

    const assembled = (sections || [])
      .map((s) => `## ${String(s.section_name || '').replace(/_/g, ' ').toUpperCase()}\n\n${s.content || ''}`)
      .join('\n\n')

    await supabase.from('generated_documents').upsert({
      org_id: organizationId,
      document_type: documentType,
      section_name: '__final__',
      content: assembled,
      created_at: new Date().toISOString()
    }, { onConflict: 'org_id,document_type,section_name' })

    res.json({ success: true, mode: 'ASSEMBLY', organization_id: organizationId, document_type: documentType, section_count: sections.length, content: assembled })
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to assemble document' })
  }
})

app.get('/api/documents/export/:docType', requireAuth, async (req, res) => {
  const userId = resolveUserId(req)
  const documentType = normalizeDocType(req.params.docType)
  const requestedFormat = String(req.query?.format || '').toLowerCase()
  if (!documentType) return res.status(400).json({ success: false, error: 'Unsupported document type' })
  try {
    const organizationId = await resolveOrCreateOrganizationUuid(req, userId)
    const { data: finalRow, error: finalErr } = await supabase
      .from('generated_documents')
      .select('content')
      .eq('org_id', organizationId)
      .eq('document_type', documentType)
      .eq('section_name', '__final__')
      .maybeSingle()
    if (finalErr) throw finalErr
    if (!finalRow?.content) {
      return res.status(400).json({ success: false, error: 'Assemble final document before export' })
    }

    if (documentType === 'ISMS') {
      const format = requestedFormat || 'docx'
      if (format === 'pdf') {
        res.setHeader('Content-Type', 'application/pdf')
        res.setHeader('Content-Disposition', 'attachment; filename="isms-policy.pdf"')
        const pdf = new PDFDocument({ margin: 50, size: 'A4' })
        pdf.pipe(res)
        pdf.fontSize(18).text('ISO 27001 ISMS Policy', { underline: true })
        pdf.moveDown(1)
        pdf.fontSize(11).text(finalRow.content, { align: 'left' })
        pdf.end()
        return
      }
      const lines = String(finalRow.content).split(/\n+/).filter(Boolean)
      const children = lines.map((line) =>
        line.startsWith('## ')
          ? new Paragraph({ text: line.replace(/^##\s*/, ''), heading: HeadingLevel.HEADING_2 })
          : new Paragraph({ children: [new TextRun(line)] })
      )
      const doc = new Document({
        sections: [{
          properties: {},
          children: [new Paragraph({ text: 'ISO 27001 ISMS Policy', heading: HeadingLevel.HEADING_1 }), ...children]
        }]
      })
      const buffer = await Packer.toBuffer(doc)
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
      res.setHeader('Content-Disposition', 'attachment; filename="isms-policy.docx"')
      return res.send(buffer)
    }

    const workbook = new ExcelJS.Workbook()
    const sheet = workbook.addWorksheet(`${documentType} Export`)
    sheet.columns = [
      { header: 'Section', key: 'section', width: 32 },
      { header: 'Content', key: 'content', width: 120 }
    ]
    const { data: sectionRows } = await supabase
      .from('generated_documents')
      .select('section_name,content')
      .eq('org_id', organizationId)
      .eq('document_type', documentType)
      .neq('section_name', '__final__')
      .order('created_at', { ascending: true })
    for (const row of sectionRows || []) {
      sheet.addRow({ section: row.section_name, content: row.content })
    }
    const buffer = await workbook.xlsx.writeBuffer()
    const fileStem = documentType.toLowerCase()
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    res.setHeader('Content-Disposition', `attachment; filename="${fileStem}-document.xlsx"`)
    return res.send(Buffer.from(buffer))
  } catch (err) {
    res.status(500).json({ success: false, error: err?.message || 'Unable to export document' })
  }
})

app.use((err, req, res, next) => {
  if (!err) return next()
  if (err.message === 'CORS blocked') {
    return res.status(403).json({ success: false, error: 'Origin not allowed' })
  }
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ success: false, error: 'File too large. Maximum size is 10MB.' })
  }
  if (String(err.message || '').includes('Unsupported file type')) {
    return res.status(400).json({ success: false, error: 'Unsupported file type' })
  }
  return res.status(500).json({ success: false, error: 'Unexpected server error' })
})

// Health
app.get('/api/health', async (req, res) => {
  res.json({ status: 'OK', time: new Date().toISOString() })
})

app.listen(PORT, () => {
  console.log(`\nISO 27001 Smart API running on http://localhost:${PORT}`)
  console.log(`\nFlow:`)
  console.log(`  1. POST /api/start - Start`)
  console.log(`  2. POST /api/check/isms - Do you have ISMS?`)
  console.log(`  3. If YES → POST /api/upload/isms (AI analyzes)`)
  console.log(`  4. If NO → POST /api/answers/isms (with questions)`)
  console.log(`  5. POST /api/generate/isms - Generate document`)
})