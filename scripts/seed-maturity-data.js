import dotenv from 'dotenv'
import { createClient } from '@supabase/supabase-js'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
dotenv.config({ path: path.join(__dirname, '..', '.env') })

const supabaseUrl = process.env.SUPABASE_URL
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SERVICE_KEY in backend/.env')
}

const supabase = createClient(supabaseUrl, supabaseServiceKey)

const organizations = [
  {
    id: '11111111-1111-4111-8111-111111111111',
    name: 'cyberhub.in',
    industry: 'IT Services',
    company_size: '11-50',
    country: 'India',
    maturity: 20
  },
  {
    id: '22222222-2222-4222-8222-222222222222',
    name: 'mousepadder.co',
    industry: 'E-commerce',
    company_size: '51-200',
    country: 'India',
    maturity: 40
  },
  {
    id: '33333333-3333-4333-8333-333333333333',
    name: 'facemaker.io',
    industry: 'SaaS',
    company_size: '201-500',
    country: 'UAE',
    maturity: 60
  },
  {
    id: '44444444-4444-4444-8444-444444444444',
    name: 'cybersec',
    industry: 'Cybersecurity',
    company_size: '501-1000',
    country: 'UK',
    maturity: 80
  },
  {
    id: '55555555-5555-4555-8555-555555555555',
    name: 'evoke ai',
    industry: 'AI/ML Platform',
    company_size: '1000+',
    country: 'USA',
    maturity: 100
  }
]

const sectionTemplates = [
  'Context of Organization',
  'Leadership',
  'Planning',
  'Support',
  'Operation',
  'Performance Evaluation',
  'Improvement'
]

const policyQuestions = [
  { section: 'Clause 5', question: 'Is there an approved Information Security Policy?' },
  { section: 'Clause 6', question: 'Are security objectives documented and measured?' },
  { section: 'Clause 7', question: 'Is staff awareness training performed and recorded?' },
  { section: 'Clause 8', question: 'Are operational controls defined for key processes?' },
  { section: 'Clause 9', question: 'Are internal audits and management reviews completed?' },
  { section: 'Clause 10', question: 'Are corrective actions tracked to closure?' }
]

const soaControls = [
  { id: 'A.5.1', title: 'Policies for information security', category: 'Information Security Policies' },
  { id: 'A.5.2', title: 'Review of policies', category: 'Information Security Policies' },
  { id: 'A.8.1', title: 'Responsibility for assets', category: 'Asset Management' },
  { id: 'A.9.1', title: 'Business requirements of access control', category: 'Access Control' },
  { id: 'A.12.4', title: 'Logging and monitoring', category: 'Operations Security' },
  { id: 'A.12.6', title: 'Technical vulnerability management', category: 'Operations Security' },
  { id: 'A.17.1', title: 'Information security continuity', category: 'Business Continuity' }
]

function maturityBand(maturity) {
  if (maturity <= 20) return 'very-weak'
  if (maturity <= 40) return 'basic'
  if (maturity <= 60) return 'moderate'
  if (maturity <= 80) return 'strong'
  return 'fully-compliant'
}

function buildAssets(org) {
  const base = [
    { name: 'CEO Laptop', type: 'Hardware', owner: 'Executive Office', location: 'HQ', classification: 'Confidential', os: 'Windows 11', internet: true, critical: true },
    { name: 'Email Server', type: 'Software', owner: 'IT Ops', location: 'Data Center', classification: 'Confidential', os: 'Ubuntu 22.04', internet: true, critical: true },
    { name: 'Customer Database', type: 'Data', owner: 'Data Team', location: 'Cloud', classification: 'Restricted', os: 'PostgreSQL 15', internet: false, critical: true },
    { name: 'API Gateway', type: 'Software', owner: 'Platform Team', location: 'Cloud', classification: 'Internal', os: 'Linux Container', internet: true, critical: true },
    { name: 'HR File Share', type: 'Data', owner: 'HR', location: 'HQ NAS', classification: 'Confidential', os: 'Windows Server 2019', internet: false, critical: false },
    { name: 'Finance ERP', type: 'Software', owner: 'Finance', location: 'Cloud', classification: 'Restricted', os: 'SaaS', internet: true, critical: true },
    { name: 'SIEM Console', type: 'Software', owner: 'Security Team', location: 'Cloud', classification: 'Internal', os: 'SaaS', internet: false, critical: false },
    { name: 'Developer Workstation 01', type: 'Hardware', owner: 'Engineering', location: 'Remote', classification: 'Internal', os: 'macOS 14', internet: true, critical: false },
    { name: 'Git Repository', type: 'Data', owner: 'Engineering', location: 'Cloud', classification: 'Confidential', os: 'GitHub Enterprise', internet: true, critical: true },
    { name: 'Backup Repository', type: 'Data', owner: 'IT Ops', location: 'Cloud', classification: 'Restricted', os: 'Object Storage', internet: false, critical: true },
    { name: 'VPN Concentrator', type: 'Hardware', owner: 'Network Team', location: 'HQ', classification: 'Internal', os: 'ApplianceOS', internet: true, critical: true },
    { name: 'MDM Platform', type: 'Software', owner: 'Endpoint Team', location: 'Cloud', classification: 'Internal', os: 'SaaS', internet: true, critical: false },
    { name: 'Sales CRM', type: 'Software', owner: 'Sales Ops', location: 'Cloud', classification: 'Confidential', os: 'SaaS', internet: true, critical: false },
    { name: 'Document DMS', type: 'Data', owner: 'Compliance', location: 'Cloud', classification: 'Confidential', os: 'SaaS', internet: false, critical: false },
    { name: 'Production Kubernetes Cluster', type: 'Software', owner: 'Platform Team', location: 'Cloud', classification: 'Restricted', os: 'Kubernetes', internet: true, critical: true },
    { name: 'Threat Intel Feed', type: 'Software', owner: 'SOC', location: 'Cloud', classification: 'Internal', os: 'SaaS', internet: false, critical: false },
    { name: 'Identity Provider', type: 'Software', owner: 'IT Security', location: 'Cloud', classification: 'Restricted', os: 'SaaS', internet: true, critical: true },
    { name: 'Secure Code Scanner', type: 'Software', owner: 'AppSec', location: 'Cloud', classification: 'Internal', os: 'SaaS', internet: false, critical: false },
    { name: 'Customer Support Portal', type: 'Software', owner: 'Support Team', location: 'Cloud', classification: 'Confidential', os: 'SaaS', internet: true, critical: false }
  ]

  const targetCount = org.maturity === 20 ? 4 : org.maturity === 40 ? 7 : org.maturity === 60 ? 11 : org.maturity === 80 ? 15 : 19
  const subset = base.slice(0, targetCount)
  return subset.map((a, idx) => {
    const weak = org.maturity <= 40
    const moderate = org.maturity === 60
    const strong = org.maturity >= 80
    const fully = org.maturity === 100

    const antivirus = fully ? true : strong ? idx % 8 !== 0 : moderate ? idx % 3 !== 0 : weak ? idx % 2 === 0 : false
    const backup = fully ? true : strong ? idx % 6 !== 0 : moderate ? idx % 3 === 0 : false
    const accessControl = fully ? true : strong ? idx % 7 !== 0 : moderate ? idx % 2 === 0 : false
    const logging = fully ? true : strong ? idx % 6 !== 0 : moderate ? idx % 3 === 0 : false
    const encryption = fully ? true : strong ? idx % 5 !== 0 : moderate ? idx % 3 === 0 : idx % 4 === 0

    return {
      organization_id: org.id,
      asset_id: `${org.name.replace(/\s+/g, '-').toUpperCase()}-AST-${String(idx + 1).padStart(3, '0')}`,
      asset_name: a.name,
      asset_type: a.type,
      owner_name: a.owner,
      owner_designation: a.owner.includes('Team') ? 'Team Lead' : 'Manager',
      department: a.owner,
      location: a.location,
      classification: a.classification,
      platform: a.os,
      antivirus_enabled: antivirus,
      antivirus_name: antivirus ? 'Microsoft Defender for Endpoint' : null,
      patch_status: fully ? 'Up-to-date' : strong ? 'Current' : moderate ? 'Partially current' : weak ? 'Outdated' : 'Unknown',
      internet_facing: a.internet,
      critical_asset: a.critical,
      backup_enabled: backup,
      encryption_enabled: encryption,
      access_control_enabled: accessControl,
      logging_enabled: logging,
      installed_software: a.type === 'Software' ? ['Core Platform', 'Security Agent'] : ['Office Suite']
    }
  })
}

function numericToText(score) {
  if (score <= 1) return 'Low'
  if (score <= 2) return 'Medium'
  if (score <= 3) return 'High'
  return 'Very High'
}

function riskLevel(score) {
  if (score >= 16) return 'CRITICAL'
  if (score >= 10) return 'HIGH'
  if (score >= 6) return 'MEDIUM'
  return 'LOW'
}

function buildRisks(org, assets) {
  const risks = []
  assets.forEach((asset, idx) => {
    if (!asset.antivirus_enabled) {
      risks.push({
        key: `${asset.asset_id}-R1`,
        title: 'Endpoint malware infection due to absent antivirus',
        threat: 'Malware',
        vulnerability: 'Antivirus not deployed',
        category: 'Technical',
        controls: ['User awareness memo'],
        recommended: ['Deploy EDR across all endpoints', 'Centralized malware monitoring']
      })
    }
    if (!asset.backup_enabled && (asset.asset_type === 'Data' || asset.critical_asset)) {
      risks.push({
        key: `${asset.asset_id}-R2`,
        title: 'Data loss from missing backup strategy',
        threat: 'Data corruption or accidental deletion',
        vulnerability: 'No tested backup',
        category: 'Continuity',
        controls: ['Ad-hoc export on demand'],
        recommended: ['Define backup policy', 'Run quarterly restore drills']
      })
    }
    if (asset.internet_facing) {
      risks.push({
        key: `${asset.asset_id}-R3`,
        title: 'External attack surface on internet-facing asset',
        threat: 'External attack',
        vulnerability: 'Publicly exposed service',
        category: 'Network',
        controls: org.maturity >= 80 ? ['WAF', 'MFA', 'SIEM alerts'] : ['Basic firewall rule'],
        recommended: ['Harden perimeter controls', 'Continuous attack surface monitoring']
      })
    }
    if (org.maturity <= 40 && idx === 1) {
      risks.push({
        key: `${asset.asset_id}-R4`,
        title: 'Use of unlicensed software creates legal and malware risk',
        threat: 'Legal action + malware compromise',
        vulnerability: 'Software licensing governance missing',
        category: 'Compliance',
        controls: ['Manual procurement approval'],
        recommended: ['Software asset management policy', 'License compliance audits']
      })
    }
  })

  const baseLikelihood = org.maturity <= 20 ? 5 : org.maturity <= 40 ? 4 : org.maturity <= 60 ? 3 : org.maturity <= 80 ? 2 : 1
  const baseImpact = org.maturity <= 20 ? 5 : org.maturity <= 40 ? 4 : org.maturity <= 60 ? 3 : org.maturity <= 80 ? 3 : 2

  return risks.slice(0, org.maturity === 20 ? 11 : org.maturity === 40 ? 10 : org.maturity === 60 ? 9 : org.maturity === 80 ? 8 : 7).map((r, i) => {
    const likelihoodScore = Math.max(1, Math.min(5, baseLikelihood - (org.maturity >= 80 && i % 3 === 0 ? 1 : 0)))
    const impactScore = Math.max(1, Math.min(5, baseImpact - (org.maturity === 100 ? 1 : 0)))
    const score = likelihoodScore * impactScore
    const level = riskLevel(score)
    return {
      organization_id: org.id,
      risk_id: `${org.name.replace(/\s+/g, '-').toUpperCase()}-RISK-${String(i + 1).padStart(3, '0')}`,
      asset_id: r.key.split('-R')[0],
      asset_name: assets.find((a) => a.asset_id === r.key.split('-R')[0])?.asset_name || 'Asset',
      title: r.title,
      description: `${r.threat}: ${r.vulnerability}`,
      category: r.category,
      threat: r.threat,
      vulnerability: r.vulnerability,
      likelihood: numericToText(likelihoodScore),
      impact: numericToText(impactScore),
      likelihood_score: likelihoodScore,
      impact_score: impactScore,
      risk_score: score,
      risk_level: level,
      status: level === 'LOW' ? 'Accepted' : 'Identified',
      owner: 'Risk Manager',
      residual_risk: level,
      treatment: level === 'LOW' ? 'Monitor' : 'Mitigate',
      control_status: org.maturity >= 80 ? 'Active' : org.maturity >= 60 ? 'Partial' : 'Weak',
      existing_controls: r.controls,
      recommended_controls: r.recommended
    }
  })
}

function buildGapControls(org) {
  const controls = [
    ['Information Security Policy Governance', '5.2'],
    ['Asset Inventory and Ownership', '8.1'],
    ['Access Control Lifecycle', '9.2'],
    ['Logging and Monitoring Program', '12.4'],
    ['Backup and Recovery Program', '12.3'],
    ['Vulnerability Management Process', '12.6'],
    ['Supplier Security Management', '15.1'],
    ['Incident Response and Lessons Learned', '16.1']
  ]
  const base = org.maturity <= 20 ? 1 : org.maturity <= 40 ? 2 : org.maturity <= 60 ? 3 : org.maturity <= 80 ? 4 : 5
  return controls.map(([controlName, clause], idx) => {
    const maturity = Math.max(0, Math.min(5, base + (idx % 4 === 0 ? -1 : 0)))
    const documented = maturity >= 3
    return {
      organization_id: org.id,
      question_id: `${org.name.replace(/\s+/g, '-').toUpperCase()}-GAP-Q-${idx + 1}`,
      control_name: controlName,
      iso_clause: clause,
      base_answer: maturity <= 1 ? 'Not implemented consistently' : maturity <= 3 ? 'Partially implemented' : 'Implemented and periodically reviewed',
      is_documented: documented,
      owner: maturity <= 2 ? 'Unassigned' : 'Control Owner',
      evidence: documented ? 'Policy + records available' : 'Evidence missing',
      maturity,
      expected_maturity: 4,
      gap_score: Math.max(0, 4 - maturity),
      missing_items: documented ? ['Continuous improvement metrics'] : ['Approved policy', 'Process owner', 'Operational evidence'],
      recommendation: maturity <= 2
        ? ['Define and approve policy', 'Assign accountable owner', 'Collect evidence monthly']
        : ['Improve control effectiveness KPI', 'Increase review cadence'],
      critical_gap: maturity <= 1
    }
  })
}

function buildSoaControls(org, risks) {
  const severeRiskIds = risks.filter((r) => ['CRITICAL', 'HIGH'].includes(r.risk_level)).slice(0, 3).map((r) => r.risk_id)
  return soaControls.map((c, idx) => {
    const status = org.maturity <= 20
      ? 'NOT IMPLEMENTED'
      : org.maturity <= 40
        ? (idx % 3 === 0 ? 'NOT IMPLEMENTED' : 'PARTIAL')
        : org.maturity <= 60
          ? (idx % 4 === 0 ? 'PARTIAL' : 'IMPLEMENTED')
          : org.maturity <= 80
            ? (idx % 6 === 0 ? 'PARTIAL' : 'IMPLEMENTED')
            : 'IMPLEMENTED'

    return {
      organization_id: org.id,
      control_id: c.id,
      title: c.title,
      category: c.category,
      applicable: true,
      implemented: status === 'IMPLEMENTED',
      implementation_status: status,
      justification: status === 'NOT IMPLEMENTED'
        ? 'Control framework has not yet been established.'
        : status === 'PARTIAL'
          ? 'Control exists but lacks full operational coverage and evidence consistency.'
          : 'Control is operational, documented, and evidence-backed.',
      linked_risks: severeRiskIds
    }
  })
}

function buildIsmsSections(org) {
  return sectionTemplates.map((sectionName, idx) => ({
    org_id: org.id,
    section_name: sectionName,
    structured_data: {
      maturity_band: maturityBand(org.maturity),
      owner: idx % 2 === 0 ? 'Compliance Manager' : 'CISO',
      review_cycle: org.maturity >= 80 ? 'Quarterly' : 'Annual'
    },
    generated_text: `${sectionName} for ${org.name} is currently at ${org.maturity}% maturity with ${org.maturity >= 80 ? 'defined and monitored' : 'partially implemented'} governance mechanisms.`,
    completion_score: Math.max(5, org.maturity - (idx % 3) * 5)
  }))
}

function buildIsmsPolicyData(org) {
  return policyQuestions.map((q, idx) => ({
    org_id: org.id,
    section: q.section,
    question: q.question,
    answer: org.maturity <= 20
      ? (idx <= 1 ? 'No formal process exists.' : '')
      : org.maturity <= 40
        ? 'Basic process exists but inconsistent across departments.'
        : org.maturity <= 60
          ? 'Documented process exists with partial implementation evidence.'
          : org.maturity <= 80
            ? 'Documented, approved, and operating with periodic review.'
            : 'Fully documented, measured, and continuously improved.'
  }))
}

async function upsertBy(table, rows, onConflict) {
  if (!rows.length) return
  const { error } = await supabase.from(table).upsert(rows, { onConflict })
  if (error) throw new Error(`${table}: ${error.message}`)
}

function completionFromGap(gaps) {
  const avg = gaps.reduce((sum, g) => sum + (g.maturity || 0), 0) / Math.max(1, gaps.length)
  return Math.round((avg / 5) * 100)
}

async function run() {
  await upsertBy(
    'organizations',
    organizations.map((o) => ({
      id: o.id,
      name: o.name
    })),
    'id'
  )

  const summary = []
  for (const org of organizations) {
    const assets = buildAssets(org)
    const risks = buildRisks(org, assets)
    const gaps = buildGapControls(org)
    const soa = buildSoaControls(org, risks)
    const sections = buildIsmsSections(org)
    const policyData = buildIsmsPolicyData(org)

    await upsertBy('isms_sections', sections, 'org_id,section_name')
    await upsertBy('isms_policy_data', policyData, 'org_id,question')
    await upsertBy('assets', assets, 'organization_id,asset_id')
    await upsertBy('risks', risks, 'organization_id,risk_id')
    await upsertBy('gap_controls', gaps, 'organization_id,control_name')
    await upsertBy('soa_controls', soa, 'organization_id,control_id')

    const criticalCount = risks.filter((r) => r.risk_level === 'CRITICAL').length
    const highCount = risks.filter((r) => r.risk_level === 'HIGH').length
    const riskScorePercent = org.maturity === 100 ? 18 : Math.max(20, 100 - org.maturity)
    const securityPostureScore = org.maturity

    await upsertBy('risk_scores', [{
      organization_id: org.id,
      risk_score_percent: riskScorePercent,
      security_posture_score: securityPostureScore,
      critical_risk_count: criticalCount,
      high_risk_count: highCount,
      updated_at: new Date().toISOString()
    }], 'organization_id')

    summary.push({
      organization: org.name,
      maturity: `${org.maturity}%`,
      riskCount: risks.length,
      criticalRisks: criticalCount,
      completion: `${completionFromGap(gaps)}%`
    })
  }

  console.log('\nOrganization | Maturity | Risk Count | Critical Risks | Completion %')
  console.log('---|---:|---:|---:|---:')
  for (const row of summary) {
    console.log(`${row.organization} | ${row.maturity} | ${row.riskCount} | ${row.criticalRisks} | ${row.completion}`)
  }
}

run().catch((err) => {
  console.error('Seed failed:', err.message)
  process.exit(1)
})
