import { ISMS_QUESTION_BANK } from '../data/ismsQuestionBank.js'
import { detectWeakAnswer } from './smartQuestionEngine.js'

const EXPECTED_MATURITY = 4

const SECTION_TO_ISO = {
  organization_introduction: 'Clause 4, Clause 5',
  scope: 'Clause 4.3',
  organization_roles: 'Clause 5.3, Annex A.5.2',
  asset_management: 'Annex A.5.9-A.5.13',
  acceptable_use_policy: 'Annex A.5.10, A.6.7, A.8.x',
  human_resource_security: 'Annex A.6.1-A.6.8',
  physical_security: 'Annex A.7.1-A.7.14',
  operations_communication: 'Clause 8, Annex A.8.x',
  information_handling_exchange: 'Annex A.5.14, A.8.12, A.8.24',
  access_control: 'Annex A.5.15-A.5.18, A.8.2-A.8.5',
  system_development_security: 'Annex A.8.25-A.8.31',
  incident_management: 'Annex A.5.24-A.5.27',
  business_continuity: 'Annex A.5.28-A.5.30',
  compliance: 'Clause 9, Clause 10, Annex A.5.31-A.5.37',
  objectives_planning: 'Clause 6.2, Clause 9.1',
  communication_matrix: 'Clause 7.4'
}

const SECTION_TO_CLAUSE = {
  organization_introduction: ['4.1', '4.2'],
  scope: ['4.3', '4.4'],
  organization_roles: ['5.1', '5.2', '5.3'],
  objectives_planning: ['6.1.1', '6.1.2', '6.1.3', '6.2'],
  human_resource_security: ['7.2', '7.3'],
  communication_matrix: ['7.4'],
  operations_communication: ['8.1'],
  access_control: ['8.1'],
  asset_management: ['8.1'],
  information_handling_exchange: ['8.1'],
  system_development_security: ['8.1'],
  incident_management: ['8.1'],
  business_continuity: ['8.1'],
  compliance: ['9.1', '9.2', '9.3', '10.1', '10.2'],
  physical_security: ['8.1'],
  acceptable_use_policy: ['8.1']
}

function normalizeBaseAnswer(raw) {
  const ans = raw?.answer
  if (ans === undefined || ans === null) return ''
  if (Array.isArray(ans)) return ans.join(', ')
  if (typeof ans === 'object') {
    return Object.entries(ans).map(([k, v]) => `${k}: ${v}`).join(', ')
  }
  return String(ans).trim()
}

function recommendationFor(controlName, weak) {
  if (weak) return [`Document and implement control for "${controlName}" with owner, evidence, and monitoring cadence.`]
  return [`Raise maturity to level ${EXPECTED_MATURITY} by adding measurable KPIs, periodic review records, and audit evidence.`]
}

export function buildGapControls(questionPack, ismsAnswers = {}, savedValidation = {}) {
  const controls = []
  for (const section of questionPack.sections || []) {
    const isoClause = SECTION_TO_ISO[section.key] || 'Clause/Annex mapping pending'
    for (const q of section.questions || []) {
      const baseAnswer = normalizeBaseAnswer(ismsAnswers[q.id])
      const weakOrMissing = !baseAnswer || /^no\b/i.test(baseAnswer) || detectWeakAnswer(baseAnswer)
      const existing = savedValidation[q.id] || {}
      const maturity = weakOrMissing ? 0 : Number(existing.maturity ?? 2)
      const gapScore = Math.max(0, EXPECTED_MATURITY - maturity)
      const missingItems = []
      if (weakOrMissing) missingItems.push('Base ISMS answer missing/weak')
      if (!existing.owner && !weakOrMissing) missingItems.push('Owner')
      if (!existing.evidence && !weakOrMissing) missingItems.push('Evidence')
      if (existing.is_documented === false && !weakOrMissing) missingItems.push('Documented procedure')
      controls.push({
        id: q.id,
        section_key: section.key,
        section: section.title,
        control_name: q.question,
        iso_clause: isoClause,
        base_answer: baseAnswer || 'No usable ISMS answer',
        weak_base_answer: weakOrMissing,
        validation: weakOrMissing
          ? { is_documented: false, owner: '', evidence: '', maturity: 0, skipped_validation: true }
          : {
              is_documented: Boolean(existing.is_documented),
              owner: existing.owner || '',
              evidence: existing.evidence || '',
              maturity
            },
        maturity,
        gap_score: gapScore,
        missing_items: missingItems,
        recommendation: recommendationFor(q.question, weakOrMissing),
        critical_gap: gapScore >= 3 || maturity === 0
      })
    }
  }
  return controls
}

export function summarizeGapReport(controls = []) {
  const critical = controls.filter((c) => c.critical_gap)
  const matrix = controls.map((c) => {
    const requirementMet = c.maturity >= EXPECTED_MATURITY && c.missing_items.length === 0 ? 'yes' : c.maturity === 0 ? 'no' : 'working'
    return {
      clause: (SECTION_TO_CLAUSE[c.section_key] || [c.iso_clause])[0],
      requirement: c.control_name,
      documents_needed: c.validation?.is_documented ? 'Documented control/procedure available' : 'Policy/procedure document required',
      evidence_to_confirm_compliance: c.validation?.evidence || c.base_answer || 'Evidence pending',
      requirement_met: requirementMet
    }
  })

  return {
    expected_maturity: EXPECTED_MATURITY,
    isms_gap_assessment_matrix: matrix,
    control_wise_maturity_matrix: controls.map((c) => ({
      control_name: c.control_name,
      iso_clause: c.iso_clause,
      maturity: c.maturity,
      gap_score: c.gap_score
    })),
    critical_gaps: critical.map((c) => ({
      control_name: c.control_name,
      iso_clause: c.iso_clause,
      base_answer: c.base_answer,
      missing_items: c.missing_items
    })),
    recommendations: critical.flatMap((c) => c.recommendation)
  }
}
