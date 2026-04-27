const CONTROL_LIBRARY = [
  { control_id: 'A.5.1', name: 'Policies for information security', domain: 'Organizational', linked_sections: ['organization_introduction', 'objectives_planning', 'compliance'], risk_tags: ['policy', 'governance'] },
  { control_id: 'A.5.2', name: 'Information security roles and responsibilities', domain: 'Organizational', linked_sections: ['organization_structure_roles'], risk_tags: ['insider threat', 'unauthorized access'] },
  { control_id: 'A.5.9', name: 'Inventory of information and other associated assets', domain: 'Organizational', linked_sections: ['asset_management'], risk_tags: ['data leakage', 'physical theft'] },
  { control_id: 'A.5.15', name: 'Access control', domain: 'Organizational', linked_sections: ['access_control'], risk_tags: ['unauthorized access'] },
  { control_id: 'A.5.23', name: 'Information security for use of cloud services', domain: 'Organizational', linked_sections: ['operations_communication'], risk_tags: ['misconfiguration', 'vendor breach'] },
  { control_id: 'A.6.3', name: 'Information security awareness, education and training', domain: 'People', linked_sections: ['human_resource_security', 'communication_matrix'], risk_tags: ['phishing', 'insider threat'] },
  { control_id: 'A.6.4', name: 'Disciplinary process', domain: 'People', linked_sections: ['human_resource_security'], risk_tags: ['insider threat'] },
  { control_id: 'A.7.4', name: 'Physical security monitoring', domain: 'Physical', linked_sections: ['physical_security'], risk_tags: ['physical theft'] },
  { control_id: 'A.8.7', name: 'Protection against malware', domain: 'Technological', linked_sections: ['operations_communication'], risk_tags: ['malware', 'ransomware'] },
  { control_id: 'A.8.8', name: 'Management of technical vulnerabilities', domain: 'Technological', linked_sections: ['operations_communication', 'system_development_security'], risk_tags: ['unpatched vulnerability'] },
  { control_id: 'A.8.9', name: 'Configuration management', domain: 'Technological', linked_sections: ['operations_communication', 'system_development_security'], risk_tags: ['misconfiguration'] },
  { control_id: 'A.8.13', name: 'Information backup', domain: 'Technological', linked_sections: ['business_continuity', 'operations_communication'], risk_tags: ['ransomware', 'data leakage'] },
  { control_id: 'A.8.15', name: 'Logging', domain: 'Technological', linked_sections: ['operations_communication', 'incident_management'], risk_tags: ['undetected breach', 'insider threat'] },
  { control_id: 'A.8.16', name: 'Monitoring activities', domain: 'Technological', linked_sections: ['incident_management', 'compliance'], risk_tags: ['unauthorized access', 'dos/ddos'] },
  { control_id: 'A.8.20', name: 'Network security', domain: 'Technological', linked_sections: ['operations_communication'], risk_tags: ['dos/ddos', 'lateral movement'] },
  { control_id: 'A.8.21', name: 'Security of network services', domain: 'Technological', linked_sections: ['operations_communication', 'vendor_supplier_management'], risk_tags: ['vendor breach', 'dos/ddos'] },
  { control_id: 'A.8.24', name: 'Use of cryptography', domain: 'Technological', linked_sections: ['information_handling_exchange', 'access_control'], risk_tags: ['data leakage'] }
]

function toLower(value) {
  return String(value || '').toLowerCase()
}

function mapMaturityToImplementation(maturity) {
  const m = Number(maturity || 0)
  if (m >= 4) return 'Implemented'
  if (m >= 2) return 'Partially Implemented'
  return 'Not Implemented'
}

function riskTagsForRows(risks = []) {
  const tags = new Set()
  risks.forEach((r) => {
    const t = toLower(r.threat)
    if (t) tags.add(t)
    const v = toLower(r.vulnerability)
    if (v) tags.add(v)
  })
  return tags
}

function sectionsFromIsms(ismsResponses = []) {
  return new Set(ismsResponses.map((r) => String(r.section_key || '').trim()).filter(Boolean))
}

export function getControlLibrary() {
  return CONTROL_LIBRARY
}

export function buildSoaControls({ ismsResponses = [], gapControls = [], risks = [] }) {
  const gapByClause = new Map()
  gapControls.forEach((g) => {
    const key = String(g.iso_clause || '').trim()
    if (!key) return
    if (!gapByClause.has(key)) gapByClause.set(key, [])
    gapByClause.get(key).push(g)
  })
  const ismsSections = sectionsFromIsms(ismsResponses)
  const riskTags = riskTagsForRows(risks)

  return CONTROL_LIBRARY.map((control) => {
    const sectionMatch = control.linked_sections.some((s) => ismsSections.has(s))
    const gapMatches = gapControls.filter((g) => toLower(g.control_name).includes(toLower(control.name).split(' ')[0]))
    const riskMatches = risks.filter((r) =>
      control.risk_tags.some((tag) => toLower(r.threat).includes(toLower(tag)) || toLower(r.vulnerability).includes(toLower(tag)))
    )

    const applicable = Boolean(sectionMatch || gapMatches.length > 0 || riskMatches.length > 0)
    const topGap = gapMatches[0]
    const maturity = Number(topGap?.maturity ?? 0)
    const implementation_status = applicable ? mapMaturityToImplementation(maturity) : 'Not Applicable'
    const linked_risks = riskMatches.map((r) => r.risk_id || r.id).filter(Boolean)
    const linked_gaps = gapMatches.map((g) => g.id).filter(Boolean)
    const triggeredBy = [
      sectionMatch ? 'ISMS section relevance' : null,
      gapMatches.length ? `gap evidence (${gapMatches.length})` : null,
      riskMatches.length ? `risk evidence (${riskMatches.length})` : null
    ].filter(Boolean)
    const justification = applicable
      ? `Applicable due to ${triggeredBy.join(', ')}. Current state: ${implementation_status}.`
      : 'Not applicable because no related assets, risks, or control gaps were identified.'
    const critical_missing = applicable && implementation_status === 'Not Implemented' && (riskMatches.length > 0 || gapMatches.length > 0)
    return {
      control_id: control.control_id,
      control_name: control.name,
      domain: control.domain,
      applicable,
      implementation_status,
      justification,
      linked_risks,
      linked_gaps,
      evidence_required: 'Policy, SOP, logs, and audit evidence reference',
      evidence_ref: '',
      critical_missing
    }
  })
}
