const CLASSIFICATION_IMPACT = {
  public: 1,
  internal: 2,
  confidential: 4,
  critical: 5
}

export const THREAT_LIBRARY = [
  'Malware',
  'Ransomware',
  'Phishing',
  'Insider Threat',
  'Data Leakage',
  'Unauthorized Access',
  'DoS/DDoS',
  'Misconfiguration',
  'Unpatched Vulnerability',
  'Physical Theft',
  'Vendor Breach'
]

function normalizeBool(value) {
  if (typeof value === 'boolean') return value
  const text = String(value || '').trim().toLowerCase()
  return ['yes', 'true', '1', 'enabled'].includes(text)
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value))
}

function levelFromScore(score) {
  if (score <= 5) return 'Low'
  if (score <= 10) return 'Medium'
  if (score <= 15) return 'High'
  return 'Critical'
}

function buildRuleFindings(asset = {}, network = {}, software = {}) {
  const findings = []
  const classification = String(asset.classification || '').toLowerCase()
  const assetCritical = normalizeBool(asset.critical_asset) || classification === 'critical'
  const internetFacing = normalizeBool(asset.internet_facing)
  const hasFirewall = normalizeBool(network.firewall_enabled)
  const noSegmentation = ['none', 'flat network'].includes(String(network.network_segmentation || '').toLowerCase())
  const missingMonitoring = !normalizeBool(asset.logging_enabled)

  if (!normalizeBool(asset.antivirus_enabled)) {
    findings.push({
      threat: 'Malware',
      vulnerability: 'No endpoint protection',
      recommended_controls: ['Deploy AV/EDR', 'Enable real-time scanning'],
      control_status: 'Missing'
    })
  }
  if (String(asset.patch_status || '').toLowerCase() === 'outdated') {
    findings.push({
      threat: 'Unpatched Vulnerability',
      vulnerability: 'Outdated patch status',
      recommended_controls: ['Patch management SLA', 'Monthly vulnerability remediation'],
      control_status: 'Weak'
    })
  }
  if (normalizeBool(software.pirated_software_present)) {
    findings.push({
      threat: 'Malware',
      vulnerability: 'Pirated or modified software present',
      recommended_controls: ['Remove unlicensed software', 'Application allow-listing'],
      control_status: 'Missing'
    })
    findings.push({
      threat: 'Data Leakage',
      vulnerability: 'Legal and supply-chain exposure from untrusted binaries',
      recommended_controls: ['SAM governance', 'License compliance checks'],
      control_status: 'Missing'
    })
  }
  if (!normalizeBool(asset.backup_enabled)) {
    findings.push({
      threat: 'Ransomware',
      vulnerability: 'No backup capability',
      recommended_controls: ['Enable immutable backups', 'Quarterly restore testing'],
      control_status: 'Missing'
    })
  }
  if (internetFacing && !hasFirewall) {
    findings.push({
      threat: 'Unauthorized Access',
      vulnerability: 'Internet-facing asset without firewall protection',
      recommended_controls: ['Deploy NGFW/WAF', 'Restrict ingress'],
      control_status: 'Missing'
    })
  }
  if (noSegmentation) {
    findings.push({
      threat: 'Insider Threat',
      vulnerability: 'No network segmentation enabling lateral movement',
      recommended_controls: ['Implement VLAN/Zero Trust segmentation', 'East-west filtering'],
      control_status: 'Weak'
    })
  }
  if (assetCritical && missingMonitoring) {
    findings.push({
      threat: 'Misconfiguration',
      vulnerability: 'Critical asset without logging/monitoring',
      recommended_controls: ['Enable centralized logging and SIEM alerts'],
      control_status: 'Missing'
    })
  }
  if (!normalizeBool(asset.encryption_enabled) && ['confidential', 'critical'].includes(classification)) {
    findings.push({
      threat: 'Data Leakage',
      vulnerability: 'Sensitive data not encrypted',
      recommended_controls: ['Enable at-rest and in-transit encryption', 'Key management policy'],
      control_status: 'Missing'
    })
  }
  if (!normalizeBool(asset.access_control_enabled)) {
    findings.push({
      threat: 'Unauthorized Access',
      vulnerability: 'Access control not enabled',
      recommended_controls: ['Role-based access control', 'Quarterly access review'],
      control_status: 'Missing'
    })
  }
  if (String(network.wifi_security || '').toLowerCase() === 'open') {
    findings.push({
      threat: 'Phishing',
      vulnerability: 'Unsecured WiFi profile',
      recommended_controls: ['Move to WPA3 enterprise', '802.1X enforcement'],
      control_status: 'Weak'
    })
  }
  return findings
}

function scoreRisk(asset = {}, finding = {}) {
  const classification = String(asset.classification || '').toLowerCase()
  const baseImpact = CLASSIFICATION_IMPACT[classification] || 2
  const internetFacingBoost = normalizeBool(asset.internet_facing) ? 1 : 0
  const criticalBoost = normalizeBool(asset.critical_asset) ? 1 : 0
  const missingControlsBoost = finding.control_status === 'Missing' ? 1 : 0
  const impact = clamp(baseImpact + criticalBoost, 1, 5)
  const likelihood = clamp(2 + internetFacingBoost + missingControlsBoost, 1, 5)
  const risk_score = likelihood * impact
  return {
    likelihood,
    impact,
    risk_score,
    risk_level: levelFromScore(risk_score)
  }
}

export function buildGeneratedRisks({ assets = [], networkProfile = {}, softwareControls = {} }) {
  const risks = []
  for (const asset of assets) {
    const findings = buildRuleFindings(asset, networkProfile, softwareControls)
    for (const finding of findings) {
      const scoring = scoreRisk(asset, finding)
      risks.push({
        risk_id: `${asset.asset_id || 'asset'}-${finding.threat}`.replace(/\s+/g, '_').toLowerCase(),
        asset_id: asset.asset_id,
        asset_name: asset.asset_name,
        threat: finding.threat,
        vulnerability: finding.vulnerability,
        likelihood: scoring.likelihood,
        impact: scoring.impact,
        risk_score: scoring.risk_score,
        risk_level: scoring.risk_level,
        existing_controls: [],
        recommended_controls: finding.recommended_controls,
        control_status: finding.control_status
      })
    }
  }
  return risks
}

export function summarizeRiskReport({ assets = [], risks = [] }) {
  const critical = risks.filter((r) => r.risk_level === 'Critical')
  const high = risks.filter((r) => r.risk_level === 'High')
  const scoreAvg = risks.length ? risks.reduce((sum, r) => sum + Number(r.risk_score || 0), 0) / risks.length : 0
  const maxScore = 25
  const riskScorePct = clamp(Math.round((scoreAvg / maxScore) * 100), 0, 100)
  const posture = clamp(100 - riskScorePct, 0, 100)

  const heatmap = [1, 2, 3, 4, 5].flatMap((impact) =>
    [1, 2, 3, 4, 5].map((likelihood) => ({
      impact,
      likelihood,
      count: risks.filter((r) => Number(r.impact) === impact && Number(r.likelihood) === likelihood).length
    }))
  )

  const badges = {
    fully_protected_assets: assets.filter((a) =>
      normalizeBool(a.antivirus_enabled) &&
      normalizeBool(a.backup_enabled) &&
      normalizeBool(a.encryption_enabled) &&
      normalizeBool(a.access_control_enabled) &&
      normalizeBool(a.logging_enabled)
    ).length,
    high_risk_assets: Array.from(new Set(high.concat(critical).map((r) => r.asset_id))).length,
    no_backup_warning_assets: assets.filter((a) => !normalizeBool(a.backup_enabled)).length
  }

  return {
    generated_at: new Date().toISOString(),
    totals: {
      assets: assets.length,
      risks: risks.length,
      critical: critical.length,
      high: high.length
    },
    risk_score_percent: riskScorePct,
    security_posture_score: posture,
    critical_risk_alerts: critical.slice(0, 20),
    top_risks: [...critical, ...high].slice(0, 20),
    heatmap,
    badges
  }
}

export function defaultRiskGuidedQuestions() {
  return [
    'How are assets discovered and onboarded?',
    'Who approves and owns asset classification?',
    'How often is the asset inventory reviewed?'
  ]
}
