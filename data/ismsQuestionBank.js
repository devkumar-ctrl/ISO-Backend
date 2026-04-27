export const ISMS_QUESTION_BANK = [
  {
    key: 'organization_introduction',
    title: 'Organization & Introduction',
    treePath: '01 Governance > Organization',
    keywords: ['organization', 'stakeholder', 'management', 'mission'],
    questions: [
      'What is the legal name of your organization?',
      'What is the nature of your business?',
      'What services/products do you provide?',
      "What is your organization’s mission regarding information security?",
      'Why is information security important for your business?',
      'Who are your key stakeholders (clients, regulators, partners)?',
      'What are stakeholder security expectations?',
      'Who is responsible for ISMS at top level?',
      'Do you have an ISMS core group? List members and roles',
      'How does management demonstrate commitment to ISMS?'
    ]
  },
  {
    key: 'scope',
    title: 'Scope',
    treePath: '01 Governance > Scope',
    keywords: ['scope', 'in scope', 'out of scope', 'boundary'],
    questions: [
      'What is the defined ISMS scope?',
      'Which locations are included?',
      'Which departments are in scope?',
      'Which systems/applications are in scope?',
      'What is explicitly excluded from scope?',
      'How do you control interfaces with out-of-scope entities?',
      'Who approves scope changes?',
      'How often is scope reviewed?'
    ]
  },
  {
    key: 'organization_roles',
    title: 'Organization Structure & Roles',
    treePath: '01 Governance > Roles & Accountability',
    keywords: ['roles', 'responsibilities', 'segregation', 'escalation'],
    questions: [
      'Who is the Information Security Head?',
      'What departments are involved in ISMS?',
      'Define roles for HR, IT, and Management.',
      'Who handles Risk, Access, and Incident management?',
      'Is there segregation of duties? How?',
      'Who reviews ISMS performance?',
      'Who escalates incidents(handles escalation process)?',
      'How responsibilities are documented?',
      'Who is backup owner for critical roles?',
      'How are responsibilities communicated?'
    ]
  },
  {
    key: 'asset_management',
    title: 'Asset Management',
    treePath: '02 Operations > Asset Controls',
    keywords: ['asset', 'inventory', 'classification', 'ownership'],
    questions: [
      'Do you maintain asset inventory?',
      'What types of assets exist (IT, data, physical)?',
      'Who owns assets?',
      'How assets are classified?',
      'Define classification levels.',
      'How assets are labeled?',
      'How often inventory is reviewed?',
      'Where is asset register stored?',
      'How new assets are added?',
      'How unused assets are removed?',
      'How asset risk is evaluated?',
      'How asset ownership is transferred?'
    ]
  },
  {
    key: 'acceptable_use_policy',
    title: 'Acceptable Use Policy',
    treePath: '02 Operations > User Behavior',
    keywords: ['acceptable use', 'password', 'mfa', 'email'],
    questions: [
      'Do you have acceptable use policy?',
      'What are allowed uses of systems?',
      'What are prohibited actions?',
      'Password requirements?',
      'MFA usage?',
      'Antivirus policy?',
      'Patch/update policy?',
      'Internet usage rules?',
      'Email usage rules?',
      'How violations are handled?'
    ]
  },
  {
    key: 'human_resource_security',
    title: 'Human Resource Security',
    treePath: '02 Operations > HR Security',
    keywords: ['hr', 'training', 'termination', 'background'],
    questions: [
      'Do you perform background verification?',
      'What checks are done?',
      'Are contracts signed?',
      'Do contracts include security clauses?',
      'Do you conduct security training?',
      'Training frequency?',
      'How awareness is measured?',
      'Role-based access updates?',
      'How disciplinary actions are handled?',
      'Who handles termination?',
      'How access is revoked?',
      'How assets are returned?',
      'Is exit checklist used?',
      'How knowledge transfer handled?',
      'How long records are retained?'
    ]
  },
  {
    key: 'physical_security',
    title: 'Physical Security',
    treePath: '02 Operations > Physical Controls',
    keywords: ['physical', 'cctv', 'visitor', 'equipment', 'fire'],
    questions: [
      'Office location details',
      'Entry points count',
      'Access control method (guard, biometric)',
      'Visitor management process',
      'Are CCTV systems installed?',
      'Fire protection systems?',
      'Power backup availability?',
      'Equipment placement safety?',
      'Environmental risk handling?',
      'Cabling security?',
      'Device maintenance process?',
      'Offsite equipment usage?',
      'Physical access logs maintained?',
      'Disposal process of equipment?',
      'Who approves physical access?'
    ]
  },
  {
    key: 'operations_communication',
    title: 'Operations & Communication',
    treePath: '03 Assurance > Operations',
    keywords: ['sop', 'change', 'logging', 'network', 'backup'],
    questions: [
      'Do you have SOPs?',
      'Change management process?',
      'Who approves changes?',
      'Is logging maintained?',
      'Segregation of dev/test/prod?',
      'Third-party services used?',
      'Vendor monitoring process?',
      'Antivirus usage?',
      'Malware protection method?',
      'Backup items list?',
      'Backup frequency?',
      'Backup storage location?',
      'Backup testing frequency?',
      'Network architecture?',
      'Is network encrypted?',
      'Firewall usage?',
      'Log monitoring frequency?',
      'Removable media policy?'
    ]
  },
  {
    key: 'information_handling_exchange',
    title: 'Information Handling & Exchange',
    treePath: '03 Assurance > Information Exchange',
    keywords: ['data transfer', 'encryption', 'communication', 'sharing'],
    questions: [
      'How data is shared internally?',
      'What communication tools used?',
      'Is data encrypted in transfer?',
      'Are external transfers controlled?',
      'Email security controls?',
      'Are users trained on data handling?',
      'Is sensitive data restricted?',
      'Is data copying controlled?',
      'Are communication logs stored?',
      'Who approves data sharing?'
    ]
  },
  {
    key: 'access_control',
    title: 'Access Control',
    treePath: '03 Assurance > Access Governance',
    keywords: ['access', 'user', 'privileged', 'revocation'],
    questions: [
      'Access control policy exists?',
      'User registration process?',
      'Password policy details?',
      'Access review frequency?',
      'Privileged access control?',
      'Network access restrictions?',
      'External access allowed?',
      'OS-level access control?',
      'Application access control?',
      'Mobile/remote access policy?',
      'Session timeout policy?',
      'Access revocation process?'
    ]
  },
  {
    key: 'system_development_security',
    title: 'System Development Security',
    treePath: '03 Assurance > SDLC Security',
    keywords: ['development', 'validation', 'source code', 'vulnerability'],
    questions: [
      'Do you develop software?',
      'Input validation controls?',
      'Output validation process?',
      'Change control in code?',
      'Source code protection?',
      'Cryptographic controls used?',
      'Vulnerability management process?',
      'Patch management?',
      'Logging in applications?',
      'Testing process?'
    ]
  },
  {
    key: 'incident_management',
    title: 'Incident Management',
    treePath: '04 Resilience > Incident Response',
    keywords: ['incident', 'root cause', 'escalation', 'reporting'],
    questions: [
      'Incident reporting process?',
      'Who records incidents?',
      'Incident classification method?',
      'Root cause analysis process?',
      'Incident review frequency?',
      'Escalation process?',
      'Communication during incident?',
      'Incident documentation stored where?',
      'How are lessons learned incorporated into controls?'
    ]
  },
  {
    key: 'business_continuity',
    title: 'Business Continuity',
    treePath: '04 Resilience > BCP & DR',
    keywords: ['bcp', 'dr', 'rto', 'rpo', 'disaster'],
    questions: [
      'Do you have BCP?',
      'Is BCP tested?',
      'Recovery objectives (RTO/RPO)?',
      'Backup integration with BCP?',
      'Disaster recovery plan?',
      'Who is responsible?',
      'What crisis escalation matrix is used during disaster events?'
    ]
  },
  {
    key: 'compliance',
    title: 'Compliance',
    treePath: '05 Governance > Compliance',
    keywords: ['compliance', 'audit', 'law', 'privacy'],
    questions: [
      'Legal register maintained?',
      'Applicable laws?',
      'Software licensing policy?',
      'Data protection compliance?',
      'Record retention policy?',
      'Internal audit frequency?',
      'Audit findings handling?',
      'Privacy policy implementation?',
      'How are non-conformities tracked to closure?'
    ]
  },
  {
    key: 'objectives_planning',
    title: 'Objectives & Planning',
    treePath: '05 Governance > Objectives',
    keywords: ['objective', 'kpi', 'measurement', 'planning'],
    questions: [
      'Security objectives defined?',
      'KPIs for ISMS?',
      'Who tracks objectives?',
      'Measurement method?',
      'How ofen you review?',
      'Reporting format?'
    ]
  },
  {
    key: 'communication_matrix',
    title: 'Communication Matrix',
    treePath: '05 Governance > Communications',
    keywords: ['communication', 'internal', 'external', 'vendor'],
    questions: [
      'Internal communication methods?',
      'External communication methods?',
      'Who communicates policies?',
      'Training communication flow?',
      'Incident communication flow?',
      'Vendor communication process?'
    ]
  }
]
