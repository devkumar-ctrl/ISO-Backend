-- =====================================================
-- SUPABASE DATABASE SCHEMA FOR ISO 27001 ISMS
-- =====================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- ORGANIZATIONS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    industry TEXT,
    company_size TEXT,
    address TEXT,
    country TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- USERS (extended from Supabase Auth)
-- =====================================================
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    full_name TEXT,
    role TEXT,
    email TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- ASSESSMENTS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    assessor_name TEXT,
    assessor_role TEXT,
    assessor_email TEXT,
    org_name TEXT,
    org_size TEXT,
    scope TEXT,
    current_phase TEXT DEFAULT 'preassessment',
    current_clause TEXT DEFAULT '4',
    compliance_score INTEGER,
    status TEXT DEFAULT 'in_progress',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- ASSESSMENT ANSWERS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS assessment_answers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    question_id TEXT NOT NULL,
    clause TEXT,
    answer TEXT,
    answered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure one answer row per assessment + question for clean autosave upsert
CREATE UNIQUE INDEX IF NOT EXISTS idx_assessment_answers_assessment_question
ON assessment_answers (assessment_id, question_id);

-- =====================================================
-- REPORTS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    user_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
    report_type TEXT DEFAULT 'pdf',
    file_name TEXT,
    file_url TEXT,
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- POLICIES TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT,
    status TEXT DEFAULT 'Draft',
    version TEXT DEFAULT '1.0',
    owner TEXT,
    description TEXT,
    document_url TEXT,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- RISKS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS risks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    likelihood TEXT,
    impact TEXT,
    status TEXT DEFAULT 'Identified',
    owner TEXT,
    residual_risk TEXT,
    treatment TEXT,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- TASKS TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    priority TEXT DEFAULT 'Medium',
    status TEXT DEFAULT 'todo',
    assignee TEXT,
    due_date DATE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE SET NULL,
    created_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- EVIDENCE TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE SET NULL,
    control_id TEXT,
    file_name TEXT NOT NULL,
    file_type TEXT,
    file_size INTEGER,
    file_url TEXT,
    status TEXT DEFAULT 'Pending',
    uploaded_by UUID REFERENCES profiles(id) ON DELETE SET NULL,
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- SOA (Statement of Applicability) TABLE
-- =====================================================
CREATE TABLE IF NOT EXISTS soa_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    title TEXT,
    category TEXT,
    applicable BOOLEAN DEFAULT TRUE,
    implemented BOOLEAN DEFAULT FALSE,
    na_reason TEXT,
    exclusion_reason TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS implementation_status TEXT;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS justification TEXT;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS linked_risks JSONB DEFAULT '[]'::jsonb;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS linked_gaps JSONB DEFAULT '[]'::jsonb;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS evidence_required TEXT;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS evidence_ref TEXT;
ALTER TABLE soa_controls ADD COLUMN IF NOT EXISTS critical_missing BOOLEAN DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_soa_controls_org_control
ON soa_controls (organization_id, control_id);

-- =====================================================
-- ISMS QUESTION MASTER + RESPONSES (NORMALIZED)
-- =====================================================
CREATE TABLE IF NOT EXISTS isms_questions (
    id TEXT PRIMARY KEY,
    section_key TEXT NOT NULL,
    section_title TEXT NOT NULL,
    tree_path TEXT,
    question_text TEXT NOT NULL,
    iso_clause TEXT,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS isms_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    question_id TEXT NOT NULL REFERENCES isms_questions(id) ON DELETE CASCADE,
    section_key TEXT,
    section_title TEXT,
    answer_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    owner_role TEXT,
    tooling TEXT,
    control_frequency TEXT,
    evidence_ref TEXT,
    risk_link TEXT,
    weak_answer BOOLEAN DEFAULT FALSE,
    completion_score NUMERIC(5,2) DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_isms_responses_org_question
ON isms_responses (organization_id, question_id);
CREATE INDEX IF NOT EXISTS idx_isms_responses_org_section
ON isms_responses (organization_id, section_key);

-- =====================================================
-- GAP ENGINE TABLES (CONTROL, MATRIX, REPORT)
-- =====================================================
CREATE TABLE IF NOT EXISTS gap_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    question_id TEXT,
    control_name TEXT NOT NULL,
    iso_clause TEXT,
    base_answer TEXT,
    is_documented BOOLEAN DEFAULT FALSE,
    owner TEXT,
    evidence TEXT,
    maturity INTEGER DEFAULT 0 CHECK (maturity BETWEEN 0 AND 5),
    expected_maturity INTEGER DEFAULT 4 CHECK (expected_maturity BETWEEN 0 AND 5),
    gap_score INTEGER DEFAULT 0,
    missing_items JSONB DEFAULT '[]'::jsonb,
    recommendation JSONB DEFAULT '[]'::jsonb,
    critical_gap BOOLEAN DEFAULT FALSE,
    skipped_validation BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gap_controls_org_question
ON gap_controls (organization_id, question_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gap_controls_org_control_name
ON gap_controls (organization_id, control_name);

CREATE TABLE IF NOT EXISTS gap_matrix_rows (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    clause TEXT NOT NULL,
    requirement TEXT NOT NULL,
    documents_needed TEXT,
    evidence_to_confirm_compliance TEXT,
    requirement_met TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_gap_matrix_org_clause_requirement
ON gap_matrix_rows (organization_id, clause, requirement);

CREATE TABLE IF NOT EXISTS gap_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    assessment_id UUID REFERENCES assessments(id) ON DELETE CASCADE,
    expected_maturity INTEGER DEFAULT 4 CHECK (expected_maturity BETWEEN 0 AND 5),
    critical_gap_count INTEGER DEFAULT 0,
    average_maturity NUMERIC(5,2) DEFAULT 0,
    report_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- RISK ENGINE TABLES (ASSET-CENTRIC)
-- =====================================================
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    asset_name TEXT NOT NULL,
    asset_type TEXT,
    mac_address TEXT,
    ip_address TEXT,
    owner_name TEXT,
    owner_designation TEXT,
    department TEXT,
    location TEXT,
    classification TEXT DEFAULT 'Internal',
    platform TEXT,
    installed_software JSONB DEFAULT '[]'::jsonb,
    antivirus_enabled BOOLEAN DEFAULT FALSE,
    antivirus_name TEXT,
    patch_status TEXT DEFAULT 'Unknown',
    internet_facing BOOLEAN DEFAULT FALSE,
    critical_asset BOOLEAN DEFAULT FALSE,
    backup_enabled BOOLEAN DEFAULT FALSE,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    access_control_enabled BOOLEAN DEFAULT FALSE,
    logging_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_org_asset
ON assets (organization_id, asset_id);

CREATE TABLE IF NOT EXISTS network_profile (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    isp_provider TEXT,
    bandwidth TEXT,
    ip_type TEXT,
    firewall_enabled BOOLEAN DEFAULT FALSE,
    firewall_type TEXT,
    vpn_usage BOOLEAN DEFAULT FALSE,
    network_segmentation TEXT,
    wifi_security TEXT,
    guest_network_isolation BOOLEAN DEFAULT FALSE,
    cloud_providers JSONB DEFAULT '[]'::jsonb,
    architecture_type TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS software_controls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    licensed_software_only BOOLEAN DEFAULT FALSE,
    pirated_software_present BOOLEAN DEFAULT FALSE,
    endpoint_protection TEXT,
    patch_management_process TEXT,
    usb_media_control BOOLEAN DEFAULT FALSE,
    admin_privilege_restrictions BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE risks ADD COLUMN IF NOT EXISTS risk_id TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS asset_id TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS asset_name TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS threat TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS vulnerability TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS likelihood_score INTEGER;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS impact_score INTEGER;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS existing_controls JSONB DEFAULT '[]'::jsonb;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS recommended_controls JSONB DEFAULT '[]'::jsonb;
ALTER TABLE risks ADD COLUMN IF NOT EXISTS control_status TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_risks_org_risk_id
ON risks (organization_id, risk_id);

CREATE TABLE IF NOT EXISTS risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    risk_score_percent INTEGER DEFAULT 0,
    security_posture_score INTEGER DEFAULT 0,
    critical_risk_count INTEGER DEFAULT 0,
    high_risk_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    report_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- LEGACY/COMPAT TABLES FOR POLICY SECTION STORAGE
-- =====================================================
CREATE TABLE IF NOT EXISTS isms_policy_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    section TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_isms_policy_data_org_question
ON isms_policy_data (org_id, question);

CREATE TABLE IF NOT EXISTS isms_sections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    section_name TEXT NOT NULL,
    structured_data JSONB DEFAULT '{}'::jsonb,
    generated_text TEXT,
    completion_score NUMERIC(5,2) DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_isms_sections_org_section
ON isms_sections (org_id, section_name);

-- =====================================================
-- CONTROLLED AI OUTPUT + USAGE LOG
-- =====================================================
CREATE TABLE IF NOT EXISTS generated_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    document_type TEXT NOT NULL CHECK (document_type IN ('ISMS','GAP','RISK','SOA')),
    section_name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_generated_documents_org_doc_section
ON generated_documents (org_id, document_type, section_name);

CREATE TABLE IF NOT EXISTS ai_generation_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT,
    document_type TEXT,
    section_name TEXT,
    mode TEXT,
    status TEXT,
    model TEXT,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =====================================================
-- SECURITY AUDIT LOGS (REQUEST/DEVICE LEVEL)
-- =====================================================
CREATE TABLE IF NOT EXISTS security_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    ip_address TEXT NOT NULL,
    browser TEXT,
    os TEXT,
    device_type TEXT,
    user_agent TEXT,
    action TEXT NOT NULL,
    endpoint TEXT,
    method TEXT,
    status_code INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_security_logs_created_at ON security_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_user_created ON security_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_action_created ON security_logs (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_org_created ON security_logs (org_id, created_at DESC);

-- Retention helper: purge records older than 90 days
CREATE OR REPLACE FUNCTION public.purge_security_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM security_logs
  WHERE created_at < NOW() - make_interval(days => retention_days);
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$;

-- =====================================================
-- SECURITY: Enable Row Level Security
-- =====================================================

-- Organizations RLS
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- Profiles RLS  
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Assessments RLS
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_answers ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- Policies RLS
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE soa_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE isms_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE isms_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE gap_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE gap_matrix_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE gap_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE isms_policy_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE isms_sections ENABLE ROW LEVEL SECURITY;
ALTER TABLE generated_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_generation_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_logs ENABLE ROW LEVEL SECURITY;

-- =====================================================
-- RLS POLICIES
-- =====================================================

CREATE OR REPLACE FUNCTION public.is_admin_user()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM profiles p
    WHERE p.id = auth.uid()
      AND LOWER(COALESCE(p.role, '')) IN ('admin', 'super_admin')
  );
$$;

-- Organizations: Users can view their org
DROP POLICY IF EXISTS "Users can view their organization" ON organizations;
CREATE POLICY "Users can view their organization" ON organizations
    FOR SELECT USING (true);

-- Profiles: Users can view their profile
DROP POLICY IF EXISTS "Users can view own profile" ON profiles;
CREATE POLICY "Users can view own profile" ON profiles
    FOR SELECT USING (auth.uid() = id);

-- Assessments: Users in org can view all assessments
DROP POLICY IF EXISTS "Org members can view assessments" ON assessments;
CREATE POLICY "Org members can view assessments" ON assessments
    FOR SELECT USING (true);

-- Answers: Users in org can view all answers
DROP POLICY IF EXISTS "Org members can view answers" ON assessment_answers;
CREATE POLICY "Org members can view answers" ON assessment_answers
    FOR SELECT USING (true);

-- Policies: Users in org can view
DROP POLICY IF EXISTS "Org members can view policies" ON policies;
CREATE POLICY "Org members can view policies" ON policies
    FOR SELECT USING (true);

-- Risks: Users in org can view
DROP POLICY IF EXISTS "Org members can view risks" ON risks;
CREATE POLICY "Org members can view risks" ON risks
    FOR SELECT USING (true);

-- Tasks: Users in org can view
DROP POLICY IF EXISTS "Org members can view tasks" ON tasks;
CREATE POLICY "Org members can view tasks" ON tasks
    FOR SELECT USING (true);

-- Evidence: Users in org can view
DROP POLICY IF EXISTS "Org members can view evidence" ON evidence;
CREATE POLICY "Org members can view evidence" ON evidence
    FOR SELECT USING (true);

-- SOA: Users in org can view
DROP POLICY IF EXISTS "Org members can view soa" ON soa_controls;
CREATE POLICY "Org members can view soa" ON soa_controls
    FOR SELECT USING (true);

DROP POLICY IF EXISTS "Org members can view isms questions" ON isms_questions;
CREATE POLICY "Org members can view isms questions" ON isms_questions
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view isms responses" ON isms_responses;
CREATE POLICY "Org members can view isms responses" ON isms_responses
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view gap controls" ON gap_controls;
CREATE POLICY "Org members can view gap controls" ON gap_controls
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view gap matrix rows" ON gap_matrix_rows;
CREATE POLICY "Org members can view gap matrix rows" ON gap_matrix_rows
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view gap reports" ON gap_reports;
CREATE POLICY "Org members can view gap reports" ON gap_reports
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view assets" ON assets;
CREATE POLICY "Org members can view assets" ON assets
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view network profile" ON network_profile;
CREATE POLICY "Org members can view network profile" ON network_profile
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view software controls" ON software_controls;
CREATE POLICY "Org members can view software controls" ON software_controls
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view risk scores" ON risk_scores;
CREATE POLICY "Org members can view risk scores" ON risk_scores
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view risk reports" ON risk_reports;
CREATE POLICY "Org members can view risk reports" ON risk_reports
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view isms policy data" ON isms_policy_data;
CREATE POLICY "Org members can view isms policy data" ON isms_policy_data
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view isms sections" ON isms_sections;
CREATE POLICY "Org members can view isms sections" ON isms_sections
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view generated documents" ON generated_documents;
CREATE POLICY "Org members can view generated documents" ON generated_documents
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Org members can view ai generation logs" ON ai_generation_logs;
CREATE POLICY "Org members can view ai generation logs" ON ai_generation_logs
    FOR SELECT USING (true);
DROP POLICY IF EXISTS "Admins can view security logs" ON security_logs;
CREATE POLICY "Admins can view security logs" ON security_logs
    FOR SELECT USING (public.is_admin_user());

-- Admin write access (you mentioned only 5-6 internal admins will use the tool)
CREATE OR REPLACE FUNCTION public.is_admin_user()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1
    FROM profiles p
    WHERE p.id = auth.uid()
      AND LOWER(COALESCE(p.role, '')) IN ('admin', 'super_admin')
  );
$$;

DROP POLICY IF EXISTS "Admins can manage isms questions" ON isms_questions;
CREATE POLICY "Admins can manage isms questions" ON isms_questions
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage isms responses" ON isms_responses;
CREATE POLICY "Admins can manage isms responses" ON isms_responses
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage gap controls" ON gap_controls;
CREATE POLICY "Admins can manage gap controls" ON gap_controls
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage gap matrix rows" ON gap_matrix_rows;
CREATE POLICY "Admins can manage gap matrix rows" ON gap_matrix_rows
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage gap reports" ON gap_reports;
CREATE POLICY "Admins can manage gap reports" ON gap_reports
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage assets" ON assets;
CREATE POLICY "Admins can manage assets" ON assets
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage network profile" ON network_profile;
CREATE POLICY "Admins can manage network profile" ON network_profile
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage software controls" ON software_controls;
CREATE POLICY "Admins can manage software controls" ON software_controls
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage risk scores" ON risk_scores;
CREATE POLICY "Admins can manage risk scores" ON risk_scores
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());
DROP POLICY IF EXISTS "Admins can manage risk reports" ON risk_reports;
CREATE POLICY "Admins can manage risk reports" ON risk_reports
    FOR ALL USING (public.is_admin_user()) WITH CHECK (public.is_admin_user());

-- =====================================================
-- INSERT DEFAULT SOA CONTROLS
-- =====================================================
INSERT INTO soa_controls (control_id, title, category, applicable, implemented) VALUES
('A.5.1', 'Policies for information security', 'Information Security Policies', true, false),
('A.5.2', 'Review of policies', 'Information Security Policies', true, false),
('A.6.1', 'Internal organization', 'Organization of Information Security', true, false),
('A.6.2', 'Mobile devices and remote work', 'Organization of Information Security', true, false),
('A.7.1', 'Prior to employment', 'Human Resource Security', true, false),
('A.7.2', 'During employment', 'Human Resource Security', true, false),
('A.7.3', 'Termination of employment', 'Human Resource Security', true, false),
('A.8.1', 'Responsibility for assets', 'Asset Management', true, false),
('A.8.2', 'Information classification', 'Asset Management', true, false),
('A.8.3', 'Media handling', 'Asset Management', true, false),
('A.9.1', 'Business requirements of access control', 'Access Control', true, false),
('A.9.2', 'User access management', 'Access Control', true, false),
('A.9.3', 'User responsibilities', 'Access Control', true, false),
('A.9.4', 'System and application access control', 'Access Control', true, false)
ON CONFLICT DO NOTHING;

-- =====================================================
-- COMPLETION
-- =====================================================
SELECT 'Database schema created successfully!' AS status;