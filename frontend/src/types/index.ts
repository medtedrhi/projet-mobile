export type AuditCase = {
  id: string;
  app_name: string;
  package_name?: string | null;
  version_name?: string | null;
  version_code?: string | null;
  auditor: string;
  audit_date: string;
  scope: string;
  notes?: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

export type CaseSummary = {
  total_artifacts: number;
  total_evidence_items: number;
  total_mappings: number;
  total_missing_issues: number;
  completeness_score: number;
};

export type EvidenceItem = {
  id: string;
  case_id: string;
  evidence_type: string;
  source: string;
  original_filename?: string | null;
  normalized_path: string;
  hash_sha256?: string | null;
  mime_type?: string | null;
  size?: number | null;
  tags?: string | null;
  description?: string | null;
  sensitivity_level: string;
  anonymized_flag: boolean;
  traceability_refs?: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

export type MappingReference = {
  id: string;
  case_id: string;
  evidence_item_id?: string | null;
  masvs_refs?: string | null;
  maswe_refs?: string | null;
  mastg_refs?: string | null;
  status: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
};

export type MissingIssue = {
  id: string;
  case_id: string;
  rule_id: string;
  category: string;
  severity: string;
  title: string;
  rationale: string;
  recommendation: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type GeneratedReport = {
  id: string;
  case_id: string;
  report_type: string;
  output_path: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type ExportBundle = {
  id: string;
  case_id: string;
  bundle_type: string;
  output_path: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type AndroidDevice = {
  serial: string;
  state: string;
  model?: string | null;
  product?: string | null;
  device?: string | null;
  transport_id?: string | null;
};

export type CaseInsights = {
  collection_summary: string;
  missing_narratives: string[];
  missing_explanations: {
    title: string;
    why_it_matters?: string | null;
    next_step: string;
    narrative: string;
  }[];
  provider_mode: string;
  provider_label: string;
};
