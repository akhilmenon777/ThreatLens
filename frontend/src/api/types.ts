// Typed models mirroring backend/app/schemas (see /docs for the OpenAPI document).

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type IncidentStatus = 'new' | 'in_progress' | 'escalated' | 'resolved' | 'closed'
export type EvidenceStatus = 'OBSERVED' | 'INFERRED' | 'NOT_OBSERVED'

export interface Page<T> {
  total: number
  page: number
  page_size: number
  items: T[]
}

export interface Dataset {
  id: number
  name: string
  version: string
  description: string
  synthetic: boolean
  is_active: boolean
  created_at: string
  has_labels: boolean
  event_count: number
}

export interface Health {
  status: string
  backend: boolean
  database: boolean
  app_version: string
  llm: { available: boolean; models: string[]; error?: string; mode: string; base_url: string; version?: string | null }
  active_dataset: string | null
}

export interface Entities {
  source_ips: string[]
  destination_ips: string[]
  internal_hosts: string[]
  external_ips: string[]
  hostnames: string[]
  dns_domains: string[]
  users: string[]
  ports: number[]
}

export interface IncidentListItem {
  id: string
  title: string
  severity: Severity
  risk_score: number
  confidence: number
  first_seen: string
  last_seen: string
  event_count: number
  sensors: string[]
  entities: Entities
  tactics: string[]
  stages_present: string[]
  status: IncidentStatus
  assignee: string | null
  suspected_false_positive: boolean
  synthetic: boolean
}

export interface Stage {
  order: number
  stage: string
  status: EvidenceStatus
  first_timestamp: string | null
  event_ids: string[]
  observed_behavior: string
  evidence_strength: string
  confidence: number
  explanation: string
}

export interface Mapping {
  tactic_id: string
  tactic_name: string
  technique_id: string | null
  technique_name: string | null
  method: string
  status: 'OBSERVED' | 'INFERRED'
  confidence: number
  evidence_event_ids: string[]
  reason: string
  attack_version: string
  url: string | null
}

export interface BreakdownItem {
  factor: string
  label: string
  value: number
  weight: number
  points?: number
  contribution?: number
  explanation: string
}

export interface Note {
  id: number
  author: string
  text: string
  created_at: string
}

export interface StatusChange {
  from_status: string | null
  to_status: string
  actor: string
  reason: string
  created_at: string
}

export interface SummaryContent {
  executive_summary: string
  probable_sequence: { stage: string; status: 'OBSERVED' | 'INFERRED'; description: string; evidence_event_ids: string[] }[]
  claims: { text: string; status: 'OBSERVED' | 'INFERRED'; evidence_event_ids: string[] }[]
  alternative_explanations: string[]
  missing_evidence: string[]
  investigation_questions: string[]
  recommended_next_steps: string[]
  fallback_reason?: string
  model_attempted?: string | null
  raw_excerpt?: string
}

export interface Summary {
  id: number
  generator: 'llm' | 'fallback'
  model: string
  model_version: string | null
  prompt_version: string
  status: 'valid' | 'fallback' | 'invalid'
  content: SummaryContent
  latency_ms: number
  attempts: number
  validation_errors: string[]
  injection_flags: { event_id: string | null; field: string; length: number; excerpt: string }[]
  created_at: string
  is_current: boolean
}

export interface IncidentDetail extends IncidentListItem {
  description: string
  risk_breakdown: BreakdownItem[]
  confidence_breakdown: BreakdownItem[]
  alternative_explanations: string[]
  correlation_notes: string[]
  stages: Stage[]
  mappings: Mapping[]
  notes: Note[]
  status_changes: StatusChange[]
  summary: Summary | null
  link_count: number
  run_id: number
  ground_truth?: { labelled: number; malicious: number; benign: number; tactics: { tactic: string; count: number }[] } | null
}

export interface EventItem {
  event_id: string
  source_sensor: string
  source_log: string
  timestamp_utc: string
  event_type: string
  source_ip: string | null
  source_port: number | null
  destination_ip: string | null
  destination_port: number | null
  transport_protocol: string | null
  application_protocol: string | null
  destination_host: string | null
  alert_signature: string | null
  alert_signature_id: number | null
  alert_category: string | null
  sensor_severity: number | null
  connection_state: string | null
  bytes_sent: number | null
  bytes_received: number | null
  duration: number | null
  dns_query: string | null
  http_host: string | null
  http_uri: string | null
  http_user_agent: string | null
  tls_server_name: string | null
  auth_success: boolean | null
  community_id: string | null
  flow_uid: string | null
  normalization_warnings: string[]
  detector_tags: string[]
  tag_evidence: Record<string, string>
  original_event_reference: string
  incident_ids: string[]
  stage: string | null
  ground_truth?: GroundTruth | null
}

export interface GroundTruth { malicious: boolean; tactics: string[]; techniques: string[] }

export interface EventDetail extends EventItem {
  raw_payload: string
  source_record_id: string | null
  schema_version: string
}

export interface Link {
  event_a: string
  event_b: string
  score: number
  components: { entity: number; time: number; behavior: number; cross_sensor: number }
  shared_entities: string[]
  dt_seconds: number
  rule: string
  explanation: string
  uncertainty: string
}

export interface Job {
  id: number
  dataset_id: number
  filename: string
  sensor: string
  file_format: string
  status: string
  total_records: number
  accepted: number
  rejected: number
  duplicates: number
  with_warnings: number
  message: string
  started_at: string
  finished_at: string | null
}

export interface CorrelationRunOut {
  id: number
  status: string
  n_events: number
  n_signal_events: number
  n_links: number
  n_incidents: number
  n_unassigned: number
  duration_ms: number
  message: string
  finished_at: string | null
}

export interface Overview {
  dataset: { id: number; name: string; version: string; synthetic: boolean }
  totals: {
    raw_events: number
    signal_events: number
    incidents: number
    critical_high: number
    events_in_incidents: number
    unassigned_events: number
    unassigned_signal_events: number
    triage_items: number
    reduction_pct: number | null
    triage_reduction_pct: number | null
    open_incidents: number
  }
  definitions: Record<string, string>
  latest_ingestion: string | null
  correlation_run: { id: number; finished_at: string | null; duration_ms: number; message: string } | null
  severity_distribution: { severity: Severity; count: number }[]
  status_distribution: { status: IncidentStatus; count: number }[]
  sensor_distribution: { sensor: string; count: number }[]
  stage_distribution: { stage: string; OBSERVED: number; INFERRED: number }[]
  timeline: { hour: string; suricata: number; zeek: number; wazuh?: number; aminer?: number; signal: number; incidents_started: number }[]
  timeline_granularity?: 'hour' | 'day' 
  heatmap: { hosts: string[]; tactics: string[]; cells: { host: string; tactic: string; count: number }[] }
  top_incidents: IncidentListItem[]
}

export interface MatrixTechnique {
  id: string
  name: string
  url: string
  count: number
  observed: number
  inferred: number
  max_confidence: number | null
  incidents: string[]
  methods: string[]
  evidence_events: number
}

export interface Matrix {
  version: string
  coverage_note: string
  tactics: { id: string; name: string; count: number; techniques: MatrixTechnique[] }[]
}

export interface PRF {
  precision: number | null
  recall: number | null
  f1: number | null
  tp: number
  fp: number
  fn: number
  unit?: string
}

export interface MethodResult {
  method: string
  input_events: number
  signal_events: number
  incidents: number
  signal_events_in_incidents: number
  unassigned_signal_events: number
  unassigned_events_total: number
  triage_items: number
  reduction_all_events_pct: number | null
  triage_reduction_vs_independent_pct: number | null
  largest_incident: number
  grouping?: PRF
  labelled_malicious_events_not_in_any_incident?: number
  labelled_malicious_events?: number
  unrelated_singletons_merged?: number | null
  detection?: PRF
}

export interface LabelScores {
  labelled_events: number
  labelled_malicious: number
  tactics: { tactic: string; events: number; signal: number; in_incident: number; recall: number | null }[]
  tactic_agreement: PRF
  incidents: { title: string; events: number; severity: Severity; labelled_malicious: number; purity: number; predicted_tactics: string[]; labelled_tactics: string[] }[]
  incidents_without_labelled_attack: number
  note: string
}

export interface ScenarioRow {
  group: string
  description: string
  malicious: boolean
  detected: boolean
  labelled_events: number
  matched_incident_events: number
  incident_severity?: Severity
  risk_score?: number
  confidence?: number
  predicted_stages?: string[]
  expected_stages?: string[]
  stage_order_correct?: boolean | null
  predicted_techniques?: string[]
  expected_techniques?: string[]
  benign_escalated_to_high?: boolean | null
  severity_within_expectation?: boolean | null
  group_recall?: number
  incident_purity?: number
}

export interface EvaluationResults {
  dataset: { name: string; version: string; synthetic: boolean; input_events: number; signal_events: number }
  engine_version: string
  attack_catalog: string
  ground_truth: { available: boolean; version: string | null; note: string }
  timings: Record<string, number>
  methods: Record<string, MethodResult>
  semantic_experiment_note: string
  label_scores?: LabelScores | null
  scenario_scores: null | {
    groups: ScenarioRow[]
    attack_chain_stages: PRF
    stage_order_correct: { correct: number; evaluated: number }
    attack_techniques: PRF
    attack_tactics: PRF
    benign: { benign_groups_with_incident: number; escalated_to_high_or_critical: number; false_positive_rate: number | null; note: string }
  }
  llm: {
    run: boolean
    note?: string
    incidents_evaluated?: number
    fallback_valid_rate?: number | null
    models?: Record<string, Record<string, unknown>>
  }
}

export interface EvaluationRun {
  id: number
  dataset_id: number
  created_at: string
  status: 'running' | 'completed' | 'failed'
  params: Record<string, unknown>
  results?: EvaluationResults
  duration_ms: number
  message: string
  summary?: { incidents: number; f1: number | null; llm: boolean } | null
}

export interface AnalysisSettings {
  correlation: Record<string, number | string[]>
  risk: Record<string, number>
  llm: {
    mode: 'off' | 'cached' | 'live'
    ollama_base_url: string
    primary_model: string
    secondary_model: string
    timeout_seconds: number
    max_retries: number
    temperature: number
    max_events_in_prompt: number
  }
  display: { timezone: string; attack_version: string; retain_raw_payload: boolean; max_raw_payload_chars: number }
}

export interface LlmStatus {
  available: boolean
  base_url: string
  error?: string
  version?: string | null
  models: { name: string; size?: number; parameter_size?: string; quantization?: string; family?: string }[]
  configured: { primary: string; secondary: string }
  primary_installed?: boolean
  secondary_installed?: boolean
}

export interface KeyCount { key: string | number; count: number }

export interface Analytics {
  dataset: { id: number; name: string; description: string; version: string; synthetic: boolean }
  totals: {
    events: number; signal_events: number; unique_sources: number; unique_destinations: number
    bytes_out: number; bytes_in: number; first_seen: string | null; last_seen: string | null; span_hours: number
  }
  granularity: 'hour' | 'day'
  timeline: { t: string; events: number; signal: number; malicious: number; benign: number }[]
  protocols: KeyCount[]
  services: KeyCount[]
  conn_states: KeyCount[]
  dest_ports: KeyCount[]
  top_sources: KeyCount[]
  top_destinations: KeyCount[]
  top_sources_by_bytes: { key: string; bytes: number }[]
  detector_tags: { tag: string; count: number }[]
  sources: {
    sensor: string; events: number; signal: number; in_incident: number; malicious: number; detected: number
    recall: number | null; precision: number | null; first_seen: string | null; last_seen: string | null
  }[]
  top_alerts: { key: string; sensor: string; count: number }[]
  ground_truth: {
    available: boolean
    labelled_events?: number
    malicious?: number
    benign?: number
    tactics?: { tactic: string; events: number; tagged: number; in_incident: number; coverage_pct: number | null }[]
    techniques?: { technique: string; count: number }[]
    detection?: PRF
    tactic_timeline?: ({ t: string } & Record<string, number | string>)[]
    note?: string | null
  }
}

export interface TaskStatus {
  id: string
  kind: string
  status: 'running' | 'completed' | 'failed'
  progress: number
  message: string
  result: { dataset: Dataset; jobs: Job[]; correlation: CorrelationRunOut; settings_changed: string | null } | null
  error: string | null
  elapsed_s: number
}

export interface UwfInfo {
  parts: { id: string; label: string; description: string; files: { name: string; bytes: number }[]; bytes: number }[]
  loaded: Dataset[]
  running_task: TaskStatus | null
  ait?: { original_total: number; kept_total: number; method: string; source: string } | null
}
