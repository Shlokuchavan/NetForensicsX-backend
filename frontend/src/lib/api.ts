export type Case = {
  id: string;
  case_number: string;
  name: string;
  description: string | null;
  status: string;
  severity: string;
  created_at: string;
  updated_at: string;
};

export type Evidence = {
  id: string;
  case_id: string;
  original_filename: string;
  stored_filename: string;
  file_path: string;
  file_size: number;
  sha256: string;
  mime_type: string | null;
  evidence_type: string;
  status: string;
  created_at: string;
};

export type PcapAnalysis = {
  id: string;
  evidence_id: string;
  packet_count: number;
  host_count: number;
  tcp_count: number;
  udp_count: number;
  icmp_count: number;
  dns_count: number;
  http_count: number;
  https_count: number;
  flow_count: number;
  capture_start: number | null;
  capture_end: number | null;
  duration: number;
  status: string;
  created_at: string;
};

export type NetworkFlow = {
  id: string;
  evidence_id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  source_port: number | null;
  destination_port: number | null;
  packets: number;
  bytes: number;
  first_seen: number | null;
  last_seen: number | null;
  created_at: string;
};

export type NetworkHost = {
  id: string;
  evidence_id: string;
  ip_address: string;

  packets_sent: number;
  packets_received: number;

  bytes_sent: number;
  bytes_received: number;

  unique_destinations: number;
  unique_sources: number;

  first_seen: number | null;
  last_seen: number | null;

  created_at: string;
};

export type DNSRecord = {
  id: string;
  evidence_id: string;
  timestamp: number | null;
  source_ip: string;
  destination_ip: string;
  query_name: string;
  query_type: string | null;
  response_code: number | null;
  answers: string | null;
  created_at: string;
};

export type HTTPTransaction = {
  id: string;
  evidence_id: string;
  timestamp: number | null;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  method: string | null;
  host: string | null;
  uri: string | null;
  status_code: number | null;
  user_agent: string | null;
  created_at: string;
};

export type TLSSession = {
  id: string;
  evidence_id: string;
  timestamp: number | null;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  tls_version: string | null;
  sni: string | null;
  cipher: string | null;
  handshake_type: string | null;
  created_at: string;
};

export type TopologyNode = {
  id: string;
  label: string;
  packets: number;
  bytes: number;
  connections: number;
};


export type TopologyEdge = {
  id: string;

  source: string;
  target: string;

  protocol: string;

  source_port: number | null;
  destination_port: number | null;

  packets: number;
  bytes: number;
};


export type NetworkTopology = {
  evidence_id: string;

  nodes: TopologyNode[];
  edges: TopologyEdge[];

  node_count: number;
  edge_count: number;
};

export type Detection = {
  id: string;
  evidence_id: string;
  timestamp: number | null;
  detection_type: string;
  severity: string;
  title: string;
  description: string;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  confidence: number;
  status: string;
  fingerprint: string;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type DetectionSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type DetectionAnalysisResponse = {
  created: number;
  existing: number;
  total: number;
};

export type IOC = {
  id: string;
  evidence_id: string;
  ioc_type: string;
  value: string;
  source: string;
  first_seen: number | null;
  last_seen: number | null;
  occurrences: number;
  confidence: number;
  severity: string;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type IOCAnalysisResponse = {
  created: number;
  updated: number;
  total: number;
};

export type TimelineEvent = {
  id: string;
  evidence_id: string;
  timestamp: number;
  event_type: string;
  source_ip: string | null;
  destination_ip: string | null;
  title: string;
  description: string;
  severity: string;
  reference_type: string | null;
  reference_id: string | null;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type TimelineAnalysisResponse = {
  created: number;
  total: number;
};

export type MitreMapping = {
  id: string;
  evidence_id: string;
  detection_id: string | null;
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  confidence: number;
  metadata_json: Record<string, unknown>;
  created_at: string;
};

export type MitreAnalysisResponse = {
  created: number;
  total: number;
};

export const API_URL = (
process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"
).replace(/\/api\/v1\/?$/, "")
.replace(/\/+$/, "");



export async function getCases(): Promise<Case[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load cases");
  }

  return response.json();
}

export async function getNetworkTopology(
  caseId: string,
  evidenceId: string
): Promise<NetworkTopology> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/topology`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    let message = "Unable to load network topology";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}

export async function getTopology(
  caseId: string,
  evidenceId: string
): Promise<NetworkTopology> {
  return getNetworkTopology(caseId, evidenceId);
}

export async function analyzeDNS(
  caseId: string,
  evidenceId: string
): Promise<DNSRecord[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/dns/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    let message = "Unable to analyze DNS";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getDNSRecords(
  caseId: string,
  evidenceId: string,
  options?: {
    limit?: number;
    offset?: number;
  }
): Promise<DNSRecord[]> {
  const params = new URLSearchParams();

  if (options?.limit !== undefined) {
    params.set("limit", String(options.limit));
  }

  if (options?.offset !== undefined) {
    params.set("offset", String(options.offset));
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/dns${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load DNS records");
  }

  return response.json();
}

export async function analyzeHTTP(
  caseId: string,
  evidenceId: string
): Promise<HTTPTransaction[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/http/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    let message = "Unable to analyze HTTP";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getHTTPTransactions(
  caseId: string,
  evidenceId: string,
  options?: {
    limit?: number;
    offset?: number;
  }
): Promise<HTTPTransaction[]> {
  const params = new URLSearchParams();

  if (options?.limit !== undefined) {
    params.set("limit", String(options.limit));
  }

  if (options?.offset !== undefined) {
    params.set("offset", String(options.offset));
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/http${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load HTTP transactions");
  }

  return response.json();
}
export async function analyzeTLS(
  caseId: string,
  evidenceId: string
): Promise<TLSSession[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/tls/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    let message = "Unable to analyze TLS";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getTLSSessions(
  caseId: string,
  evidenceId: string,
  options?: {
    limit?: number;
    offset?: number;
  }
): Promise<TLSSession[]> {
  const params = new URLSearchParams();

  if (options?.limit !== undefined) {
    params.set("limit", String(options.limit));
  }

  if (options?.offset !== undefined) {
    params.set("offset", String(options.offset));
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/tls${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load TLS sessions");
  }

  return response.json();
}

export async function getCaseById(
  caseId: string
): Promise<Case> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    let message = "Unable to load case";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}
export async function createCase(
  payload: {
    name: string;
    description?: string;
    severity?: string;
  }
): Promise<Case> {
  const response = await fetch(
    `${API_URL}/api/v1/cases`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    let message = "Unable to create case";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getCaseEvidence(
  caseId: string
): Promise<Evidence[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load evidence");
  }

  return response.json();
}


export async function uploadEvidence(
  caseId: string,
  file: File
): Promise<Evidence> {
  const formData = new FormData();

  formData.append(
    "file",
    file
  );

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence`,
    {
      method: "POST",
      body: formData,
    }
  );

  if (!response.ok) {
    let message = "Unable to upload evidence";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function analyzeEvidence(
  caseId: string,
  evidenceId: string
): Promise<PcapAnalysis> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    let message = "Unable to analyze PCAP";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getEvidenceAnalysis(
  caseId: string,
  evidenceId: string
): Promise<PcapAnalysis | null> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/analysis`,
    {
      cache: "no-store",
    }
  );

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error("Unable to load analysis");
  }

  return response.json();
}


export async function getEvidenceFlows(
  caseId: string,
  evidenceId: string,
  options?: {
    limit?: number;
    offset?: number;
    protocol?: string;
  }
): Promise<NetworkFlow[]> {
  const params = new URLSearchParams();

  if (options?.limit !== undefined) {
    params.set(
      "limit",
      String(options.limit)
    );
  }

  if (options?.offset !== undefined) {
    params.set(
      "offset",
      String(options.offset)
    );
  }

  if (
    options?.protocol &&
    options.protocol !== "ALL"
  ) {
    params.set(
      "protocol",
      options.protocol
    );
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/flows${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    let message = "Unable to load network flows";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function discoverHosts(
  caseId: string,
  evidenceId: string
): Promise<NetworkHost[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/hosts/discover`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    let message = "Unable to discover hosts";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}


export async function getDiscoveredHosts(
  caseId: string,
  evidenceId: string
): Promise<NetworkHost[]> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/hosts`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load discovered hosts");
  }

  return response.json();
}

export async function analyzeDetections(
  caseId: string,
  evidenceId: string
): Promise<DetectionAnalysisResponse> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/detections/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to analyze detections");
  }

  return response.json();
}


export async function getDetections(
  caseId: string,
  evidenceId: string,
  options?: {
    severity?: string;
    detectionType?: string;
    status?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }
): Promise<Detection[]> {
  const params = new URLSearchParams();

  if (options?.severity) {
    params.set("severity", options.severity);
  }

  if (options?.detectionType) {
    params.set(
      "detection_type",
      options.detectionType
    );
  }

  if (options?.status) {
    params.set("status", options.status);
  }

  if (options?.search) {
    params.set("search", options.search);
  }

  if (options?.limit !== undefined) {
    params.set(
      "limit",
      String(options.limit)
    );
  }

  if (options?.offset !== undefined) {
    params.set(
      "offset",
      String(options.offset)
    );
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/detections${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load detections");
  }

  return response.json();
}


export async function getDetectionSummary(
  caseId: string,
  evidenceId: string
): Promise<DetectionSummary> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/detections/summary`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load detection summary");
  }

  return response.json();
}

export async function analyzeIOCs(
  caseId: string,
  evidenceId: string
): Promise<IOCAnalysisResponse> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/iocs/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to extract IOCs");
  }

  return response.json();
}


export async function getIOCs(
  caseId: string,
  evidenceId: string,
  options?: {
    iocType?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }
): Promise<IOC[]> {
  const params = new URLSearchParams();

  if (options?.iocType) {
    params.set(
      "ioc_type",
      options.iocType
    );
  }

  if (options?.search) {
    params.set(
      "search",
      options.search
    );
  }

  if (options?.limit !== undefined) {
    params.set(
      "limit",
      String(options.limit)
    );
  }

  if (options?.offset !== undefined) {
    params.set(
      "offset",
      String(options.offset)
    );
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/iocs${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load IOCs");
  }

  return response.json();
}

export async function buildTimeline(
  caseId: string,
  evidenceId: string
): Promise<TimelineAnalysisResponse> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/timeline/build`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to build timeline");
  }

  return response.json();
}


export async function getTimeline(
  caseId: string,
  evidenceId: string,
  options?: {
    eventType?: string;
    severity?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }
): Promise<TimelineEvent[]> {
  const params = new URLSearchParams();

  if (options?.eventType) {
    params.set(
      "event_type",
      options.eventType
    );
  }

  if (options?.severity) {
    params.set(
      "severity",
      options.severity
    );
  }

  if (options?.search) {
    params.set(
      "search",
      options.search
    );
  }

  if (options?.limit !== undefined) {
    params.set(
      "limit",
      String(options.limit)
    );
  }

  if (options?.offset !== undefined) {
    params.set(
      "offset",
      String(options.offset)
    );
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/timeline${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load timeline");
  }

  return response.json();
}
export async function analyzeMitre(
  caseId: string,
  evidenceId: string
): Promise<MitreAnalysisResponse> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/mitre/analyze`,
    {
      method: "POST",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to map MITRE ATT&CK techniques");
  }

  return response.json();
}


export async function getMitreMappings(
  caseId: string,
  evidenceId: string,
  options?: {
    techniqueId?: string;
    tactic?: string;
    limit?: number;
    offset?: number;
  }
): Promise<MitreMapping[]> {
  const params = new URLSearchParams();

  if (options?.techniqueId) {
    params.set(
      "technique_id",
      options.techniqueId
    );
  }

  if (options?.tactic) {
    params.set(
      "tactic",
      options.tactic
    );
  }

  if (options?.limit !== undefined) {
    params.set(
      "limit",
      String(options.limit)
    );
  }

  if (options?.offset !== undefined) {
    params.set(
      "offset",
      String(options.offset)
    );
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/evidence/${evidenceId}/mitre${
      query ? `?${query}` : ""
    }`,
    {
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error("Unable to load MITRE mappings");
  }

  return response.json();
}

/* =========================================================
   Additions for CaseInvestigationPanel
   These mirror endpoints the panel already calls directly.
   ========================================================= */

export type CaseActivity = {
  id: string;
  actor?: string;
  action?: string;
  details?: string;
  created_at?: string;
};

export type CaseActivityList = {
  items?: CaseActivity[];
};

export type CaseReport = {
  report_type?: string;
  generated_at?: string;
  case?: Record<string, unknown>;
  summary?: Record<string, unknown>;
  evidence?: Record<string, unknown>[];
  detections?: Record<string, unknown>[];
  iocs?: Record<string, unknown>[];
  timeline_events?: Record<string, unknown>[];
  mitre_mappings?: Record<string, unknown>[];
  limitations?: string[];
};

export async function getCaseReport(
  caseId: string,
  evidenceId?: string
): Promise<CaseReport> {
  const params = new URLSearchParams();

  if (evidenceId && evidenceId.trim()) {
    params.set("evidence_id", evidenceId.trim());
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/reports/cases/${caseId}${query ? `?${query}` : ""}`,
    { cache: "no-store" }
  );

  if (!response.ok) {
    let message = "Unable to load report";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}

export async function exportCaseReport(
  caseId: string,
  format: "json" | "pdf",
  evidenceId?: string
): Promise<Blob> {
  const params = new URLSearchParams();

  if (evidenceId && evidenceId.trim()) {
    params.set("evidence_id", evidenceId.trim());
  }

  const query = params.toString();

  const response = await fetch(
    `${API_URL}/api/v1/reports/cases/${caseId}/export.${format}${
      query ? `?${query}` : ""
    }`,
    { cache: "no-store" }
  );

  if (!response.ok) {
    const body = await response.text();

    throw new Error(
      `Export failed (${response.status}): ${body.slice(0, 250)}`
    );
  }

  return response.blob();
}

export async function getCaseActivity(
  caseId: string
): Promise<CaseActivityList> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/activity`,
    { cache: "no-store" }
  );

  if (!response.ok) {
    let message = "Unable to load case activity";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}

export async function createCaseActivity(
  caseId: string,
  payload: { actor: string; action: string; details: string }
): Promise<unknown> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/activity`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    let message = "Unable to save activity";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}

export async function updateCaseStatus(
  caseId: string,
  payload: { status: string; actor: string }
): Promise<unknown> {
  const response = await fetch(
    `${API_URL}/api/v1/cases/${caseId}/status`,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );

  if (!response.ok) {
    let message = "Unable to update case status";

    try {
      const data = await response.json();

      if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch {}

    throw new Error(message);
  }

  return response.json();
}
