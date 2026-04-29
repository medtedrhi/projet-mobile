import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import type { AuditCase, CaseInsights, EvidenceItem, MappingReference, MissingIssue } from "../types";

export function useCases() {
  return useQuery<AuditCase[]>({ queryKey: ["cases"], queryFn: api.listCases });
}

export function useCaseDetails(caseId?: string) {
  return useQuery<{ case: AuditCase; summary: any }>({
    queryKey: ["case", caseId],
    queryFn: () => api.getCase(caseId!),
    enabled: Boolean(caseId),
  });
}

export function useEvidence(caseId?: string) {
  return useQuery<EvidenceItem[]>({
    queryKey: ["evidence", caseId],
    queryFn: () => api.getEvidence(caseId!),
    enabled: Boolean(caseId),
  });
}

export function useCaseInsights(caseId?: string) {
  return useQuery<CaseInsights>({
    queryKey: ["case-insights", caseId],
    queryFn: () => api.getCaseInsights(caseId!),
    enabled: Boolean(caseId),
  });
}

export function useMapping(caseId?: string) {
  return useQuery<MappingReference[]>({
    queryKey: ["mapping", caseId],
    queryFn: () => api.getMapping(caseId!),
    enabled: Boolean(caseId),
  });
}

export function useMissingEvidence(caseId?: string) {
  return useQuery<MissingIssue[]>({
    queryKey: ["missing-evidence", caseId],
    queryFn: () => api.getMissingEvidence(caseId!),
    enabled: Boolean(caseId),
  });
}
