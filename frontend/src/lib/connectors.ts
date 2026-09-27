/**
 * Connector registry queries.
 *
 * The registry is the source of truth for what the platform can scan: a
 * connector declares its module, its own job type and the settings it accepts
 * at registration. Reading that over the API is what lets a connector added
 * after this frontend was built show up in job history and become configurable
 * without a frontend change.
 *
 * Credentials are per connector too: each worker authenticates with its own
 * token, so one leaked value can be revoked (or rotated) without touching the
 * others.
 */

import { api } from "@/lib/api";
import type { Connector, ConnectorModulesResponse, ConnectorTokenResponse } from "@/types/api";

/** Modules with their connectors, declared job types and config schemas. */
export function fetchConnectorModules(): Promise<ConnectorModulesResponse> {
  return api.get<ConnectorModulesResponse>("/connectors/modules").then((r) => r.data);
}

/**
 * Issue (or rotate) a connector's own credential.
 *
 * The plaintext comes back exactly once — the core keeps only a digest — so the
 * caller must show it to the operator immediately and never store it.
 */
export function issueConnectorToken(connectorId: string): Promise<ConnectorTokenResponse> {
  return api.post<ConnectorTokenResponse>(`/connectors/${connectorId}/token`).then((r) => r.data);
}

/** Revoke a connector's credential; its registry row and history are kept. */
export function revokeConnectorToken(connectorId: string): Promise<Connector> {
  return api.delete<Connector>(`/connectors/${connectorId}/token`).then((r) => r.data);
}
