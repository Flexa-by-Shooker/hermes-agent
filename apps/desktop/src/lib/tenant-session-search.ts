import { searchSessions, type SessionSearchResponse } from '@/hermes'
import { $gatewaySwitching, $tenantRuntimeEpoch } from '@/store/gateway-switch'

export async function searchSessionsForTenant(
  query: string,
  tenantEpoch: number,
  search: (query: string) => Promise<SessionSearchResponse> = searchSessions
): Promise<SessionSearchResponse | null> {
  const result = await search(query)

  return $tenantRuntimeEpoch.get() === tenantEpoch && !$gatewaySwitching.get() ? result : null
}
