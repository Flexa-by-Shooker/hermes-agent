import { useStore } from '@nanostores/react'
import { useQuery } from '@tanstack/react-query'

import { getHermesConfigRecord } from '@/hermes'
import { queryClient } from '@/lib/query-client'
import { $gatewaySwitching, $tenantRuntimeEpoch } from '@/store/gateway-switch'
import type { HermesConfigRecord } from '@/types/hermes'

// One shared cache namespace for the whole profile config record
// (`GET /api/config`). The tenant epoch suffix keeps a late result from one
// backend out of another backend's cache.
export const HERMES_CONFIG_KEY = ['hermes-config-record'] as const

export const hermesConfigKey = (tenantEpoch: number) => [...HERMES_CONFIG_KEY, tenantEpoch] as const

// Reads pause while the mutable REST connection is between tenants. Each
// runtime epoch receives a distinct key, so an old in-flight result cannot
// populate or paint the new tenant's configuration.
export const useHermesConfigRecord = () => {
  const gatewaySwitching = useStore($gatewaySwitching)
  const tenantEpoch = useStore($tenantRuntimeEpoch)

  return useQuery({
    enabled: !gatewaySwitching,
    queryKey: hermesConfigKey(tenantEpoch),
    queryFn: getHermesConfigRecord,
    staleTime: 0
  })
}

type HermesConfigUpdater =
  | HermesConfigRecord
  | ((current: HermesConfigRecord | undefined) => HermesConfigRecord | undefined)

export const setHermesConfigCache = (update: HermesConfigUpdater, tenantEpoch = $tenantRuntimeEpoch.get()): void =>
  void queryClient.setQueryData<HermesConfigRecord>(hermesConfigKey(tenantEpoch), current =>
    typeof update === 'function' ? update(current) : update
  )

export const invalidateHermesConfig = () => queryClient.invalidateQueries({ queryKey: HERMES_CONFIG_KEY })
