import type { HermesConnection } from '@/global'
import type { HermesGateway } from '@/hermes'
import { GatewayConnectionSupersededError, sameConnectionIdentity } from '@/lib/desktop-gateway-connection'
import type { GatewayRequestCall } from '@/lib/gateway-request'
import { $gateway, gatewayMatchesConnection } from '@/store/gateway'
import { $gatewaySwitching, $tenantRuntimeEpoch } from '@/store/gateway-switch'
import { $connection } from '@/store/session'

export interface ActiveGatewayBinding {
  connection: HermesConnection
  isActive: () => boolean
  request: GatewayRequestCall
}

/** Pin the exact active tenant behind a reused HermesGateway instance. */
export function pinActiveGatewayBinding(gateway: HermesGateway): ActiveGatewayBinding {
  const connection = $connection.get()
  const tenantEpoch = $tenantRuntimeEpoch.get()
  const isActive = () =>
    !$gatewaySwitching.get() &&
    $tenantRuntimeEpoch.get() === tenantEpoch &&
    $gateway.get() === gateway &&
    sameConnectionIdentity($connection.get(), connection) &&
    Boolean(connection && gatewayMatchesConnection(gateway, connection))

  if (!connection || !isActive()) {
    throw new GatewayConnectionSupersededError('Hermes cannot verify the active gateway binding.')
  }

  const request: GatewayRequestCall = async <T>(
    method: string,
    params?: Record<string, unknown>,
    timeoutMs?: number,
    signal?: AbortSignal
  ) => {
    if (!isActive()) {
      throw new GatewayConnectionSupersededError('Hermes changed profiles during the pinned request.')
    }

    const result = await gateway.request<T>(method, params, timeoutMs, signal)

    if (!isActive()) {
      throw new GatewayConnectionSupersededError('Hermes changed profiles during the pinned request.')
    }

    return result
  }

  return { connection, isActive, request }
}
