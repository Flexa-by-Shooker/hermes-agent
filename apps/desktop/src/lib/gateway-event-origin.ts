import type { HermesConnection } from '@/global'
import type { HermesGateway } from '@/hermes'

export interface GatewayEventOrigin {
  connection: HermesConnection
  gateway: HermesGateway
}

const origins = new WeakMap<object, GatewayEventOrigin>()

export function tagGatewayEventOrigin<T extends object>(event: T, origin: GatewayEventOrigin | null): T {
  if (origin) {
    origins.set(event, origin)
  }

  return event
}

export function gatewayEventOrigin(event: object): GatewayEventOrigin | null {
  return origins.get(event) ?? null
}
