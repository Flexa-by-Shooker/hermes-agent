import { isGatewayReauthRequired } from '@hermes/shared'
import { useStore } from '@nanostores/react'
import { useCallback, useEffect, useRef } from 'react'

import type { HermesConnection } from '@/global'
import type { HermesGateway } from '@/hermes'
import {
  exactConnectionProfile,
  GatewayConnectionSupersededError,
  resolveDesktopGatewayWsUrl,
  sameConnectionIdentity
} from '@/lib/desktop-gateway-connection'
import type { GatewayRequest, GatewayRequestCall } from '@/lib/gateway-request'
import {
  $gateway,
  ensureExactSecondaryGatewayOpen,
  gatewayMatchesConnection,
  isExactPrimaryGateway
} from '@/store/gateway'
import { $gatewaySwitching } from '@/store/gateway-switch'
import { $activeGatewayProfile } from '@/store/profile'
import { $connection, $gatewayState, setConnection } from '@/store/session'

interface GatewayBinding {
  connection: HermesConnection
  gateway: HermesGateway
  profile: string
}

export function useGatewayRequest() {
  const gatewayState = useStore($gatewayState)
  const gatewayRef = useRef<HermesGateway | null>(null)

  const connectionRef = useRef<Awaited<ReturnType<NonNullable<typeof window.hermesDesktop>['getConnection']>> | null>(
    null
  )

  const gatewayStateRef = useRef(gatewayState)
  const reconnectingRef = useRef<
    | (GatewayBinding & {
        promise: Promise<HermesGateway | null>
      })
    | null
  >(null)
  // Holds the reauth error from the most recent failed reconnect so
  // requestGateway can surface the gateway's "session expired, sign in again"
  // message instead of the opaque "connection closed" that triggered the retry.
  const reauthErrorRef = useRef<unknown>(null)

  useEffect(() => {
    gatewayStateRef.current = gatewayState
  }, [gatewayState])

  // Track the active gateway (primary or a background profile's socket) so
  // outbound requests and overlay props always target the focused profile.
  useEffect(
    () =>
      $gateway.subscribe(gateway => {
        gatewayRef.current = gateway as HermesGateway | null
      }),
    []
  )

  const captureActiveBinding = useCallback((): GatewayBinding => {
    const gateway = gatewayRef.current
    const connection = $connection.get()
    const profile = ($activeGatewayProfile.get() || '').trim() || 'default'

    if (
      $gatewaySwitching.get() ||
      !gateway ||
      !connection ||
      exactConnectionProfile(connection) !== profile ||
      !gatewayMatchesConnection(gateway, connection)
    ) {
      throw new GatewayConnectionSupersededError('Hermes changed gateways before the request could be pinned.')
    }

    return { connection, gateway, profile }
  }, [])

  const bindingIsActive = useCallback(
    (binding: GatewayBinding): boolean =>
      !$gatewaySwitching.get() &&
      gatewayRef.current === binding.gateway &&
      $activeGatewayProfile.get() === binding.profile &&
      sameConnectionIdentity($connection.get(), binding.connection) &&
      gatewayMatchesConnection(binding.gateway, binding.connection),
    []
  )

  const ensureGatewayOpen = useCallback(
    async (binding: GatewayBinding): Promise<HermesGateway | null> => {
      const { connection: originConnection, gateway: existing, profile: targetProfile } = binding

      if (!bindingIsActive(binding)) {
        return null
      }

      if (gatewayStateRef.current === 'open') {
        return existing
      }

      const reconnecting = reconnectingRef.current

      if (reconnecting) {
        return sameConnectionIdentity(reconnecting.connection, originConnection) && reconnecting.gateway === existing
          ? reconnecting.promise
          : null
      }

      const task = (async () => {
        const desktop = window.hermesDesktop

        if (!desktop) {
          return null
        }

        reauthErrorRef.current = null

        try {
          const conn = await desktop.getConnection(targetProfile)

          if (
            !bindingIsActive(binding) ||
            exactConnectionProfile(conn) !== targetProfile ||
            !sameConnectionIdentity(conn, originConnection)
          ) {
            return null
          }
          const wsUrl = await resolveDesktopGatewayWsUrl(desktop, conn)

          if (!bindingIsActive(binding)) {
            return null
          }

          await existing.connect(wsUrl)

          if (!bindingIsActive(binding)) {
            return null
          }

          connectionRef.current = conn
          setConnection(conn)

          return existing
        } catch (error) {
          if (isGatewayReauthRequired(error)) {
            reauthErrorRef.current = error
          }

          if (bindingIsActive(binding)) {
            connectionRef.current = null
            setConnection(null)
          }

          return null
        }
      })()

      reconnectingRef.current = { ...binding, promise: task }

      try {
        return await task
      } finally {
        if (reconnectingRef.current?.promise === task) {
          reconnectingRef.current = null
        }
      }
    },
    [bindingIsActive]
  )

  const pinGateway = useCallback((): GatewayRequestCall => {
    const binding = captureActiveBinding()

    return async <T>(method: string, params = {}, timeoutMs?: number, signal?: AbortSignal): Promise<T> => {
      if (!gatewayMatchesConnection(binding.gateway, binding.connection)) {
        throw new GatewayConnectionSupersededError('The originating Hermes gateway is no longer available.')
      }

      return binding.gateway.request<T>(method, params, timeoutMs, signal)
    }
  }, [captureActiveBinding])

  const requestGateway = useCallback(
    async <T>(method: string, params: Record<string, unknown> = {}, timeoutMs?: number, signal?: AbortSignal) => {
      const binding = captureActiveBinding()

      try {
        const result = await binding.gateway.request<T>(method, params, timeoutMs, signal)

        if (!bindingIsActive(binding)) {
          throw new GatewayConnectionSupersededError('Hermes changed profiles before the request completed.')
        }

        return result
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)

        if (!/not connected|connection closed/i.test(message)) {
          throw error
        }

        if (!bindingIsActive(binding)) {
          throw new GatewayConnectionSupersededError('Hermes changed profiles before the request retry.')
        }

        const recovered = isExactPrimaryGateway(binding.gateway, binding.profile)
          ? await ensureGatewayOpen(binding)
          : await ensureExactSecondaryGatewayOpen(binding.profile, binding.gateway, binding.connection)

        if (!recovered || recovered !== binding.gateway || !bindingIsActive(binding)) {
          // Prefer the reauth error from the failed reconnect (OAuth session
          // expired) over the generic transport error that triggered the retry.
          const reauthError = reauthErrorRef.current
          reauthErrorRef.current = null

          if (reauthError) {
            throw reauthError
          }

          throw error
        }

        const result = await recovered.request<T>(method, params, timeoutMs, signal)

        if (!bindingIsActive(binding)) {
          throw new GatewayConnectionSupersededError('Hermes changed profiles before the request completed.')
        }

        return result
      }
    },
    [bindingIsActive, captureActiveBinding, ensureGatewayOpen]
  ) as GatewayRequest

  requestGateway.pin = pinGateway

  return { connectionRef, gatewayRef, requestGateway }
}
