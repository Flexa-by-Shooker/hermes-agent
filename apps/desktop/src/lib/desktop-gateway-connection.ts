import { GatewayReauthRequiredError } from '@hermes/shared'

import type { HermesConnection } from '@/global'

export interface DesktopGatewayUrlBridge {
  getGatewayWsUrl?: (profile: null | string, generation: number) => Promise<string>
}

export class GatewayConnectionSupersededError extends Error {
  readonly code = 'HERMES_STALE_CONNECTION'

  constructor(message = 'The Hermes connection changed while connecting. Please retry.') {
    super(message)
    this.name = 'GatewayConnectionSupersededError'
  }
}

export function isGatewayConnectionSuperseded(error: unknown): boolean {
  return (
    error instanceof GatewayConnectionSupersededError ||
    (typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'HERMES_STALE_CONNECTION')
  )
}

export function exactConnectionProfile(connection: HermesConnection): string {
  const profile = connection.profile?.trim()

  if (!profile) {
    throw new GatewayConnectionSupersededError('Hermes returned a connection without an exact profile.')
  }

  return profile
}

export function exactConnectionGeneration(connection: HermesConnection): number {
  if (!Number.isSafeInteger(connection.generation) || connection.generation <= 0) {
    throw new GatewayConnectionSupersededError('Hermes returned a connection without a valid generation.')
  }

  return connection.generation
}

export function sameConnectionIdentity(
  left: Pick<HermesConnection, 'authorityId' | 'generation' | 'profile'> | null | undefined,
  right: Pick<HermesConnection, 'authorityId' | 'generation' | 'profile'> | null | undefined
): boolean {
  return Boolean(
    left &&
    right &&
    left.profile?.trim() &&
    left.profile?.trim() === right.profile?.trim() &&
    left.generation === right.generation &&
    (left.authorityId || right.authorityId ? left.authorityId === right.authorityId : true)
  )
}

/**
 * Resolve a URL for this exact immutable descriptor. Unlike the generic shared
 * helper, Desktop passes both profile and generation to Electron so a late
 * OAuth mint or token refresh cannot silently attach a socket to a replacement
 * backend. Token connections intentionally fail closed too: falling back to a
 * cached URL after a stale-generation rejection would defeat the identity
 * check.
 */
export async function resolveDesktopGatewayWsUrl(
  desktop: DesktopGatewayUrlBridge,
  connection: HermesConnection
): Promise<string> {
  const profile = exactConnectionProfile(connection)
  const generation = exactConnectionGeneration(connection)
  const mint = desktop.getGatewayWsUrl

  if (!mint) {
    if (connection.authMode === 'oauth') {
      throw new GatewayReauthRequiredError(
        'Your remote gateway session needs to be refreshed. Open Settings -> Gateway and click "Sign in" again.'
      )
    }

    throw new GatewayConnectionSupersededError('Desktop cannot verify the current Hermes connection.')
  }

  try {
    const url = await mint(profile, generation)

    if (!url) {
      throw new Error('Hermes returned an empty gateway URL.')
    }

    return url
  } catch (error) {
    if (isGatewayConnectionSuperseded(error)) {
      throw error
    }

    if (connection.authMode === 'oauth') {
      throw new GatewayReauthRequiredError(
        'Your remote gateway session has expired. Open Settings -> Gateway and click "Sign in" again.',
        { cause: error }
      )
    }

    throw error
  }
}
