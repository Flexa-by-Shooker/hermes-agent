import type { HermesConnection } from '@/global'

import { exactConnectionProfile } from './desktop-gateway-connection'

const SCOPE_PREFIX = 'hermes-composer:v2'
const SESSION_MARKER = ':session:'
const NEW_SESSION = '__new__'

function normalizedRemoteAuthority(baseUrl: string): string | null {
  try {
    const url = new URL(baseUrl)

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null
    }

    url.hash = ''
    url.password = ''
    url.search = ''
    url.username = ''
    url.pathname = url.pathname.replace(/\/+$/, '') || '/'

    return url.toString().replace(/\/$/, '')
  } catch {
    return null
  }
}

/** Stable tenant authority for composer state. Reconnect generations are
 * intentionally excluded so a reconnect preserves the employee's draft. */
export function composerGatewayScope(connection: HermesConnection | null | undefined): string | null {
  if (!connection) {
    return null
  }

  let profile: string

  try {
    profile = exactConnectionProfile(connection)
  } catch {
    return null
  }

  const mode = connection.mode === 'remote' ? 'remote' : 'local'
  const authority = mode === 'remote' ? normalizedRemoteAuthority(connection.baseUrl) : 'desktop-local'
  const authenticatedAuthority = mode === 'remote' ? connection.authorityId?.trim() : 'desktop-local-user'

  if (!authority || !authenticatedAuthority) {
    return null
  }

  return `${SCOPE_PREFIX}:${mode}:${encodeURIComponent(authority)}:authority:${encodeURIComponent(authenticatedAuthority)}:profile:${encodeURIComponent(profile)}`
}

/** Profile- and backend-qualified scope for drafts, chips, and prompt queues. */
export function composerSessionScope(
  connection: HermesConnection | null | undefined,
  sessionKey: string | null | undefined
): string | null {
  const gatewayScope = composerGatewayScope(connection)

  if (!gatewayScope) {
    return null
  }

  const session = sessionKey?.trim() || NEW_SESSION

  return `${gatewayScope}${SESSION_MARKER}${encodeURIComponent(session)}`
}

export function sameComposerGatewayScope(left: string | null | undefined, right: string | null | undefined): boolean {
  const namespace = (scope: string | null | undefined): string | null => {
    const index = scope?.lastIndexOf(SESSION_MARKER) ?? -1

    return index > 0 ? scope!.slice(0, index) : null
  }

  const leftNamespace = namespace(left)
  const rightNamespace = namespace(right)

  // Legacy unqualified keys remain readable by the low-level store, but are
  // never considered safe migration peers for a qualified tenant scope.
  return Boolean(leftNamespace && rightNamespace && leftNamespace === rightNamespace)
}
