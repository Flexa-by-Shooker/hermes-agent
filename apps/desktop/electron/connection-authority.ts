import crypto from 'node:crypto'

import { normalizeRemoteBaseUrl } from './connection-config'

export function buildRemoteAuthorityId(baseUrl: string, serverAuthorityId: string): string {
  if (!serverAuthorityId.trim()) {
    throw new Error('Hermes did not return a verified remote authority.')
  }

  return crypto
    .createHash('sha256')
    .update(['hermes-remote-authority:v2', normalizeRemoteBaseUrl(baseUrl), serverAuthorityId].join('\u0000'))
    .digest('base64url')
}

export function remoteAuthorityMatches(expected: unknown, actual: unknown): boolean {
  return typeof expected === 'string' && Boolean(expected) && expected === actual
}
