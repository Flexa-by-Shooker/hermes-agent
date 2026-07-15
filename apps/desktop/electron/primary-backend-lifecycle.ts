export function buildPrimaryBackendArgs(profile: null | string): string[] {
  const exactProfile = String(profile || '').trim() || 'default'

  // Always pass --profile, including exact default. Omitting it lets the CLI's
  // sticky active_profile file silently select a different HERMES_HOME while
  // Desktop publishes a descriptor claiming `profile: "default"`.
  return ['--profile', exactProfile, 'serve', '--host', '127.0.0.1', '--port', '0']
}

export interface PrimaryProfilePromotionDeps {
  teardownPoolProfile: (profile: string) => Promise<void>
  teardownPrimary: () => Promise<void>
  writePreference: () => null | string
}

/** Promote a profile from the secondary pool to the window-owned primary.
 * The pool child must be fully gone before the preference is written and a new
 * primary can spawn, otherwise two backends serve the same HERMES_HOME. */
export async function promoteProfileToPrimary(
  nextPreference: null | string,
  deps: PrimaryProfilePromotionDeps
): Promise<null | string> {
  const exactProfile = String(nextPreference || '').trim() || 'default'

  await deps.teardownPoolProfile(exactProfile)
  const stored = deps.writePreference()
  await deps.teardownPrimary()

  return stored
}
