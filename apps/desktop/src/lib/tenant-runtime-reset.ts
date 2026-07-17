type TenantRuntimeReset = () => void

const resetters = new Set<TenantRuntimeReset>()

/** Register synchronous cleanup for a lazily loaded tenant-owned feature store. */
export function registerTenantRuntimeReset(reset: TenantRuntimeReset): () => void {
  resetters.add(reset)

  return () => resetters.delete(reset)
}

export function runTenantRuntimeResets(): void {
  for (const reset of resetters) {
    reset()
  }
}
