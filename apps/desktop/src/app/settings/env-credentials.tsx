import { useStore } from '@nanostores/react'
import { useEffect, useLayoutEffect, useState } from 'react'

import { deleteEnvVar, getEnvVars, revealEnvVar, setEnvVar } from '@/hermes'
import { useI18n } from '@/i18n'
import { type IconComponent } from '@/lib/icons'
import { $gatewaySwitching, $tenantRuntimeEpoch } from '@/store/gateway-switch'
import { notify, notifyError } from '@/store/notifications'
import type { EnvVarInfo } from '@/types/hermes'

import { asText, includesQuery, redactedValue, withoutKey } from './helpers'
import { Pill } from './primitives'
import type { EnvRowProps } from './types'

// Shared filter used by every credential surface (Providers + Keys pages):
// category gate first, then a free-text match across key name + description.
export function filterEnv(info: EnvVarInfo, key: string, q: string, cat: string, extra?: string): boolean {
  if (asText(info.category) !== cat) {
    return false
  }

  if (!q) {
    return true
  }

  return (
    key.toLowerCase().includes(q) ||
    includesQuery(info.description, q) ||
    Boolean(extra && extra.toLowerCase().includes(q))
  )
}

export function SettingsCategoryHeading({ count, icon: Icon, title }: CategoryHeadingProps) {
  return (
    <div className="mb-3 flex items-center gap-2 text-[length:var(--conversation-text-font-size)] font-medium">
      <Icon className="size-4 text-muted-foreground" />
      <span>{title}</span>
      {count && <Pill>{count}</Pill>}
    </div>
  )
}

// Owns the env-var fetch + the edit/reveal/save/delete lifecycle so multiple
// credential pages (Providers, Keys) share one source of truth and one set of
// mutation handlers instead of duplicating the plumbing.
export function useEnvCredentials(): UseEnvCredentials {
  const { t } = useI18n()
  const credentials = t.settings.credentials
  const toolsets = t.settings.toolsets
  const gatewaySwitching = useStore($gatewaySwitching)
  const tenantEpoch = useStore($tenantRuntimeEpoch)
  const [stateTenantEpoch, setStateTenantEpoch] = useState(tenantEpoch)
  const [vars, setVars] = useState<Record<string, EnvVarInfo> | null>(null)
  const [edits, setEdits] = useState<Record<string, string>>({})
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<string | null>(null)

  // Best-effort cleanup of a retired localStorage flag (global "Show
  // advanced" toggle) — everything in these views is configuration-level.
  useEffect(() => {
    try {
      window.localStorage.removeItem('desktop.settings.keys.show_advanced')
    } catch {
      // Ignore — old key cleanup is best-effort.
    }
  }, [])

  // Credentials include plaintext revealed values. Hide the retiring tenant's
  // state during render and clear it before the browser paints the new epoch.
  useLayoutEffect(() => {
    setStateTenantEpoch(tenantEpoch)
    setVars(null)
    setEdits({})
    setRevealed({})
    setSaving(null)
  }, [tenantEpoch])

  useEffect(() => {
    let cancelled = false
    const loadTenantEpoch = tenantEpoch

    if (gatewaySwitching) {
      setVars(null)
      setEdits({})
      setRevealed({})
      setSaving(null)

      return () => void (cancelled = true)
    }
    void (async () => {
      try {
        const next = await getEnvVars()

        if (!cancelled && tenantIsCurrent(loadTenantEpoch)) {
          setVars(next)
        }
      } catch (err) {
        if (!cancelled && tenantIsCurrent(loadTenantEpoch)) {
          notifyError(err, t.settings.keys.failedLoad)
        }
      }
    })()

    return () => void (cancelled = true)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- copy is stable
  }, [gatewaySwitching, tenantEpoch])

  function patchVar(key: string, patch: Partial<Pick<EnvVarInfo, 'is_set' | 'redacted_value'>>) {
    setVars(c => (c ? { ...c, [key]: { ...c[key], ...patch } } : c))
  }

  function clearLocalState(key: string) {
    setEdits(c => withoutKey(c, key))
    setRevealed(c => withoutKey(c, key))
  }

  async function handleSave(key: string) {
    const value = edits[key]
    const actionTenantEpoch = tenantEpoch

    if (!value || !tenantIsCurrent(actionTenantEpoch)) {
      return
    }

    setSaving(key)

    try {
      await setEnvVar(key, value)

      if (!tenantIsCurrent(actionTenantEpoch)) {
        return
      }

      patchVar(key, { is_set: true, redacted_value: redactedValue(value) })
      clearLocalState(key)
      notify({ kind: 'success', title: toolsets.savedTitle, message: toolsets.savedMessage(key) })
    } catch (err) {
      if (tenantIsCurrent(actionTenantEpoch)) {
        notifyError(err, toolsets.failedSave(key))
      }
    } finally {
      if (tenantIsCurrent(actionTenantEpoch)) {
        setSaving(null)
      }
    }
  }

  // Direct save for a known value (no edit-state round-trip) — used by the
  // onboarding-style key form, which owns its own input. Returns a result so
  // the form can surface inline errors instead of only toasting.
  async function saveValue(key: string, value: string): Promise<{ message?: string; ok: boolean }> {
    const trimmed = value.trim()
    const actionTenantEpoch = tenantEpoch

    if (!trimmed || !tenantIsCurrent(actionTenantEpoch)) {
      return { message: credentials.enterValueFirst, ok: false }
    }

    setSaving(key)

    try {
      await setEnvVar(key, trimmed)

      if (!tenantIsCurrent(actionTenantEpoch)) {
        return { ok: false }
      }

      patchVar(key, { is_set: true, redacted_value: redactedValue(trimmed) })
      clearLocalState(key)
      notify({ kind: 'success', message: toolsets.savedMessage(key), title: toolsets.savedTitle })

      return { ok: true }
    } catch (err) {
      if (!tenantIsCurrent(actionTenantEpoch)) {
        return { ok: false }
      }

      notifyError(err, toolsets.failedSave(key))

      return { message: err instanceof Error ? err.message : credentials.couldNotSave, ok: false }
    } finally {
      if (tenantIsCurrent(actionTenantEpoch)) {
        setSaving(null)
      }
    }
  }

  async function handleClear(key: string) {
    const actionTenantEpoch = tenantEpoch

    if (!tenantIsCurrent(actionTenantEpoch) || !window.confirm(toolsets.removeConfirm(key))) {
      return
    }

    setSaving(key)

    try {
      await deleteEnvVar(key)

      if (!tenantIsCurrent(actionTenantEpoch)) {
        return
      }

      patchVar(key, { is_set: false, redacted_value: null })
      clearLocalState(key)
      notify({ kind: 'success', title: toolsets.removedTitle, message: toolsets.removedMessage(key) })
    } catch (err) {
      if (tenantIsCurrent(actionTenantEpoch)) {
        notifyError(err, toolsets.failedRemove(key))
      }
    } finally {
      if (tenantIsCurrent(actionTenantEpoch)) {
        setSaving(null)
      }
    }
  }

  async function handleReveal(key: string) {
    const actionTenantEpoch = tenantEpoch

    if (!tenantIsCurrent(actionTenantEpoch)) {
      return
    }

    if (revealed[key]) {
      setRevealed(c => withoutKey(c, key))

      return
    }

    try {
      const result = await revealEnvVar(key)

      if (tenantIsCurrent(actionTenantEpoch)) {
        setRevealed(c => ({ ...c, [key]: result.value }))
      }
    } catch (err) {
      if (tenantIsCurrent(actionTenantEpoch)) {
        notifyError(err, toolsets.failedReveal(key))
      }
    }
  }

  const stateIsCurrent = !gatewaySwitching && stateTenantEpoch === tenantEpoch

  return {
    saveValue,
    vars: stateIsCurrent ? vars : null,
    rowProps: {
      edits: stateIsCurrent ? edits : {},
      revealed: stateIsCurrent ? revealed : {},
      saving: stateIsCurrent ? saving : null,
      setEdits: stateIsCurrent ? setEdits : () => undefined,
      onSave: handleSave,
      onClear: handleClear,
      onReveal: handleReveal
    }
  }
}

function tenantIsCurrent(tenantEpoch: number): boolean {
  return $tenantRuntimeEpoch.get() === tenantEpoch && !$gatewaySwitching.get()
}

interface CategoryHeadingProps {
  count?: string
  icon: IconComponent
  title: string
}

interface UseEnvCredentials {
  rowProps: Omit<EnvRowProps, 'varKey' | 'info'>
  saveValue: (key: string, value: string) => Promise<{ message?: string; ok: boolean }>
  vars: Record<string, EnvVarInfo> | null
}
