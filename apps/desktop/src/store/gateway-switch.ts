import { atom } from 'nanostores'

import { requestComposerTenantReset } from '@/app/chat/composer/focus'
import { clearAgentTerminalRuntime } from '@/app/right-sidebar/terminal/agent-terminal-stream'
import { composerSessionScope } from '@/lib/composer-scope'
import { queryClient } from '@/lib/query-client'
import { runTenantRuntimeResets } from '@/lib/tenant-runtime-reset'
import { clearDesktopActionTasks } from '@/store/activity'
import { clearClarifyRequest } from '@/store/clarify'
import { clearAllCompactionState } from '@/store/compaction'
import { clearComposerAttachments, clearComposerTerminalSelections } from '@/store/composer'
import { $perSessionBrowse } from '@/store/composer-input-history'
import { clearAllBackgroundProcesses } from '@/store/composer-status'
import { resetSessionsLimit } from '@/store/layout'
import { clearNativeNotificationTenantState } from '@/store/native-notifications'
import { clearNotifications } from '@/store/notifications'
import { clearPreviewRuntimeState } from '@/store/preview'
import { clearPreviewEditState } from '@/store/preview-edit'
import { clearAllPreviewArtifacts } from '@/store/preview-status'
import { clearAllPrompts } from '@/store/prompts'
import {
  $activeSessionId,
  $connection,
  $currentBranch,
  $currentCwd,
  $selectedStoredSessionId,
  setActiveSessionId,
  setAttentionSessionIds,
  setCronSessions,
  setFreshDraftReady,
  setMessages,
  setMessagingPlatformTotals,
  setMessagingSessions,
  setMessagingTruncated,
  setSelectedStoredSessionId,
  setSessionProfileTotals,
  setSessions,
  setSessionsLoading,
  setSessionsTotal,
  setWorkingSessionIds
} from '@/store/session'
import { $subagentsBySession } from '@/store/subagents'
import { clearAllSessionTodos } from '@/store/todos'
import { clearToolDiffs } from '@/store/tool-diffs'

// True while a soft gateway-mode apply is mid-flight (wipe → re-dial). Lets the
// boot hook suppress the backend-exit toast and keeps the cold-boot CONNECTING
// overlay from resurrecting when startHermes re-emits boot progress.
export const $gatewaySwitching = atom(false)
export const $tenantRuntimeEpoch = atom(0)

const PREVIEW_HOLD_MS = 1400

/**
 * Clear gateway-bound session UI so sidebar skeletons retrigger.
 *
 * Sessions live in nanostores (not React Query) — refreshSessions merges into
 * the existing list, so without an explicit wipe a soft switch would keep
 * painting the previous gateway's rows. RQ caches (settings/config/skills) are
 * invalidated separately; the live session list is this path.
 *
 * Does NOT call requestFreshSession() — that navigates to NEW_CHAT and would
 * close route overlays (Settings). Clear chat state in place; leave the URL
 * alone so the user stays where they were (e.g. mid-Gateway settings).
 */
export function wipeSessionListsForGatewaySwitch(): void {
  const composerScope = composerSessionScope(
    $connection.get(),
    $selectedStoredSessionId.get() || $activeSessionId.get()
  )

  requestComposerTenantReset()
  clearAgentTerminalRuntime()
  clearComposerAttachments()
  clearComposerTerminalSelections(composerScope)
  $tenantRuntimeEpoch.set($tenantRuntimeEpoch.get() + 1)
  clearClarifyRequest()
  clearAllPrompts()
  clearNotifications()
  clearNativeNotificationTenantState()
  $perSessionBrowse.set({})
  clearAllBackgroundProcesses()
  clearAllCompactionState()
  $subagentsBySession.set({})
  clearAllSessionTodos()
  clearAllPreviewArtifacts()
  clearPreviewRuntimeState()
  clearPreviewEditState()
  clearToolDiffs()
  clearDesktopActionTasks()
  runTenantRuntimeResets()
  setSessions([])
  setSessionsTotal(0)
  setSessionProfileTotals({})
  setCronSessions([])
  setMessagingSessions([])
  setMessagingPlatformTotals({})
  setMessagingTruncated(false)
  setWorkingSessionIds([])
  setAttentionSessionIds([])
  setSessionsLoading(true)
  resetSessionsLimit()

  // These paths belong to the old backend. Clear the live atoms without using
  // the persistence setters (which would overwrite that backend's remembered
  // workspace while the descriptor still points at it).
  $currentCwd.set('')
  $currentBranch.set('')

  setActiveSessionId(null)
  setSelectedStoredSessionId(null)
  setMessages([])
  setFreshDraftReady(true)

  queryClient.clear()
}

/**
 * Dev review beat: wipe → skeletons for PREVIEW_HOLD_MS → clear loading.
 * Does not tear down a real backend. Fired from the Settings button (Electron
 * has no easy `?query=` entry).
 */
export async function previewGatewaySwitch(holdMs = PREVIEW_HOLD_MS): Promise<void> {
  if ($gatewaySwitching.get()) {
    return
  }

  $gatewaySwitching.set(true)
  wipeSessionListsForGatewaySwitch()

  try {
    await new Promise<void>(resolve => {
      window.setTimeout(resolve, holdMs)
    })
  } finally {
    setSessionsLoading(false)
    $gatewaySwitching.set(false)
  }
}
