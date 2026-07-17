import { atom } from 'nanostores'

import { triggerHaptic } from '@/lib/haptics'

export interface ComposerAttachment {
  id: string
  kind: 'image' | 'file' | 'folder' | 'terminal' | 'url'
  label: string
  detail?: string
  refText?: string
  previewUrl?: string
  path?: string
  attachedSessionId?: string
  /** Opaque gateway-side handle used to detach governed uploads. */
  attachmentId?: string
  /** Stable idempotency key for this logical file/image. Generated once when
   * the chip is created and reused by eager upload, submit-time joins, retries,
   * and draft restores. Never regenerate it merely because an RPC failed. */
  uploadNonce?: string
  /** Set while the file/image bytes are being staged into the session
   * workspace (remote upload or local stage), and 'error' if that failed.
   * Drives the spinner / error state on the composer attachment card. */
  uploadState?: 'uploading' | 'error'
}

const UPLOAD_NONCE_RE = /^[0-9a-f]{32}$/

export function createAttachmentUploadNonce(): string {
  const bytes = new Uint8Array(16)

  globalThis.crypto.getRandomValues(bytes)

  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}

export function withAttachmentUploadNonce(attachment: ComposerAttachment): ComposerAttachment {
  if (attachment.kind !== 'image' && attachment.kind !== 'file') {
    return attachment
  }

  if (attachment.uploadNonce && UPLOAD_NONCE_RE.test(attachment.uploadNonce)) {
    return attachment
  }

  return { ...attachment, uploadNonce: createAttachmentUploadNonce() }
}

export const $composerDraft = atom('')
export const $composerAttachments = atom<ComposerAttachment[]>([])
export const $composerTerminalSelections = atom<Record<string, Record<string, string>>>({})

// Per-thread draft stash for the decoupled composer. Session lifecycle never
// touches this — only ChatBar's scope swap reads/writes it. Text mirrors to
// localStorage; attachments are memory-only (blobs, upload state).
export const SESSION_DRAFTS_STORAGE_KEY = 'hermes:composer-drafts:v4'

const NEW_SESSION_DRAFT_KEY = '__new__'
const MAX_PERSISTED_DRAFTS = 50
const EMPTY_SESSION_DRAFT: SessionDraft = { attachments: [], text: '' }

export interface SessionDraft {
  attachments: ComposerAttachment[]
  text: string
}

const draftKey = (scope: string | null | undefined) => scope?.trim() || NEW_SESSION_DRAFT_KEY

const cloneDraft = (draft: SessionDraft): SessionDraft => ({
  attachments: draft.attachments.map(attachment => ({ ...attachment })),
  text: draft.text
})

function loadPersistedDraftTexts(): [string, SessionDraft][] {
  try {
    const raw = window.localStorage.getItem(SESSION_DRAFTS_STORAGE_KEY)

    if (!raw) {
      return []
    }

    return Object.entries(JSON.parse(raw) as Record<string, string>).map(([key, text]) => [
      key,
      { attachments: [], text }
    ])
  } catch {
    return []
  }
}

const draftsBySession = new Map<string, SessionDraft>(loadPersistedDraftTexts())

function persistDraftTexts() {
  try {
    const entries = [...draftsBySession]
      .filter(([, draft]) => draft.text)
      .slice(-MAX_PERSISTED_DRAFTS)
      .map(([key, draft]) => [key, draft.text] as const)

    if (entries.length === 0) {
      window.localStorage.removeItem(SESSION_DRAFTS_STORAGE_KEY)
    } else {
      window.localStorage.setItem(SESSION_DRAFTS_STORAGE_KEY, JSON.stringify(Object.fromEntries(entries)))
    }
  } catch {
    // Best-effort only — quota/private-mode must never break typing.
  }
}

export function stashSessionDraft(scope: string | null | undefined, text: string, attachments: ComposerAttachment[]) {
  const key = draftKey(scope)

  // Delete-then-set keeps MRU order for MAX_PERSISTED_DRAFTS eviction.
  draftsBySession.delete(key)

  if (text.trim() || attachments.length > 0) {
    draftsBySession.set(key, cloneDraft({ attachments, text }))
  }

  reconcileComposerTerminalSelections(scope, text)
  persistDraftTexts()
}

export function takeSessionDraft(scope: string | null | undefined): SessionDraft {
  const stashed = draftsBySession.get(draftKey(scope))

  return stashed ? cloneDraft(stashed) : EMPTY_SESSION_DRAFT
}

export const clearSessionDraft = (scope: string | null | undefined) => stashSessionDraft(scope, '', [])

export function setComposerDraft(value: string) {
  $composerDraft.set(value)
}

export function appendComposerDraft(value: string) {
  const text = value.trim()

  if (!text) {
    return
  }

  const current = $composerDraft.get()
  const separator = current && !current.endsWith('\n') ? '\n\n' : ''

  $composerDraft.set(`${current}${separator}${text}`)
}

export function appendComposerInline(value: string) {
  const text = value.trim()

  if (!text) {
    return
  }

  const current = $composerDraft.get().trimEnd()
  const separator = current ? ' ' : ''

  $composerDraft.set(`${current}${separator}${text}`)
}

export function clearComposerDraft() {
  $composerDraft.set('')
}

export function addComposerAttachment(attachment: ComposerAttachment) {
  const normalized = withAttachmentUploadNonce(attachment)
  const previous = $composerAttachments.get()
  const existing = previous.find(item => item.id === normalized.id)
  // Async preview enrichment (image path -> data URL) must keep the nonce the
  // original chip received. A caller may reconstruct the same logical
  // attachment without copying it, so preserve the existing key centrally.
  const nextAttachment =
    existing?.uploadNonce && (normalized.kind === 'image' || normalized.kind === 'file')
      ? { ...normalized, uploadNonce: existing.uploadNonce }
      : normalized
  const next = upsertAttachment(previous, nextAttachment)
  $composerAttachments.set(next)

  if (next.length > previous.length && nextAttachment.kind !== 'url') {
    triggerHaptic('selection')
  }
}

export function removeComposerAttachment(id: string): ComposerAttachment | null {
  const current = $composerAttachments.get()
  const removed = current.find(attachment => attachment.id === id) || null
  $composerAttachments.set(current.filter(attachment => attachment.id !== id))

  return removed
}

/** Replace an existing attachment in place by id. No-op (returns false) when the
 * id is gone — e.g. the user removed the chip while an eager upload was still in
 * flight, so a late success must NOT resurrect it. Use this instead of
 * addComposerAttachment for async results that may land after a removal. */
export function updateComposerAttachment(attachment: ComposerAttachment): boolean {
  const current = $composerAttachments.get()
  const index = current.findIndex(item => item.id === attachment.id)

  if (index < 0) {
    return false
  }

  const next = [...current]
  next[index] = attachment
  $composerAttachments.set(next)

  return true
}

export function clearComposerAttachments() {
  $composerAttachments.set([])
}

/** Update only the upload state of an existing attachment (no-op if it's gone,
 * e.g. the user removed it mid-upload). Pass `undefined` to clear it. */
export function setComposerAttachmentUploadState(id: string, uploadState?: ComposerAttachment['uploadState']) {
  const current = $composerAttachments.get()
  const index = current.findIndex(attachment => attachment.id === id)

  if (index < 0) {
    return
  }

  const next = [...current]
  next[index] = { ...next[index]!, uploadState }
  $composerAttachments.set(next)
}

const TERMINAL_REF_RE = /@terminal:(`[^`\n]+`|"[^"\n]+"|'[^'\n]+'|\S+)/g

function unquoteRefValue(raw: string) {
  const head = raw[0]
  const tail = raw[raw.length - 1]
  const quoted = (head === '`' && tail === '`') || (head === '"' && tail === '"') || (head === "'" && tail === "'")

  return (quoted ? raw.slice(1, -1) : raw).replace(/[,.;!?]+$/, '').trim()
}

function terminalLabelsFromDraft(draft: string) {
  const labels: string[] = []
  const seen = new Set<string>()

  for (const match of draft.matchAll(TERMINAL_REF_RE)) {
    const label = unquoteRefValue(match[1] || '')

    if (!label || seen.has(label)) {
      continue
    }

    seen.add(label)
    labels.push(label)
  }

  return labels
}

export function setComposerTerminalSelection(scope: string | null | undefined, label: string, text: string) {
  const scopeKey = scope?.trim()
  const nextLabel = label.trim()
  const nextText = text.trim()

  if (!scopeKey || !nextLabel || !nextText) {
    return
  }

  const current = $composerTerminalSelections.get()
  const scoped = current[scopeKey] ?? {}

  if (scoped[nextLabel] === nextText) {
    return
  }

  $composerTerminalSelections.set({
    ...current,
    [scopeKey]: { ...scoped, [nextLabel]: nextText }
  })
}

export function reconcileComposerTerminalSelections(scope: string | null | undefined, draft: string) {
  const scopeKey = scope?.trim()

  if (!scopeKey) {
    return
  }

  const current = $composerTerminalSelections.get()
  const scoped = current[scopeKey] ?? {}
  const labels = new Set(terminalLabelsFromDraft(draft))
  let changed = false
  const next: Record<string, string> = {}

  for (const [label, text] of Object.entries(scoped)) {
    if (!labels.has(label)) {
      changed = true

      continue
    }

    next[label] = text
  }

  if (changed) {
    const all = { ...current }

    if (Object.keys(next).length === 0) {
      delete all[scopeKey]
    } else {
      all[scopeKey] = next
    }

    $composerTerminalSelections.set(all)
  }
}

export function terminalContextBlocksFromDraft(scope: string | null | undefined, draft: string) {
  const labels = terminalLabelsFromDraft(draft)

  if (labels.length === 0) {
    return []
  }

  const selections = scope ? ($composerTerminalSelections.get()[scope] ?? {}) : {}

  return labels.flatMap(label => {
    const text = selections[label]?.trim()

    if (!text) {
      return []
    }

    return `\`\`\`terminal\n${text}\n\`\`\``
  })
}

export function clearComposerTerminalSelections(scope: string | null | undefined) {
  const scopeKey = scope?.trim()
  const current = $composerTerminalSelections.get()

  if (!scopeKey || !current[scopeKey]) {
    return
  }

  const next = { ...current }
  delete next[scopeKey]
  $composerTerminalSelections.set(next)
}

function upsertAttachment(attachments: ComposerAttachment[], attachment: ComposerAttachment) {
  const index = attachments.findIndex(item => item.id === attachment.id)

  if (index < 0) {
    return [...attachments, attachment]
  }

  const next = [...attachments]
  next[index] = attachment

  return next
}
