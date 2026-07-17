import { GatewayConnectionSupersededError, sameConnectionIdentity } from '@/lib/desktop-gateway-connection'
import { $gateway, gatewayMatchesConnection } from '@/store/gateway'
import { $tenantRuntimeEpoch } from '@/store/gateway-switch'
import { $activeSessionId, $connection } from '@/store/session'

// Shared client for one-off ("one-shot") LLM requests: a single stateless model
// call that runs OUTSIDE the conversation. It never appends to session history,
// so prompt caching stays intact. Use it for small generative chores (commit
// messages, rename ideas, summaries) where an agent turn would be wrong.
//
// Pair with a registered backend template (agent/oneshot.py PROMPT_TEMPLATES)
// for reusable prompt engineering, or pass raw instructions/input ad hoc.

export interface OneShotRequest {
  /** Registered backend template id (e.g. 'commit_message'). */
  template?: string
  /** Variables for the template. */
  variables?: Record<string, unknown>
  /** Raw system prompt (used when no template is given). */
  instructions?: string
  /** Raw user content (used when no template is given). */
  input?: string
  /** Auxiliary task name for model routing (defaults backend-side). */
  task?: string
  maxTokens?: number
  temperature?: number
  /**
   * Session whose model to inherit. Defaults to the active session so output
   * matches the model the user is coding with; pass null to force the
   * configured auxiliary backend instead.
   */
  sessionId?: string | null
}

/**
 * Send a one-off request to Hermes and return the generated text.
 * Throws when the gateway is offline or the backend reports an error.
 */
export async function requestOneShot(req: OneShotRequest): Promise<string> {
  const gateway = $gateway.get()
  const connection = $connection.get()
  const tenantEpoch = $tenantRuntimeEpoch.get()

  if (!gateway || !connection || !gatewayMatchesConnection(gateway, connection)) {
    throw new GatewayConnectionSupersededError('Hermes cannot verify the gateway for this one-off request.')
  }

  const sessionId = req.sessionId === undefined ? $activeSessionId.get() : req.sessionId

  const result = await gateway.request<{ text?: string }>('llm.oneshot', {
    input: req.input,
    instructions: req.instructions,
    max_tokens: req.maxTokens,
    session_id: sessionId ?? undefined,
    task: req.task,
    temperature: req.temperature,
    template: req.template,
    variables: req.variables
  })

  if (
    $tenantRuntimeEpoch.get() !== tenantEpoch ||
    $gateway.get() !== gateway ||
    !sameConnectionIdentity($connection.get(), connection) ||
    !gatewayMatchesConnection(gateway, connection)
  ) {
    throw new GatewayConnectionSupersededError('Hermes changed profiles before the one-off request completed.')
  }

  return (result?.text ?? '').trim()
}
