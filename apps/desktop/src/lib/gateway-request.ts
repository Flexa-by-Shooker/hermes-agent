export interface GatewayRequestCall {
  <T>(method: string, params?: Record<string, unknown>, timeoutMs?: number, signal?: AbortSignal): Promise<T>
}

export type GatewayRequest = GatewayRequestCall & {
  /** Capture the exact gateway/profile/generation currently behind this
   * requester. The returned function never follows a later active-profile
   * switch, which is required for upload cleanup and other paired mutations. */
  pin?: () => GatewayRequestCall
}

export function pinGatewayRequest(request: GatewayRequest): GatewayRequestCall {
  return request.pin?.() ?? request
}
