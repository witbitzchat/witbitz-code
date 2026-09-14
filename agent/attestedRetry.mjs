// agent/attestedRetry.mjs — the ONE refusal from verify-or-refuse that is worth asking again.
//
// A failed attestation is a VERDICT, not a fault: the turn refuses and the caller stops. That is right for every
// reason but one.
//
// `receipt_verification_window` means the receipt's `iat` fell outside [verified_at, verification_expires_at).
// TrustedRouter re-verifies the model enclave on a 900s cycle (measured 2026-09-10 off a live receipt: the window is
// exactly 900s, and that one was signed 143s in with 757s of headroom), so a call landing in the gap after one
// window lapses and before the next verification completes is handed a receipt whose upstream proof has already
// expired. Transient by construction — TR re-verifies and the next call passes. Both refusals in the /rc proxy's log
// did exactly that: 2 in 146 calls, each immediately followed by a verified one.
//
// It matters because a refusal kills the WHOLE turn. At ~1.4% per call an agentic turn making 20 model calls dies
// about a quarter of the time, losing the work in progress — as a room turn did, showing
// "⚠️ … · 38.4s / API Error: 400 llm_receipt_unverified: receipt_verification_window".
//
// THIS WEAKENS NOTHING. The retry re-runs the FULL verify-or-refuse on a fresh call — new nonce, new request bytes,
// new receipt. The receipt that failed is never accepted and its answer is discarded. If the second receipt is also
// outside its window, we refuse for real. Every other reason stays terminal on the first response: wrong route,
// req/resp hash mismatch, unlisted policy, uncommitted key and the rest all say the answer is not what it claims,
// and asking twice cannot change that. That boundary is the security property — see attestedRetry.test.mjs.
//
// Lives in agent/ (inside the MEASURED enclave payload) on purpose: which refusal may be re-asked is exactly the
// kind of decision that should be covered by the PCR, not configurable beside it. The /rc proxy imports the same
// module so there is one definition, not two that can drift.
export const RETRYABLE = 'receipt_verification_window'

/** Is this thrown error the one transient receipt failure? Everything else — including network and upstream faults,
 *  which have their own handling — is final here. */
export const isRetryableReceiptFailure = (e) => String((e && e.message) || e).includes(RETRYABLE)

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Run `attempt` (which must perform the whole verified call), re-asking ONCE on the transient window refusal.
 *
 *  `onRetry` runs between the two attempts and is where a caller undoes anything the failed attempt already emitted
 *  — on the turn path that means retracting the progressive partial, so the answer is not shown twice. It is awaited
 *  and its failure is not allowed to mask the retry.
 *  `attempt` receives the 1-based attempt number, for callers that must re-establish per-call state. */
export async function withReceiptRetry(attempt, { onRetry = null, sleep = defaultSleep, log = console.log, delayMs = 600 } = {}) {
  try {
    return await attempt(1)
  } catch (e) {
    if (!isRetryableReceiptFailure(e)) throw e
    try { log(`↻ ${RETRYABLE} — the gateway's upstream proof had lapsed; re-verifying once`) } catch { /* logging must never turn a recoverable call into a failure */ }
    await sleep(delayMs) // give the gateway the beat it needs to finish the re-verification the lapsed call kicks off
    if (onRetry) { try { await onRetry() } catch { /* a failed rollback must not swallow the retry */ } }
    return await attempt(2) // fully verified again, or it throws for real
  }
}

/** Wrap a verify-or-refuse `fetch`-alike so the one transient refusal is re-asked once. For call sites with no
 *  progressive output to undo (the brain's side calls, the /rc proxy). */
export function makeAttestedOnce(attestedFetch, opts = {}) {
  return (url, init) => withReceiptRetry(() => attestedFetch(url, init), opts)
}
