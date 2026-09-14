// The retry must be NARROW: exactly one reason, exactly one extra attempt, and never a way to launder a bad verdict.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { makeAttestedOnce, withReceiptRetry, isRetryableReceiptFailure, RETRYABLE } from './attestedRetry.mjs'

const quiet = { sleep: async () => {}, log: () => {}, delayMs: 0 }
const thrower = (errs) => { let i = 0; const calls = []; return { calls, fn: async (url, init) => { calls.push({ url, init }); const e = errs[i++]; if (e) throw new Error(e); return { ok: true, attempt: i } } } }

test('the transient window refusal is re-asked once and the SECOND, fully verified answer is returned', async () => {
  const { calls, fn } = thrower([`llm_receipt_unverified: ${RETRYABLE}`])
  const once = makeAttestedOnce(fn, quiet)
  assert.deepEqual(await once('u', { body: 'b' }), { ok: true, attempt: 2 })
  assert.equal(calls.length, 2, 'exactly one extra attempt')
  assert.deepEqual(calls[0], calls[1], 'the retry re-sends the SAME request — it never relaxes anything')
})

test('a receipt that fails the window TWICE is a real refusal — the retry is not a bypass', async () => {
  const { calls, fn } = thrower([`llm_receipt_unverified: ${RETRYABLE}`, `llm_receipt_unverified: ${RETRYABLE}`])
  await assert.rejects(makeAttestedOnce(fn, quiet)('u', {}), new RegExp(RETRYABLE))
  assert.equal(calls.length, 2, 'never a third attempt — one retry, then the verdict stands')
})

// The whole point: only the reason that a re-ask can legitimately change is retried.
for (const reason of ['receipt_wrong_route', 'receipt_req_hash', 'receipt_resp_hash', 'receipt_policy_unlisted', 'receipt_key_uncommitted', 'receipt_upstream_unverified', 'receipt_nonce_mismatch', 'receipt_stale', 'receipt_not_last']) {
  test(`${reason} stays TERMINAL on the first response`, async () => {
    const { calls, fn } = thrower([`llm_receipt_unverified: ${reason}`])
    await assert.rejects(makeAttestedOnce(fn, quiet)('u', {}), new RegExp(reason))
    assert.equal(calls.length, 1, 'a verdict about WHAT THE ANSWER IS must not be re-asked')
  })
}

test('a verified first answer costs no extra call', async () => {
  const { calls, fn } = thrower([])
  assert.deepEqual(await makeAttestedOnce(fn, quiet)('u', {}), { ok: true, attempt: 1 })
  assert.equal(calls.length, 1)
})

test('a non-receipt failure (network, upstream 5xx) is not silently retried either', async () => {
  const { calls, fn } = thrower(['fetch failed'])
  await assert.rejects(makeAttestedOnce(fn, quiet)('u', {}), /fetch failed/)
  assert.equal(calls.length, 1)
})

test('it waits before re-asking — TR needs a beat to finish re-verifying', async () => {
  const slept = []
  const { fn } = thrower([`llm_receipt_unverified: ${RETRYABLE}`])
  await makeAttestedOnce(fn, { sleep: async (ms) => slept.push(ms), log: () => {}, delayMs: 600 })('u', {})
  assert.deepEqual(slept, [600])
})

test('isRetryableReceiptFailure names ONLY the window reason', () => {
  assert.equal(isRetryableReceiptFailure(new Error(`llm_receipt_unverified: ${RETRYABLE}`)), true)
  assert.equal(isRetryableReceiptFailure(new Error('llm_receipt_unverified: receipt_resp_hash')), false)
  assert.equal(isRetryableReceiptFailure('fetch failed'), false)
})

test('onRetry runs BETWEEN the attempts — that ordering is what stops a double reveal', async () => {
  const order = []
  const attempt = async (n) => { order.push('attempt' + n); if (n === 1) throw new Error(`llm_receipt_unverified: ${RETRYABLE}`); return 'ok' }
  const r = await withReceiptRetry(attempt, { onRetry: () => order.push('retract'), sleep: async () => order.push('sleep'), log: () => {} })
  assert.equal(r, 'ok')
  assert.deepEqual(order, ['attempt1', 'sleep', 'retract', 'attempt2'])
})

test('a failing onRetry does not swallow the retry', async () => {
  let n = 0
  const attempt = async () => { if (++n === 1) throw new Error(`llm_receipt_unverified: ${RETRYABLE}`); return 'ok' }
  assert.equal(await withReceiptRetry(attempt, { onRetry: () => { throw new Error('sink is gone') }, sleep: async () => {}, log: () => {} }), 'ok')
})

test('onRetry never runs when the first attempt succeeds, or when the verdict is final', async () => {
  let retracted = 0
  await withReceiptRetry(async () => 'ok', { onRetry: () => retracted++, sleep: async () => {}, log: () => {} })
  await assert.rejects(withReceiptRetry(async () => { throw new Error('llm_receipt_unverified: receipt_req_hash') }, { onRetry: () => retracted++, sleep: async () => {}, log: () => {} }))
  assert.equal(retracted, 0, 'nothing was streamed twice, so nothing may be retracted')
})
