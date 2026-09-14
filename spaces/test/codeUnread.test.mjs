// codeUnread.js — which sessions in the Code list have activity you have not seen (the owner, after the running mark:
// "it also needs to show if the user missed an activity"). Measured on opencode 1.18.30: a session's time.updated moves
// with its turns, and NOT with a rename or an archive (PATCH leaves it as it was) — so it is the activity clock.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readSeen, baseline, unreadIds, markSeen, prune, normSeen, mergeSeen, SEEN_ROUTE } from '../public/codeUnread.js'

const ses = (id, updated, extra = {}) => ({ id, time: { created: 1, updated, ...extra } })

test('the stored record: junk and old shapes read as nothing seen yet', () => {
  assert.deepEqual(readSeen(null), { since: 0, at: {} })
  assert.deepEqual(readSeen('not json'), { since: 0, at: {} })
  assert.deepEqual(readSeen('[1,2]'), { since: 0, at: {} })
  assert.deepEqual(readSeen(JSON.stringify({ since: 5, at: { a: 3, b: 'x', c: -1 } })), { since: 5, at: { a: 3 } })
})

test('first sight on this device: nothing already on the list is new — measured by the SERVER\'s clock, never this device\'s', () => {
  const seen = baseline(readSeen(null), [ses('a', 100), ses('b', 250)])
  assert.equal(seen.since, 250)
  assert.equal(unreadIds([ses('a', 100), ses('b', 250)], seen).size, 0)
  const again = baseline(seen, [ses('a', 900)])
  assert.equal(again, seen, 'a device that has a baseline keeps it — the same record, not a new one')
  assert.equal(baseline(readSeen(null), []).since, 0, 'an empty list sets no baseline: the first session to appear is not missed news')
})

test('news: activity past what you saw of the session — or, never opened here, past the baseline', () => {
  const seen = { since: 200, at: { a: 150 } }
  const list = [ses('a', 150), ses('b', 190), ses('c', 300), ses('a2', 400)]
  assert.deepEqual([...unreadIds(list, { ...seen, at: { ...seen.at, a2: 400 } })], ['c'])
  assert.deepEqual([...unreadIds([ses('a', 151)], seen)], ['a'], 'one more step on a session you had opened')
  assert.deepEqual([...unreadIds([ses('n', 201)], seen)], ['n'], 'a session started elsewhere after the baseline')
})

test('never news: the session you have open, one running a turn (its spark says more), an archived one', () => {
  const seen = { since: 100, at: {} }
  const list = [ses('open', 500), ses('run', 500), ses('arch', 500, { archived: 600 }), ses('done', 500)]
  assert.deepEqual([...unreadIds(list, seen, { openSid: 'open', running: new Map([['run', 'busy']]) })], ['done'])
})

test('a subagent\'s session is never news of its own while its conversation is listed — it has no row to clear the dot', () => {
  const seen = { since: 100, at: {} }
  const list = [ses('parent', 90), { ...ses('child', 500), parentID: 'parent' }, { ...ses('orphan', 500), parentID: 'gone' }]
  assert.deepEqual([...unreadIds(list, seen)], ['orphan'], 'a subagent whose conversation is gone is listed as a row, so it can be news')
})

test('you looked: the session\'s activity is recorded, a NEW record — and looking at nothing new changes nothing', () => {
  const seen = { since: 100, at: { a: 150 } }
  const next = markSeen(seen, 'a', 300)
  assert.deepEqual(next, { since: 100, at: { a: 300 } })
  assert.deepEqual(seen, { since: 100, at: { a: 150 } }, 'the old record is untouched')
  assert.equal(markSeen(next, 'a', 300), next)
  assert.equal(markSeen(next, 'a', 200), next, 'an older stamp never moves it back')
  assert.equal(markSeen(next, '', 300), next)
  assert.equal(markSeen(next, 'b', undefined), next)
})

test('prune keeps only sessions the list still has, so the record never grows past it', () => {
  const seen = { since: 1, at: { a: 2, gone: 3 } }
  assert.deepEqual(prune(seen, [ses('a', 2), ses('b', 5)]), { since: 1, at: { a: 2 } })
  assert.equal(prune({ since: 1, at: { a: 2 } }, [ses('a', 2)]).at.a, 2)
})

// The owner: "When I switch devices I get green dots". What you saw was kept per DEVICE, so a session read on the phone
// was news on the laptop. The record is now also kept by the COMPUTER the sessions live on (the connector answers
// SEEN_ROUTE), and every device merges with it — so what any device saw, none shows as new.
test('seen records from two devices merge: the later look at each session wins, the earliest first look stays', () => {
  assert.equal(SEEN_ROUTE, '/witbitz/seen')
  const phone = { since: 5000, at: { ses_a: 9000, ses_b: 7000 } }
  const laptop = { since: 3000, at: { ses_b: 8000, ses_c: 6000 } }
  assert.deepEqual(mergeSeen(phone, laptop), { since: 3000, at: { ses_a: 9000, ses_b: 8000, ses_c: 6000 } })
  assert.deepEqual(mergeSeen(laptop, phone), mergeSeen(phone, laptop), 'the order does not matter')
  assert.deepEqual(mergeSeen({ since: 0, at: {} }, laptop), laptop, 'a device that has not looked yet takes the other\'s')
  assert.equal(mergeSeen(phone, { since: 5000, at: { ses_a: 9000 } }), phone, 'nothing new → the SAME record (nothing to save or send)')
})

test('a record from the wire is checked before it is kept: ids, numbers and size', () => {
  assert.deepEqual(normSeen(null), { since: 0, at: {} })
  assert.deepEqual(normSeen({ since: -1, at: { ses_ok: 5, '../x': 6, ses_neg: -2, ses_str: '7', ['s'.repeat(129)]: 8 } }), { since: 0, at: { ses_ok: 5 } })
  const many = { since: 1, at: Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [`ses_${i}`, i + 1])) }
  const kept = normSeen(many)
  assert.equal(Object.keys(kept.at).length, 5000, 'capped')
  assert.ok(kept.at.ses_5999 && !kept.at.ses_0, 'the most recently seen are the ones kept')
})
