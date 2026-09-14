// A local stand-in for relay/relay.mjs with the same observable semantics: a message goes to every OTHER socket on the
// channel, and the channel hears {"t":"peers","n"} on every join and leave; {"t":"relay-ping"} is answered to its sender
// alone (the heartbeat). Used by the codec, connector and page tests; relay/relay.test.mjs proves the real Worker behaves the same.
//   answerPings: false — an older relay, which broadcasts a ping like any message
//   stall() — a dead network path for every socket open now: each stays "open" but nothing reaches it or leaves it
import { WebSocketServer } from 'ws'

const PING = '{"t":"relay-ping"}', PONG = '{"t":"relay-pong"}'

export async function fakeRelay({ answerPings = true } = {}) {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' })
  await new Promise((r) => wss.once('listening', r))
  const channels = new Map()
  let pings = 0
  const announce = (set) => { const m = JSON.stringify({ t: 'peers', n: set.size }); for (const s of set) if (!s.stalled) s.send(m) }
  wss.on('connection', (ws, req) => {
    const ch = (req.url || '').replace(/^\/c\//, '')
    if (!channels.has(ch)) channels.set(ch, new Set())
    const set = channels.get(ch)
    set.add(ws)
    announce(set)
    ws.on('message', (data, isBinary) => {
      if (ws.stalled) return
      if (answerPings && !isBinary && data.toString() === PING) { ws.send(PONG); pings++; return }
      for (const s of set) if (s !== ws && !s.stalled) s.send(isBinary ? data : data.toString())
    })
    ws.on('close', () => { set.delete(ws); announce(set) })
  })
  return {
    url: () => `ws://127.0.0.1:${wss.address().port}`,
    channels,
    pings: () => pings,
    stall: () => { for (const set of channels.values()) for (const s of set) s.stalled = true },
    dropAll: () => { for (const set of channels.values()) for (const s of set) s.terminate() },
    close: () => new Promise((r) => { for (const set of channels.values()) for (const s of set) s.terminate(); wss.close(() => r()) }),
  }
}
