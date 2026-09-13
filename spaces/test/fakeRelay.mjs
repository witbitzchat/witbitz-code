// A local stand-in for relay/relay.mjs with the same observable semantics: a message goes to every OTHER socket on the
// channel, and the channel hears {"t":"peers","n"} on every join and leave. Used by the codec, connector and page tests;
// relay/relay.test.mjs proves the real Worker behaves the same.
import { WebSocketServer } from 'ws'

export async function fakeRelay() {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' })
  await new Promise((r) => wss.once('listening', r))
  const channels = new Map()
  const announce = (set) => { const m = JSON.stringify({ t: 'peers', n: set.size }); for (const s of set) s.send(m) }
  wss.on('connection', (ws, req) => {
    const ch = (req.url || '').replace(/^\/c\//, '')
    if (!channels.has(ch)) channels.set(ch, new Set())
    const set = channels.get(ch)
    set.add(ws)
    announce(set)
    ws.on('message', (data, isBinary) => { for (const s of set) if (s !== ws) s.send(isBinary ? data : data.toString()) })
    ws.on('close', () => { set.delete(ws); announce(set) })
  })
  return {
    url: () => `ws://127.0.0.1:${wss.address().port}`,
    channels,
    dropAll: () => { for (const set of channels.values()) for (const s of set) s.terminate() },
    close: () => new Promise((r) => { for (const set of channels.values()) for (const s of set) s.terminate(); wss.close(() => r()) }),
  }
}
