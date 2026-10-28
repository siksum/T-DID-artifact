// Capture existing ConsoleLogger output only. No new product logging statements.
// Security-stage emissions use a separate stdout prefix and bypass this sink.
const tdidLogKey = Buffer.from(process.env.TDID_LOG_KEY!, 'hex')
const tdidLogRef = (value: string) => createHmac('sha256', tdidLogKey)
  .update('final-thr019\0' + value).digest('hex')
const tdidEnums = new Set(['direct_post', 'direct_post.jwt', 'RequestCreated', 'RequestUriRetrieved',
  'ResponseReceived', 'ResponseVerified', 'Error', 'POST', 'GET', 'jwt_vp_json', 'jwt_vc_json',
  'vp_token', 'code', 'EdDSA', 'ES256', 'ES256K', 'RSA', 'JWT', 'openid4vp'])
const tdidJwtPattern = /[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g
function tdidLogValue(value: any, depth = 0): any {
  if (depth > 30) return { value_ref: tdidLogRef(JSON.stringify(value)), depth_limited: true }
  if (value === null || value === undefined) return null
  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'string') {
    if (tdidEnums.has(value)) return value
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
      try {
        const [head, body] = value.split('.')
        return { value_ref: tdidLogRef(value), unsigned_decoding: {
          header: tdidLogValue(JSON.parse(Buffer.from(head, 'base64url').toString()), depth + 1),
          payload: tdidLogValue(JSON.parse(Buffer.from(body, 'base64url').toString()), depth + 1),
        } }
      } catch { /* commitment still preserves exact equality */ }
    }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      try {
        const url = new URL(value)
        return { value_ref: tdidLogRef(value), url_scheme: url.protocol,
          path_ref: tdidLogRef(url.pathname),
          query: Array.from(url.searchParams, ([key, val]) => ({ key, value: tdidLogValue(val, depth + 1) })) }
      } catch { /* commitment only */ }
    }
    return { value_ref: tdidLogRef(value) }
  }
  if (Array.isArray(value)) {
    if (value.length && value.every(x => Number.isInteger(x) && x >= 0 && x <= 255))
      return { binary_value_ref: tdidLogRef(JSON.stringify(value)), byte_count: value.length }
    return value.map(x => tdidLogValue(x, depth + 1))
  }
  return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, tdidLogValue(val, depth + 1)]))
}
let tdidLogSequence = 0
for (const method of ['log', 'debug', 'info', 'warn', 'error'] as const) {
  const previous = console[method].bind(console)
  console[method] = (...args: any[]) => {
    const first = args[0]
    const match = typeof first === 'string' && /^(TRACE|DEBUG|INFO|WARN|ERROR|FATAL): (.*)$/s.exec(first)
    if (!match) { previous(...args); return }
    const embedded = [...match[2].matchAll(tdidJwtPattern)].map(m => tdidLogValue(m[0]))
    const message = match[2]
      .replace(tdidJwtPattern, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/did:[a-z0-9]+:[A-Za-z0-9:._%-]+(?:#[A-Za-z0-9._-]+)?/g, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, token => '<ref:' + tdidLogRef(token) + '>')
      .replace(/[A-Za-z0-9+/=_-]{64,}/g, token => '<ref:' + tdidLogRef(token) + '>')
    const data = args.slice(1).map(arg => {
      if (typeof arg === 'string') { try { return tdidLogValue(JSON.parse(arg)) } catch { return tdidLogValue(arg) } }
      return tdidLogValue(arg)
    })
    process.stdout.write(`TDID_DEVELOPMENT_LOG=${JSON.stringify({ sequence: ++tdidLogSequence,
      level: match[1], message, data, embedded })}\n`)
  }
}
