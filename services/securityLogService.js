import crypto from 'crypto'
import { UAParser } from 'ua-parser-js'

const IMPORTANT_ACTION_RULES = [
  { method: 'POST', pattern: /^\/api\/upload(?:\/|$)/, action: 'document_upload' },
  { method: 'POST', pattern: /^\/api\/isms\/generate-final$/, action: 'document_generate' },
  { method: 'POST', pattern: /^\/api\/documents\/generate-section$/, action: 'document_generate' },
  { method: 'POST', pattern: /^\/api\/documents\/assemble\/[^/]+$/, action: 'document_assemble' },
  { method: 'GET', pattern: /^\/api\/documents\/export\/[^/]+$/, action: 'document_export' },
  { method: 'POST', pattern: /^\/api\/risk\/generate$/, action: 'risk_assessment_generate' },
  { method: 'POST', pattern: /^\/api\/risk\/(?:assets|network-profile|software-controls)$/, action: 'risk_assessment_change' },
  { method: 'POST', pattern: /^\/api\/risks$/, action: 'risk_register_change' },
  { method: 'PUT', pattern: /^\/api\/risks\/[^/]+$/, action: 'risk_register_change' },
  { method: 'DELETE', pattern: /^\/api\/risks\/[^/]+$/, action: 'risk_register_change' },
  { method: 'PATCH', pattern: /^\/api\/tasks\/[^/]+$/, action: 'task_change' },
  { method: 'POST', pattern: /^\/api\/tasks$/, action: 'task_change' },
  { method: 'DELETE', pattern: /^\/api\/tasks\/[^/]+$/, action: 'task_change' },
  { method: 'GET', pattern: /^\/api\/security\/logs$/, action: 'admin_logs_access' },
  { method: 'DELETE', pattern: /^\/api\/policies(?:\/|$)/, action: 'admin_policy_delete' },
  { method: 'POST', pattern: /^\/api\/policies(?:\/|$)/, action: 'admin_policy_change' },
  { method: 'PUT', pattern: /^\/api\/policies\/[^/]+$/, action: 'admin_policy_change' }
]

function toDeviceType(type) {
  if (!type) return 'desktop'
  if (['mobile', 'tablet', 'smarttv', 'wearable', 'embedded'].includes(type)) return type
  return 'desktop'
}

function extractClientIp(req) {
  const forwarded = req.headers['x-forwarded-for']
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim()
  }
  const fromSocket = req.socket?.remoteAddress || req.connection?.remoteAddress || ''
  return String(fromSocket || '').trim()
}

function hashIp(ip, salt) {
  if (!ip) return ''
  return crypto.createHash('sha256').update(`${salt}:${ip}`).digest('hex')
}

function parseUserAgent(uaRaw) {
  const parser = new UAParser(uaRaw || '')
  const result = parser.getResult()
  const browser = [result.browser?.name, result.browser?.version].filter(Boolean).join(' ')
  const os = [result.os?.name, result.os?.version].filter(Boolean).join(' ')
  return {
    browser: browser || 'Unknown',
    os: os || 'Unknown',
    deviceType: toDeviceType(result.device?.type),
    raw: uaRaw || ''
  }
}

function inferAction(req) {
  if (req.auditAction) return req.auditAction
  const method = String(req.method || 'GET').toUpperCase()
  const endpoint = req.path || req.originalUrl || ''
  for (const rule of IMPORTANT_ACTION_RULES) {
    if (rule.method === method && rule.pattern.test(endpoint)) return rule.action
  }
  return null
}

function pruneOld(timestamps, maxAgeMs) {
  const now = Date.now()
  return timestamps.filter((ts) => now - ts <= maxAgeMs)
}

export function createSecurityLogService({
  supabase,
  shouldHashIp = true,
  ipHashSalt = 'itc-security-log-salt',
  queueFlushSize = 25,
  queueFlushIntervalMs = 2000
}) {
  const queue = []
  let flushing = false
  const knownDevicesByUser = new Map()
  const failedAuthByUser = new Map()

  async function flushQueue() {
    if (flushing || queue.length === 0) return
    flushing = true
    try {
      const batch = queue.splice(0, queueFlushSize)
      const { error } = await supabase.from('security_logs').insert(batch)
      if (error) {
        const msg = String(error.message || '')
        const isSchemaIssue = msg.includes('security_logs') && (msg.includes('does not exist') || msg.includes('schema cache'))
        if (!isSchemaIssue) {
          // Requeue on transient failures to avoid data loss.
          queue.unshift(...batch)
        }
      }
    } catch {
      // Best-effort logging: no throw to request lifecycle.
    } finally {
      flushing = false
    }
  }

  setInterval(flushQueue, queueFlushIntervalMs).unref()

  function enqueue(entry) {
    queue.push(entry)
    if (queue.length >= queueFlushSize) {
      void flushQueue()
    }
  }

  function enqueueAnomaly({ orgId, userId, endpoint, method, statusCode, ipAddress, ua }) {
    const deviceFingerprint = `${ua.browser}|${ua.os}|${ua.deviceType}`
    const known = knownDevicesByUser.get(userId) || new Set()
    if (known.size > 0 && !known.has(deviceFingerprint)) {
      enqueue({
        org_id: orgId,
        user_id: userId,
        ip_address: ipAddress,
        browser: ua.browser,
        os: ua.os,
        device_type: ua.deviceType,
        user_agent: ua.raw,
        action: 'anomaly_new_device',
        endpoint,
        method,
        status_code: statusCode
      })
    }
    known.add(deviceFingerprint)
    knownDevicesByUser.set(userId, known)
  }

  function recordAuthFailure({ userIdHint, orgId, endpoint, method, statusCode, ipAddress, ua }) {
    const key = String(userIdHint || 'anonymous')
    const maxAgeMs = 15 * 60 * 1000
    const state = failedAuthByUser.get(key) || { timestamps: [], ips: new Set() }
    state.timestamps = pruneOld(state.timestamps, maxAgeMs)
    state.timestamps.push(Date.now())
    state.ips.add(ipAddress)
    failedAuthByUser.set(key, state)

    if (state.timestamps.length >= 5 && state.ips.size >= 2) {
      enqueue({
        org_id: orgId,
        user_id: null,
        ip_address: ipAddress,
        browser: ua.browser,
        os: ua.os,
        device_type: ua.deviceType,
        user_agent: ua.raw,
        action: 'anomaly_multi_ip_auth_failures',
        endpoint,
        method,
        status_code: statusCode
      })
    }
  }

  function middleware(resolveOrgId, resolveUserId) {
    return (req, res, next) => {
      if (!String(req.path || '').startsWith('/api/')) return next()
      if (String(req.path || '').startsWith('/uploads/')) return next()
      const startedAt = Date.now()
      const ua = parseUserAgent(req.headers['user-agent'])
      const rawIp = extractClientIp(req)
      const ipAddress = shouldHashIp ? hashIp(rawIp, ipHashSalt) : rawIp

      res.on('finish', () => {
        const action = inferAction(req)
        const statusCode = Number(res.statusCode || 0)
        const endpoint = req.path || req.originalUrl || ''
        const method = String(req.method || 'GET').toUpperCase()
        const userId = req.authUser?.id || resolveUserId(req) || null
        const orgIdRaw = resolveOrgId(req)
        const orgId = typeof orgIdRaw === 'string' && orgIdRaw.length > 0 ? orgIdRaw : null

        if (!action && req.auditAction !== 'auth_failed') return

        const logEntry = {
          org_id: orgId,
          user_id: req.authUser?.id || null,
          ip_address: ipAddress,
          browser: ua.browser,
          os: ua.os,
          device_type: ua.deviceType,
          user_agent: ua.raw,
          action: action || req.auditAction || 'security_event',
          endpoint,
          method,
          status_code: statusCode
        }
        enqueue(logEntry)

        if (req.auditAction === 'auth_failed') {
          recordAuthFailure({
            userIdHint: userId,
            orgId,
            endpoint,
            method,
            statusCode,
            ipAddress,
            ua
          })
          return
        }

        if (req.authUser?.id && statusCode < 500) {
          enqueueAnomaly({
            orgId,
            userId: req.authUser.id,
            endpoint,
            method,
            statusCode,
            ipAddress,
            ua
          })
        }

        req.requestDurationMs = Date.now() - startedAt
      })
      next()
    }
  }

  return { enqueue, middleware, flushQueue }
}

