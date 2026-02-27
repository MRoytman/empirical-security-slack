const TOKEN_URL = 'https://empiricalsecurity.fusionauth.io/oauth2/token'
const API_BASE = 'https://app.empiricalsecurity.com/api'
const TOKEN_SCOPE = 'target-entity:0c6d5dcc-8bf0-4cd1-bd65-066ef0422369'

let cachedToken = null
let tokenExpiresAt = 0

async function getAccessToken (clientId, clientSecret) {
  const now = Date.now()
  if (cachedToken && now < tokenExpiresAt - 60_000) {
    return cachedToken
  }

  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString(
    'base64'
  )

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: TOKEN_SCOPE
    })
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Token request failed (${res.status}): ${text}`)
  }

  const data = await res.json()
  cachedToken = data.access_token

  // Parse JWT exp claim for precise expiry, fall back to 1 hour
  try {
    const payload = JSON.parse(
      Buffer.from(cachedToken.split('.')[1], 'base64').toString()
    )
    tokenExpiresAt = payload.exp * 1000
  } catch {
    tokenExpiresAt = now + 3600_000
  }

  return cachedToken
}

async function apiRequest (path, clientId, clientSecret) {
  const token = await getAccessToken(clientId, clientSecret)

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API request failed (${res.status}): ${text}`)
  }

  return res.json()
}

async function getCve (cveId, clientId, clientSecret) {
  return apiRequest(`/cves/${encodeURIComponent(cveId)}`, clientId, clientSecret)
}

async function searchCves (query, clientId, clientSecret) {
  const params = new URLSearchParams({ q: query })
  return apiRequest(`/search?${params}`, clientId, clientSecret)
}

async function getCriticalIndicators (cveId, clientId, clientSecret) {
  return apiRequest(
    `/cves/${encodeURIComponent(cveId)}/critical_indicators`,
    clientId,
    clientSecret
  )
}

module.exports = { getCve, searchCves, getCriticalIndicators }
