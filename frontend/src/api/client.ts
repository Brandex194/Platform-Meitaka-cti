async function request<T>(
  method: string,
  path: string,
  token?: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const json = await res.json()
  if (!res.ok) throw new Error(json?.error?.message ?? `HTTP ${res.status}`)
  return json as T
}

export const apiGet = <T>(path: string, token?: string) =>
  request<T>('GET', path, token)
export const apiPost = <T, B = unknown>(path: string, body: B, token?: string) =>
  request<T>('POST', path, token, body)
export const apiPatch = <T, B = unknown>(path: string, body: B, token?: string) =>
  request<T>('PATCH', path, token, body)
export const apiDelete = (path: string, token?: string) =>
  request<void>('DELETE', path, token)
