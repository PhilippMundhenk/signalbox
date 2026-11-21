// Thin fetch wrapper. Errors carry the server's code ({"error": ..., "message": ...}).

export class ApiError extends Error {
  constructor(status, body) {
    super(body.message || 'Request failed');
    this.status = status;
    this.code = body.error || 'error';
    this.body = body;
  }
}

const unauthorized = [];
export function onUnauthorized(fn) {
  unauthorized.push(fn);
}

export async function api(method, path, body) {
  let response;
  try {
    response = await fetch(`/api${path}`, {
      method,
      credentials: 'same-origin',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (err) {
    throw new ApiError(0, { error: 'network', message: 'Cannot reach the Signalbox server.' });
  }
  let data = {};
  if (response.status !== 204) {
    try {
      data = await response.json();
    } catch (err) {
      data = {};
    }
  }
  if (!response.ok) {
    const error = new ApiError(response.status, data);
    if (response.status === 401 && error.code === 'login_required') unauthorized.forEach((fn) => fn());
    throw error;
  }
  return data;
}

export const get = (path) => api('GET', path);
export const post = (path, body = {}) => api('POST', path, body);
export const put = (path, body) => api('PUT', path, body);
export const del = (path) => api('DELETE', path);
export const enc = encodeURIComponent;
