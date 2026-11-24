import { t, tServer } from './i18n.js';
// Thin fetch wrapper. Errors carry the server's code ({"error": ..., "message": ...}).

export class ApiError extends Error {
  constructor(status, body) {
    // An answer with a message id is shown in the language of the page (#204); a deploy error names
    // the device first.
    const text = body.message_id ? tServer(`msg.${body.message_id}`, body.params, body.message) : body.message;
    super(text ? (body.device && body.message_id ? `${body.device}: ${text}` : text) : t('api.requestFailed'));
    this.status = status;
    this.code = body.error || 'error';
    this.body = body;
  }
}

const unauthorized = [];
export function onUnauthorized(fn) {
  unauthorized.push(fn);
}

// Reachability: any API call that gets no answer reports "down", any answer reports "up".
const reachability = [];
export function onReachability(fn) {
  reachability.push(fn);
}
let reachable = true;
function setReachable(up) {
  if (up === reachable) return;
  reachable = up;
  reachability.forEach((fn) => fn(up));
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
    setReachable(false);
    throw new ApiError(0, { error: 'network', message: t('api.unreachable') });
  }
  setReachable(true);
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

// Session watch: a cheap GET /api/session on a timer while the tab is visible and when it becomes
// visible again. A 401 from any call (see above) ends the session in place; an unreachable server
// is not a logout: it is reported through onReachability and retried with backoff (2 s, doubling,
// at most 60 s) instead of at the normal period. Logout in one tab is announced to the others.
const PERIOD = 60000;
const MAX_BACKOFF = 60000;
const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('signalbox-session') : null;

export function announceLogout() {
  if (channel) channel.postMessage('logout');
}

export function watchSession({ onEnded, period = PERIOD }) {
  let timer = null;
  let delay = 0;
  let busy = false;
  const schedule = () => {
    clearTimeout(timer);
    timer = null;
    if (document.visibilityState === 'hidden') return; // resumed by visibilitychange
    timer = setTimeout(check, delay || period);
  };
  async function check() {
    if (busy) return;
    busy = true;
    try {
      const session = await get('/session');
      delay = 0;
      if (!session.authenticated) onEnded();
    } catch (err) {
      delay = Math.min(delay ? delay * 2 : 2000, MAX_BACKOFF);
    } finally {
      busy = false;
      schedule();
    }
  }
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') check();
    else schedule();
  });
  if (channel) channel.addEventListener('message', (e) => e.data === 'logout' && onEnded());
  schedule();
  return check;
}
