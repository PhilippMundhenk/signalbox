// Wi-Fi map (#366): one bubble per radio of our access points and one per anonymous neighbour,
// placed by the signal heard between them (wifimaplayout.js). Positions are inferred, not real.
import { get } from '../api.js';
import { select, card } from '../ui.js';
import { attachZoom } from '../topozoom.js';
import { bubbleColor, layoutWifiMap } from '../wifimaplayout.js';
import { by, clear, h, place, s } from '../util.js';
import { t } from '../i18n.js';

const BANDS = ['2.4', '5', '6'];
const state = { band: '', site: '' };
const enc = encodeURIComponent;
const short = (text, max) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);

function drawMap(ix, shown, edges, lay) {
  const svg = s('svg', { class: 'topo wifimap', role: 'img', 'aria-label': t('wifimap.graphLabel'), 'data-testid': 'wifimap-graph' });
  const vp = s('g', { class: 'viewport' });
  place(svg, vp);
  const lines = s('g', { class: 'edges' });
  const bubbles = s('g', { class: 'bubbles' });
  place(vp, lines, bubbles);
  for (const e of edges) {
    const a = lay.nodes[e.a];
    const b = lay.nodes[e.b];
    if (a && b) place(lines, s('line', { x1: String(a.x), y1: String(a.y), x2: String(b.x), y2: String(b.y), class: 'link' }));
  }
  const hot = new Set(lay.overlaps.flat());
  for (const n of shown) {
    const { x, y, r } = lay.nodes[n.id];
    const color = bubbleColor(n.band, n.channel);
    const own = n.kind === 'own';
    const ch = n.channel === null || n.channel === undefined ? t('wifimap.channelUnknown') : n.channel;
    const cls = `bubble ${own ? 'own' : 'neighbour'}${hot.has(n.id) ? ' co' : ''}`;
    const g = s('g', { class: cls, 'data-testid': 'wifimap-bubble', 'data-id': n.id, 'data-kind': n.kind, 'data-band': n.band, 'data-channel': n.channel, 'data-overlap': hot.has(n.id) ? 'true' : null });
    place(g, s('circle', { cx: String(x), cy: String(y), r: String(r), fill: color, 'fill-opacity': '0.4', stroke: color }));
    let text;
    if (own) {
      const name = ix.deviceName(n.device_id);
      const sub = t('wifimap.ownSub', { band: n.band, channel: ch });
      place(g, s('title', {}, `${name} · ${n.radio} · ${sub}`));
      place(g, s('text', { x: String(x), y: String(y - 2), 'text-anchor': 'middle', class: 'name' }, short(name, 14)), s('text', { x: String(x), y: String(y + 13), 'text-anchor': 'middle', class: 'sub' }, sub));
      text = s('a', { href: `#/device/${enc(n.device_id)}`, class: 'name-link', 'data-testid': 'wifimap-device-link', 'aria-label': t('wifimap.ownAria', { device: name, radio: n.radio, band: n.band, channel: ch }) }, g);
    } else {
      const title = t('wifimap.neighbourTitle', { n: n.index, band: n.band || '?', channel: ch, dbm: n.signal_dbm ?? '?' });
      place(g, s('title', {}, title));
      place(g, s('text', { x: String(x), y: String(y - 1), 'text-anchor': 'middle', class: 'sub' }, t('wifimap.neighbour', { n: n.index })), s('text', { x: String(x), y: String(y + 12), 'text-anchor': 'middle', class: 'sub' }, t('wifimap.neighbourSub', { channel: ch })));
      text = g;
    }
    place(bubbles, text);
  }
  svg.zoomable = { width: lay.width, height: lay.height, vp };
  return svg;
}

function legend(shown) {
  const swatch = (kids, w = 40) => s('svg', { class: 'topo key-svg', width: String(w), height: '16', viewBox: `0 0 ${w} 16`, 'aria-hidden': 'true' }, kids);
  const dot = (band, channel, cls = '') => swatch(s('circle', { cx: '20', cy: '8', r: '7', class: cls, fill: bubbleColor(band, channel), 'fill-opacity': '0.4', stroke: bubbleColor(band, channel) }));
  const item = (icon, text) => h('li', {}, icon, h('span', {}, text));
  const group = (title, items) => h('div', { class: 'legend-group' }, h('h4', {}, title), h('ul', {}, items));
  const channels = [...new Map(shown.filter((n) => n.band && n.channel).map((n) => [`${n.band}/${n.channel}`, n])).values()].sort(by((n) => `${n.band}/${String(n.channel).padStart(3, '0')}`));
  return h(
    'details',
    { class: 'topo-legend', open: true, 'data-testid': 'wifimap-legend' },
    h('summary', {}, t('wifimap.legend.title')),
    h(
      'div',
      { class: 'legend-body' },
      group(t('wifimap.legend.bands'), BANDS.map((b) => item(dot(b, 6), t('wireless.ghz', { band: b })))),
      channels.length ? group(t('wifimap.legend.channels'), channels.map((n) => item(dot(n.band, n.channel), t('wifimap.legend.channel', { band: n.band, channel: n.channel })))) : null,
      group(t('wifimap.legend.bubbles'), [
        item(swatch(s('circle', { cx: '20', cy: '8', r: '7', class: 'bubble own key' })), t('wifimap.legend.own')),
        item(swatch(s('circle', { cx: '20', cy: '8', r: '7', class: 'bubble neighbour key' })), t('wifimap.legend.neighbour')),
        item(swatch(s('circle', { cx: '20', cy: '8', r: '7', class: 'bubble co key' })), t('wifimap.legend.overlap')),
      ]),
    ),
  );
}

// The access points per site: the whole content of the page where no scan data exists.
function siteLists(data, ix) {
  const own = data.nodes.filter((n) => n.kind === 'own');
  const sites = [...new Set(own.map((n) => n.site_id))].sort(by((id) => ix.siteName(id)));
  return sites.map((id) => {
    const devices = [...new Set(own.filter((n) => n.site_id === id).map((n) => n.device_id))].sort(by((d) => ix.deviceName(d)));
    return card(
      t('wifimap.siteAps', { site: ix.siteName(id) }),
      h(
        'ul',
        { 'data-testid': 'wifimap-site-aps' },
        devices.map((d) => h('li', {}, h('a', { href: `#/device/${enc(d)}` }, ix.deviceName(d)), ' ', h('span', { class: 'muted small' }, own.filter((n) => n.device_id === d).map((n) => `${t('wireless.ghz', { band: n.band })}${n.channel ? ` · ${n.channel}` : ''}`).join(', ')))),
      ),
    );
  });
}

export async function renderWifiMap(main, ctx, ix) {
  const id = ctx.renderId;
  const data = await get('/wifi-map');
  if (!ctx.alive(id)) return;
  const own = data.nodes.filter((n) => n.kind === 'own');
  if (!own.length) {
    place(main, h('div', { class: 'card empty', 'data-testid': 'wifimap-empty' }, h('p', { class: 'muted' }, t('wifimap.noRadios'))));
    return;
  }
  const sites = [...new Set(own.map((n) => n.site_id))];
  if (state.site && !sites.includes(state.site)) state.site = '';
  const graphBox = h('div', { class: 'topo-wrap' });
  const note = h('p', { class: 'muted small', 'data-testid': 'wifimap-overlaps' });
  let zoom = null;
  const draw = () => {
    const ownShown = own.filter((n) => (!state.band || n.band === state.band) && (!state.site || n.site_id === state.site));
    const keep = new Set(ownShown.map((n) => n.id));
    const linked = new Set(data.edges.filter((e) => keep.has(e.a) || keep.has(e.b)).flatMap((e) => [e.a, e.b]));
    const others = data.nodes.filter((n) => n.kind === 'neighbour' && (!state.band || n.band === state.band) && linked.has(n.id));
    const shown = [...ownShown, ...others];
    const ids = new Set(shown.map((n) => n.id));
    const edges = data.edges.filter((e) => ids.has(e.a) && ids.has(e.b));
    const lay = layoutWifiMap({
      nodes: shown.map((n) => ({ id: n.id, kind: n.kind, band: n.band, channel: n.channel, signal_dbm: n.signal_dbm, group: n.site_id })),
      edges,
    });
    const svg = drawMap(ix, shown, edges, lay);
    place(clear(graphBox), svg);
    zoom = attachZoom(svg, svg.zoomable.vp, svg.zoomable);
    place(clear(note), t('wifimap.overlaps', { n: lay.overlaps.length }));
    place(clear(legendBox), legend(shown));
  };
  const legendBox = h('div', {});
  const bandSelect = select([['', t('wifimap.allBands')], ...BANDS.map((b) => [b, t('wireless.ghz', { band: b })])], state.band, { 'aria-label': t('wifimap.band'), 'data-testid': 'wifimap-band' });
  bandSelect.addEventListener('change', () => {
    state.band = bandSelect.value;
    draw();
  });
  let siteSelect = null;
  if (sites.length > 1) {
    siteSelect = select([['', t('wifimap.allSites')], ...sites.sort(by((x) => ix.siteName(x))).map((x) => [x, ix.siteName(x)])], state.site, { 'aria-label': t('wifimap.site'), 'data-testid': 'wifimap-site' });
    siteSelect.addEventListener('change', () => {
      state.site = siteSelect.value;
      draw();
    });
  }
  // zoom buttons and the large view: the Fullscreen API where it works, else an overlay
  const card_ = h('div', { class: 'card topo-card', 'data-full': 'false', 'data-testid': 'wifimap-card' });
  const button = (label, testid, onclick, extra) => {
    const b = h('button', { class: 'btn small', type: 'button', 'data-testid': testid, 'aria-label': label, title: label, ...extra }, label);
    b.addEventListener('click', onclick);
    return b;
  };
  const fullBtn = button(t('topology.fullscreen'), 'wifimap-full', () => setFull(card_.dataset.full !== 'true'), { 'aria-pressed': 'false' });
  const setFull = async (on) => {
    card_.dataset.full = String(on);
    card_.classList.toggle('full', on);
    fullBtn.setAttribute('aria-pressed', String(on));
    fullBtn.textContent = on ? t('topology.fullscreenExit') : t('topology.fullscreen');
    try {
      if (on && !document.fullscreenElement && card_.requestFullscreen) await card_.requestFullscreen();
      else if (!on && document.fullscreenElement) await document.exitFullscreen();
    } catch {
      // not allowed here: the overlay class already fills the window
    }
    if (zoom) zoom.fit();
  };
  const onFullChange = () => {
    if (!card_.isConnected) return document.removeEventListener('fullscreenchange', onFullChange);
    if (!document.fullscreenElement && card_.dataset.full === 'true' && card_.dataset.api === 'true') setFull(false);
    card_.dataset.api = String(Boolean(document.fullscreenElement));
    return null;
  };
  document.addEventListener('fullscreenchange', onFullChange);
  card_.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape' && card_.dataset.full === 'true' && !document.fullscreenElement) setFull(false);
  });
  const tools = h(
    'div',
    { class: 'topo-tools' },
    button('+', 'wifimap-zoom-in', () => zoom && zoom.by(1.25), { 'aria-label': t('topology.zoomIn'), title: t('topology.zoomIn') }),
    button('−', 'wifimap-zoom-out', () => zoom && zoom.by(0.8), { 'aria-label': t('topology.zoomOut'), title: t('topology.zoomOut') }),
    button(t('topology.zoomReset'), 'wifimap-zoom-reset', () => zoom && zoom.fit()),
    fullBtn,
  );
  place(main, h('p', { class: 'muted', 'data-testid': 'wifimap-intro' }, t('wifimap.intro')));
  if (!data.has_scan) {
    place(main, h('div', { class: 'card', 'data-testid': 'wifimap-noscan' }, h('h2', {}, t('wifimap.noScan.title')), h('p', { class: 'muted' }, t('wifimap.noScan.text'))), ...siteLists(data, ix));
  }
  place(card_, tools, graphBox, h('p', { class: 'muted small', 'data-testid': 'wifimap-inferred' }, t('wifimap.inferred')), note, legendBox);
  place(main, h('div', { class: 'filters' }, bandSelect, siteSelect), card_);
  draw();
}
