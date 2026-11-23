// Segments (VLANs) per site: members per device (tagged / untagged) and subnets.
import { loadNetwork, noData, siteFilter } from '../net.js';
import { by, clear, h, place } from '../util.js';
import { pageHead, purposeTag, table, tag } from '../ui.js';
import { foreignServersCard } from './probes.js';

let siteChoice = '';

function members(ix, seg) {
  const perDevice = new Map();
  for (const m of seg.members) {
    const port = ix.ports.get(m.port_id);
    const dev = port ? port.device_id : m.port_id.split('/')[0];
    if (!perDevice.has(dev)) perDevice.set(dev, { untagged: [], tagged: [] });
    perDevice.get(dev)[m.mode].push(port ? port.name : m.port_id.split('/').pop());
  }
  return [...perDevice.entries()].sort(by(([d]) => ix.deviceName(d)));
}

function segmentCard(ix, seg) {
  const subnets = ix.net.subnets.filter((x) => x.segment_id === seg.id);
  const rows = members(ix, seg);
  return h(
    'section',
    { class: 'card', 'data-testid': 'segment', 'data-id': seg.id },
    h('h3', {}, seg.vlan ? h('span', { class: 'vlan-id' }, `VLAN ${seg.vlan}`) : h('span', { class: 'vlan-id' }, 'Untagged'), seg.name ? ` ${seg.name}` : '', seg.purpose ? [' ', purposeTag(seg)] : null),
    seg.isolated ? h('p', { class: 'muted small', 'data-testid': 'segment-isolated' }, 'Isolated by the device (clients cannot reach the other networks).') : null,
    rows.length
      ? table(
          [
            ['Device', ([d]) => h('a', { href: `#/device/${encodeURIComponent(d)}` }, ix.deviceName(d))],
            ['Untagged ports', ([, m]) => (m.untagged.length ? m.untagged.sort(by((x) => x)).join(', ') : null)],
            ['Tagged ports', ([, m]) => (m.tagged.length ? m.tagged.sort(by((x) => x)).join(', ') : null)],
          ],
          rows,
          { rowTestid: 'segment-member' },
        )
      : h('p', { class: 'muted' }, 'No device reported member ports.'),
    subnets.length
      ? h(
          'div',
          { class: 'subnets' },
          h('h4', {}, 'Subnets'),
          h(
            'ul',
            { class: 'plain' },
            subnets.map((x) => h('li', { 'data-testid': 'subnet' }, h('span', { class: 'mono' }, x.interface), ' on ', ix.deviceName(x.device_id), x.gateway ? [' ', tag('gateway', 'ok')] : null)),
          ),
        )
      : null,
  );
}

export async function renderSegments(main, ctx) {
  const id = ctx.renderId;
  const ix = await loadNetwork();
  if (!ctx.alive(id)) return;
  const body = h('div', {});
  const draw = () => {
    clear(body);
    if (!ix.net.segments.length) {
      place(body, noData('segments'));
      return;
    }
    for (const site of ix.sites) {
      if (siteChoice && site.id !== siteChoice) continue;
      const segs = ix.net.segments.filter((x) => x.site_id === site.id).sort((a, b) => (a.vlan || 0) - (b.vlan || 0));
      if (!segs.length) continue;
      place(body, h('section', { class: 'group', 'data-testid': 'site-segments' }, ix.sites.length > 1 ? h('h2', {}, site.name) : null, h('div', { class: 'grid wide' }, segs.map((x) => segmentCard(ix, x)))));
    }
  };
  place(main, 
    pageHead('Segments'),
    h('p', { class: 'muted' }, 'A segment is one network (VLAN) of a site. The same VLAN on several devices is one segment.'),
    h('div', { class: 'filters' }, siteFilter(ix, siteChoice, (v) => { siteChoice = v; draw(); })),
    body,
    foreignServersCard(ctx),
  );
  draw();
}
