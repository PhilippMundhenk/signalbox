// Segments (VLANs) per site: members per device (tagged / untagged) and subnets.
import { loadNetwork, noData, siteFilter } from '../net.js';
import { by, clear, h, place } from '../util.js';
import { pageHead, purposeTag, table, tag } from '../ui.js';
import { t } from '../i18n.js';

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
    h('h3', {}, seg.vlan ? h('span', { class: 'vlan-id' }, t('segments.vlan', { vlan: seg.vlan })) : h('span', { class: 'vlan-id' }, t('segments.untagged')), seg.name ? ` ${seg.name}` : '', seg.purpose ? [' ', purposeTag(seg)] : null),
    seg.isolated ? h('p', { class: 'muted small', 'data-testid': 'segment-isolated' }, t('segments.isolated')) : null,
    rows.length
      ? table(
          [
            [t('segments.col.device'), ([d]) => h('a', { href: `#/device/${encodeURIComponent(d)}` }, ix.deviceName(d))],
            [t('segments.col.untaggedPorts'), ([, m]) => (m.untagged.length ? m.untagged.sort(by((x) => x)).join(', ') : null)],
            [t('segments.col.taggedPorts'), ([, m]) => (m.tagged.length ? m.tagged.sort(by((x) => x)).join(', ') : null)],
          ],
          rows,
          { rowTestid: 'segment-member' },
        )
      : h('p', { class: 'muted' }, t('segments.noMembers')),
    subnets.length
      ? h(
          'div',
          { class: 'subnets' },
          h('h4', {}, t('segments.subnets')),
          h(
            'ul',
            { class: 'plain' },
            subnets.map((x) => h('li', { 'data-testid': 'subnet' }, h('span', { class: 'mono' }, x.interface), t('segments.subnetOn', { device: ix.deviceName(x.device_id) }), x.gateway ? [' ', tag(t('segments.gateway'), 'ok')] : null)),
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
    pageHead(t('segments.title')),
    h('p', { class: 'muted' }, t('segments.intro')),
    h('div', { class: 'filters' }, siteFilter(ix, siteChoice, (v) => { siteChoice = v; draw(); })),
    body,
  );
  draw();
}
