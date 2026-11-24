// Zoom and pan of the topology drawing (#303): wheel, drag, pinch, and calls for the buttons.
// The picture is one group with a transform attribute (no inline styles).
// Fit may enlarge a small drawing up to this factor, so the labels stay readable on a wide canvas.
const MAX_FIT = 1.8;
const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));

export function attachZoom(svg, vp, size) {
  const v = { k: 1, x: 0, y: 0 };
  const apply = () => {
    vp.setAttribute('transform', `translate(${v.x.toFixed(1)} ${v.y.toFixed(1)}) scale(${v.k.toFixed(4)})`);
    svg.setAttribute('data-zoom', v.k.toFixed(2));
  };
  const rect = () => svg.getBoundingClientRect();
  const fit = () => {
    const r = rect();
    if (!r.width || !r.height) {
      Object.assign(v, { k: 1, x: 0, y: 0 });
    } else {
      const m = size.margin ?? 12; // free space round the drawing
      v.k = clamp(Math.min(MAX_FIT, (r.width - 2 * m) / size.width, (r.height - 2 * m) / size.height), 0.1, MAX_FIT);
      v.x = (r.width - size.width * v.k) / 2;
      v.y = size.margin === undefined ? 12 : Math.max(m, (r.height - size.height * v.k) / 2);
    }
    apply();
  };
  const zoomAt = (factor, cx, cy) => {
    const k = clamp(v.k * factor, 0.1, 4);
    const real = k / v.k;
    v.x = cx - (cx - v.x) * real;
    v.y = cy - (cy - v.y) * real;
    v.k = k;
    apply();
  };
  const by = (factor) => {
    const r = rect();
    zoomAt(factor, r.width / 2, r.height / 2);
  };
  svg.addEventListener(
    'wheel',
    (ev) => {
      ev.preventDefault();
      const r = rect();
      zoomAt(Math.exp(-ev.deltaY * 0.0015), ev.clientX - r.left, ev.clientY - r.top);
    },
    { passive: false },
  );
  const pointers = new Map();
  let drag = null;
  let pinch = null;
  svg.addEventListener('pointerdown', (ev) => {
    pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (pointers.size === 2) {
      const [p, q] = [...pointers.values()];
      pinch = { d: Math.hypot(p.x - q.x, p.y - q.y) || 1 };
      drag = null;
    } else if (pointers.size === 1 && !ev.target.closest('.port, a, .badge')) {
      drag = { x: ev.clientX, y: ev.clientY, moved: false };
    }
  });
  svg.addEventListener('pointermove', (ev) => {
    const last = pointers.get(ev.pointerId);
    if (!last) return;
    pointers.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (pinch && pointers.size === 2) {
      const [p, q] = [...pointers.values()];
      const d = Math.hypot(p.x - q.x, p.y - q.y) || 1;
      const r = rect();
      zoomAt(d / pinch.d, (p.x + q.x) / 2 - r.left, (p.y + q.y) / 2 - r.top);
      pinch.d = d;
    } else if (drag) {
      if (!drag.moved && Math.hypot(ev.clientX - drag.x, ev.clientY - drag.y) < 4) return;
      if (!drag.moved) {
        drag.moved = true;
        svg.setPointerCapture(ev.pointerId);
        svg.classList.add('panning');
      }
      v.x += ev.clientX - last.x;
      v.y += ev.clientY - last.y;
      apply();
    }
  });
  const end = (ev) => {
    pointers.delete(ev.pointerId);
    if (pointers.size < 2) pinch = null;
    if (!pointers.size) {
      drag = null;
      svg.classList.remove('panning');
    }
  };
  svg.addEventListener('pointerup', end);
  svg.addEventListener('pointercancel', end);
  fit();
  return { fit, by };
}
