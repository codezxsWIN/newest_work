import createGlobe from './vendor/cobe.js';

const markers = [
  { id: 'cdn-iad', location: [38.95, -77.45], region: 'iad1' },
  { id: 'cdn-sfo', location: [37.62, -122.38], region: 'sfo1' },
  { id: 'cdn-cdg', location: [49.01, 2.55], region: 'cdg1' },
  { id: 'cdn-hnd', location: [35.55, 139.78], region: 'hnd1' },
  { id: 'cdn-syd', location: [-33.95, 151.18], region: 'syd1' },
  { id: 'cdn-gru', location: [-23.43, -46.47], region: 'gru1' },
  { id: 'cdn-sin', location: [1.36, 103.99], region: 'sin1' },
  { id: 'cdn-arn', location: [59.65, 17.93], region: 'arn1' },
  { id: 'cdn-dub', location: [53.43, -6.25], region: 'dub1' },
  { id: 'cdn-bom', location: [19.09, 72.87], region: 'bom1' },
];

const arcs = [
  { id: 'cdn-arc-1', from: [38.95, -77.45], to: [49.01, 2.55] },
  { id: 'cdn-arc-2', from: [37.62, -122.38], to: [35.55, 139.78] },
  { id: 'cdn-arc-3', from: [49.01, 2.55], to: [1.36, 103.99] },
  { id: 'cdn-arc-4', from: [38.95, -77.45], to: [-23.43, -46.47] },
  { id: 'cdn-arc-5', from: [35.55, 139.78], to: [-33.95, 151.18] },
  { id: 'cdn-arc-6', from: [49.01, 2.55], to: [19.09, 72.87] },
];

const trafficStartingValues = [420, 380, 290, 185, 156, 134];

function labelNode(className, content) {
  const node = document.createElement('span');
  node.className = className;
  node.textContent = content;
  return node;
}

export function initialiseCobeGlobe() {
  const root = document.querySelector('[data-cobe-globe]');
  const canvas = root?.querySelector('canvas');
  if (!root || !canvas || root.dataset.ready) return;
  root.dataset.ready = 'true';

  const labels = new Map();
  const traffic = new Map();
  for (const marker of markers) {
    const label = labelNode('cobe-marker-label', marker.region);
    label.style.positionAnchor = `--cobe-${marker.id}`;
    label.style.opacity = `var(--cobe-visible-${marker.id}, 0)`;
    root.append(label);
    labels.set(marker.id, label);
  }
  for (const [index, arc] of arcs.entries()) {
    const badge = labelNode('cobe-traffic-label', `${trafficStartingValues[index]}k req/s`);
    badge.style.positionAnchor = `--cobe-arc-${arc.id}`;
    badge.style.opacity = `var(--cobe-visible-arc-${arc.id}, 0)`;
    root.append(badge);
    traffic.set(arc.id, { badge, value: trafficStartingValues[index] });
  }

  let pointerStart = null;
  let phi = 0;
  let theta = 0.2;
  let drag = { phi: 0, theta: 0 };
  let paused = false;
  let animationFrame;
  let globe;

  const resize = () => {
    const width = root.clientWidth;
    if (!width || globe) return;
    globe = createGlobe(canvas, {
      devicePixelRatio: Math.min(window.devicePixelRatio || 1, 2),
      width,
      height: width,
      phi: 0,
      theta: 0.2,
      dark: 1,
      diffuse: 3,
      mapSamples: 16000,
      mapBrightness: 1.8,
      mapBaseBrightness: 0,
      baseColor: [1, 1, 1],
      markerColor: [0.08, 0.08, 0.08],
      glowColor: [1, 1, 1],
      markerElevation: 0.02,
      markers: markers.map(({ id, location }) => ({ id, location, size: 0.012 })),
      arcs: arcs.map(({ id, from, to }) => ({ id, from, to })),
      arcColor: [0.08, 0.08, 0.08],
      arcWidth: 0.5,
      arcHeight: 0.25,
      opacity: 0.85,
    });
    canvas.style.opacity = '1';
    const animate = () => {
      if (!paused) phi += 0.003;
      globe.update({ phi: phi + drag.phi, theta: theta + drag.theta });
      animationFrame = requestAnimationFrame(animate);
    };
    animate();
  };

  const resizeObserver = new ResizeObserver(entries => {
    if (entries[0]?.contentRect.width > 0) {
      resizeObserver.disconnect();
      resize();
    }
  });
  resizeObserver.observe(root);

  canvas.addEventListener('pointerdown', event => {
    pointerStart = { x: event.clientX, y: event.clientY };
    canvas.setPointerCapture(event.pointerId);
    canvas.style.cursor = 'grabbing';
    paused = true;
  });
  canvas.addEventListener('pointermove', event => {
    if (!pointerStart) return;
    drag = { phi: (event.clientX - pointerStart.x) / 300, theta: (event.clientY - pointerStart.y) / 1000 };
  });
  const finishDrag = () => {
    if (!pointerStart) return;
    phi += drag.phi;
    theta += drag.theta;
    drag = { phi: 0, theta: 0 };
    pointerStart = null;
    paused = false;
    canvas.style.cursor = 'grab';
  };
  canvas.addEventListener('pointerup', finishDrag);
  canvas.addEventListener('pointercancel', finishDrag);

  window.setInterval(() => {
    for (const record of traffic.values()) {
      record.value = Math.max(50, record.value + Math.floor(Math.random() * 21) - 10);
      record.badge.textContent = `${record.value}k req/s`;
    }
  }, 250);

  window.addEventListener('pagehide', () => {
    cancelAnimationFrame(animationFrame);
    globe?.destroy();
  }, { once: true });
}
