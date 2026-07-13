'use strict';

const scenarios = {
  api: {
    type: 'Agent API purchase',
    title: 'An agent buys a live data feed with a measurable freshness promise.',
    amount: '$240 USDC',
    events: [
      ['00:00.0', 'Promise signed', 'Freshness under 30 seconds'],
      ['00:00.8', 'Funding observed', 'Customer-owned contract'],
      ['00:14.2', 'Delivery committed', 'Response and provenance hashed'],
      ['00:14.4', 'Objective checks', 'Freshness and schema pass'],
      ['00:14.6', 'Settlement relayed', 'Worker claim unlocked'],
    ],
  },
  compute: {
    type: 'Confidential compute job',
    title: 'A model run returns the wrong checkpoint despite a valid completion receipt.',
    amount: '$1,800 USDC',
    events: [
      ['00:00.0', 'Terms committed', 'Checkpoint and proof policy signed'],
      ['00:01.1', 'Funding observed', 'Funds stay outside Edict'],
      ['18:42.0', 'Evidence sealed', 'TEE receipt and output hash'],
      ['18:42.3', 'Dispute opened', 'Bond signed by requester'],
      ['19:08.7', 'Independent decision', 'Three judges, swap checked'],
      ['19:08.9', 'Proof ready', 'Challenge window begins'],
    ],
  },
  market: {
    type: 'Agent marketplace task',
    title: 'A research agent delivers on time, but one required source is missing.',
    amount: '$620 USDC',
    events: [
      ['00:00.0', 'Task protected', 'Criteria embedded by marketplace'],
      ['00:00.5', 'Both parties approve', 'No separate Edict accounts'],
      ['04:31.2', 'Delivery committed', 'Report and source list hashed'],
      ['04:40.1', 'Exception detected', 'Required source absent'],
      ['04:41.6', 'Resolution issued', 'Partial split within agreed outcomes'],
      ['04:41.8', 'Settlement queued', 'No Edict withdrawal key'],
    ],
  },
};

const scenarioButtons = document.querySelectorAll('[data-scenario]');
const eventStream = document.getElementById('event-stream');
let eventTimer;

function renderScenario(key) {
  const scenario = scenarios[key];
  if (!scenario || !eventStream) return;
  clearInterval(eventTimer);
  scenarioButtons.forEach((button) => button.classList.toggle('active', button.dataset.scenario === key));
  document.getElementById('trace-type').textContent = scenario.type;
  document.getElementById('trace-title').textContent = scenario.title;
  document.getElementById('trace-amount').textContent = scenario.amount;
  eventStream.innerHTML = scenario.events.map((event, index) =>
    `<div class="event-row${index === 0 ? ' active' : ''}" data-event-index="${index}">` +
      `<span class="event-time">${event[0]}</span><span class="event-signal"></span>` +
      `<span class="event-name">${event[1]}</span><span class="event-note">${event[2]}</span></div>`).join('');
  let active = 0;
  eventTimer = setInterval(() => {
    const rows = eventStream.querySelectorAll('.event-row');
    rows.forEach((row, index) => {
      row.classList.toggle('active', index === active);
      row.classList.toggle('done', index < active);
    });
    active = (active + 1) % rows.length;
  }, 1300);
}

scenarioButtons.forEach((button) => button.addEventListener('click', () => renderScenario(button.dataset.scenario)));
renderScenario('api');

const menuButton = document.querySelector('.menu-button');
const navLinks = document.querySelector('.nav-links');
function setMenuOpen(open) {
  navLinks?.classList.toggle('open', open);
  menuButton?.setAttribute('aria-expanded', String(open));
  menuButton?.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
}
menuButton?.addEventListener('click', () => {
  setMenuOpen(!navLinks?.classList.contains('open'));
});
navLinks?.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => setMenuOpen(false)));
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') setMenuOpen(false);
});

const canvas = document.getElementById('signal-canvas');
const context = canvas?.getContext('2d');
const hero = canvas?.closest('.hero');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const pointer = { x: .5, y: .5 };

const routes = [
  { y: .28, bend: .05, phase: 0 },
  { y: .37, bend: -.035, phase: .14 },
  { y: .46, bend: .025, phase: .31 },
  { y: .55, bend: -.045, phase: .48 },
  { y: .64, bend: .04, phase: .66 },
  { y: .73, bend: -.025, phase: .82 },
];

const checkpoints = Array.from({ length: 24 }, (_, index) => ({
  x: .5 + ((index * 37) % 47) / 100,
  y: .17 + ((index * 29) % 67) / 100,
  phase: (index * .173) % 1,
  size: index % 5 === 0 ? 2 : 1,
}));

function resizeCanvas() {
  if (!canvas || !context) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.floor(canvas.clientWidth * ratio);
  canvas.height = Math.floor(canvas.clientHeight * ratio);
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
}

function cubicPoint(start, controlA, controlB, end, t) {
  const inverse = 1 - t;
  return {
    x: inverse ** 3 * start.x + 3 * inverse ** 2 * t * controlA.x + 3 * inverse * t ** 2 * controlB.x + t ** 3 * end.x,
    y: inverse ** 3 * start.y + 3 * inverse ** 2 * t * controlA.y + 3 * inverse * t ** 2 * controlB.y + t ** 3 * end.y,
  };
}

function drawSignal(time = 0) {
  if (!canvas || !context || reducedMotion.matches) return;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  context.clearRect(0, 0, width, height);
  const parallaxX = (pointer.x - .5) * 10;
  const parallaxY = (pointer.y - .5) * 8;
  const routeColor = 'rgba(238,241,238,.17)';
  const boundaryColor = 'rgba(238,241,238,.065)';
  const pointColor = 'rgba(238,241,238,.28)';
  const pulseColor = 'rgba(250,251,249,.82)';

  context.save();
  context.translate(parallaxX, parallaxY);
  context.lineWidth = 1;

  for (const fraction of [.58, .7, .82, .94]) {
    const x = width * fraction;
    context.beginPath();
    context.strokeStyle = boundaryColor;
    context.moveTo(x, height * .12);
    context.lineTo(x, height * .88);
    context.stroke();
  }

  routes.forEach((route, index) => {
    const wave = Math.sin(time * .00024 + index * 1.31) * height * .012;
    const start = { x: width * (.43 + index * .012), y: height * route.y + wave };
    const controlA = { x: width * .6, y: start.y + height * route.bend };
    const controlB = { x: width * .76, y: height * .5 - height * route.bend };
    const end = { x: width * 1.01, y: height * (.47 + (index - 2.5) * .014) };

    context.beginPath();
    context.setLineDash([1, 12 + index * 2]);
    context.lineDashOffset = -((time * .018 + index * 19) % 120);
    context.strokeStyle = routeColor;
    context.moveTo(start.x, start.y);
    context.bezierCurveTo(controlA.x, controlA.y, controlB.x, controlB.y, end.x, end.y);
    context.stroke();

    const progress = (time * .000045 + route.phase) % 1;
    const pulse = cubicPoint(start, controlA, controlB, end, progress);
    context.fillStyle = pulseColor;
    context.fillRect(pulse.x - 1.5, pulse.y - 1.5, 3, 3);
  });

  context.setLineDash([]);
  checkpoints.forEach((checkpoint) => {
    const drift = Math.sin(time * .00018 + checkpoint.phase * Math.PI * 2);
    const x = width * checkpoint.x + drift * 5;
    const y = height * checkpoint.y + Math.cos(time * .00014 + checkpoint.phase * 7) * 3;
    context.fillStyle = pointColor;
    context.fillRect(x, y, checkpoint.size, checkpoint.size);
  });
  context.restore();

  requestAnimationFrame(drawSignal);
}

resizeCanvas();
window.addEventListener('resize', resizeCanvas, { passive: true });
hero?.addEventListener('pointermove', (event) => {
  const bounds = hero.getBoundingClientRect();
  pointer.x = (event.clientX - bounds.left) / bounds.width;
  pointer.y = (event.clientY - bounds.top) / bounds.height;
}, { passive: true });
hero?.addEventListener('pointerleave', () => {
  pointer.x = .5;
  pointer.y = .5;
}, { passive: true });
requestAnimationFrame(drawSignal);
