// Eseguire con: node --test tests/test_dashboard_map.js
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync('frontend/dashboard_live.html', 'utf8');
const source = html.slice(html.indexOf('function hasMapCoordinates('), html.indexOf('function renderChart('));
function setup() {
  const layers = [];
  const context = {
    Number, Math, Map, Set, map: null, analysisMap: null,
    mapHasAutoFit: false, analysisMapHasAutoFit: false,
    escapeHtml: s => String(s).replaceAll('<', '&lt;').replaceAll('>', '&gt;'),
    document: {
      querySelector: selector => ({content: selector.includes('hpx-honeypot-location')
        ? '{"lat":45.649,"lon":9.602,"city":"Dalmine (circa)"}'
        : 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'}),
      createElement: () => ({setAttribute() {}}),
      getElementById: () => ({}),
    },
    L: {
      map: () => ({setView() {return this;}, on() {}, createPane: () => ({classList: {add() {}}})}),
      control: () => ({addTo() {this.message = this.onAdd(); context.message = this.message;}}),
      tileLayer: (url, options) => {
        const layer = {url, options, handlers: {}, on(name, fn) {this.handlers[name] = fn;}, addTo() {}};
        layers.push(layer); return layer;
      },
      layerGroup: () => ({addTo() {return this;}}),
      divIcon: options => options,
      marker: (coords, options) => ({coords, options, bindPopup(popup) {this.popup = popup; return this;}}),
    },
  };
  vm.createContext(context); vm.runInContext(source, context);
  return {context, layers};
}
test('entrambe le mappe usano OSM, attribuzione e gestione errori recuperabile', () => {
  const {context: c, layers} = setup();
  c.initMap(); c.initAnalysisMap();
  assert.equal(layers.length, 2);
  for (const layer of layers) {
    assert.equal(layer.url, 'https://tile.openstreetmap.org/{z}/{x}/{y}.png');
    assert.match(layer.options.attribution, /openstreetmap.org\/copyright/);
    assert.equal(layer.options.pane, 'hpxTiles');
  }
  const layer = layers[1];
  layer.handlers.loading(); layer.handlers.tileerror(); layer.handlers.load();
  assert.equal(c.message.hidden, false);
  layer.handlers.loading(); layer.handlers.load();
  assert.equal(c.message.hidden, true);
  c.initMap(); assert.equal(layers.length, 2);
});
test('coordinate reali, aggregazione, LAN su Dalmine e Unknown esclusi', () => {
  const {context: c} = setup();
  const valid = {lat: 45, lon: 9, ip: '1.1.1.1', country: 'IT', attack_type: 'Scan'};
  const points = c.buildMapPoints([valid, {...valid, danger_level: 'Alto'},
    {country: 'Local', lat: null, lon: null}, {country: 'Unknown'},
    {...valid, lat: 91}, {...valid, lon: NaN}, {...valid, lat: '45'}]);
  assert.equal(points.length, 2); assert.equal(points[0].count, 2);
  assert.equal(points[1].lat, 45.649); assert.equal(points[1].lon, 9.602);
  assert.equal(points[1].city, 'Dalmine (circa)'); assert.equal(points[1].is_local, true);
  assert.equal(points[0].danger_level, 'Alto');
});
test('marker e popup aggiornati senza duplicati, payload HTML neutralizzato', () => {
  const {context: c} = setup();
  const markers = [];
  const layer = {clearLayers() {markers.length = 0;}, addLayer(marker) {markers.push(marker);}};
  const map = {setView() {}, fitBounds() {}};
  const point = {lat: 0, lon: 0, attack_type: '<img>', sample_ip: '<script>', count: 1};
  c.renderMapInto(map, layer, [point], true);
  assert.equal(markers.length, 1); assert.match(markers[0].popup, /&lt;img&gt;/);
  assert.match(markers[0].options.icon.html, /background:#58a6ff/);
  assert.doesNotMatch(markers[0].popup, /<script>/);
  c.renderMapInto(map, layer, [point], false); assert.equal(markers.length, 1);
  c.renderMapInto(map, layer, [], false); assert.equal(markers.length, 0);
});
test('Leaflet assente non interrompe la dashboard', () => {
  const {context: c} = setup(); delete c.L;
  assert.doesNotThrow(() => {c.initMap(); c.initAnalysisMap();});
});

test('LAN usa la posizione configurata del PC e gestisce configurazioni non valide', () => {
  const {context: c} = setup();
  c.document.querySelector = () => ({content: '{"lat":40,"lon":10,"city":"Sede honeypot"}'});
  const local = {country: 'Local', lat: 1, lon: 2};
  const point = c.buildMapPoints([local])[0];
  assert.equal(point.lat, 40); assert.equal(point.lon, 10);
  assert.equal(point.city, 'Sede honeypot');
  for (const content of ['bad json', '{"lat":100,"lon":10}', '{"lat":null,"lon":10}', 'null']) {
    c.document.querySelector = () => ({content});
    assert.equal(c.buildMapPoints([local]).length, 0);
    assert.equal(c.buildMapPoints([{lat: 45, lon: 9, country: 'IT'}]).length, 1);
  }
});
