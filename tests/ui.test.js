import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const ui=fs.readFileSync(new URL('../app/static/app.js', import.meta.url),'utf8');
const html=fs.readFileSync(new URL('../app/static/index.html', import.meta.url),'utf8');
test('all five pages have separate routes and nav entries',()=>{
  for (const path of ['/','/disk','/ports','/proposals','/audit']) assert.ok(path==='/' || ui.includes(`path==='${path}'`));
  for (const label of ['01&nbsp; Overview','02&nbsp; Disk','03&nbsp; Ports','04&nbsp; Proposals','05&nbsp; Audit log']) assert.ok(html.includes(label));
});
test('UI keeps simulated Alexa+ labeling and no icon images',()=>{
  assert.ok((html+ui).includes('SIMULATED ALEXA+ CLIENT'));
  assert.ok(!/<img\b/i.test(html+ui));
});
test('disk UI derives values from measurement endpoints rather than sample values',()=>{
  assert.ok(ui.includes("api('/api/scan')"));
  assert.ok(ui.includes("api('/api/health')"));
  assert.ok(!/412\s*\/\s*476|5\.1 GB|3\.8 GB/.test(ui));
});
test('disk UI can choose, add, and remove persisted scan roots',()=>{
  for (const text of ['Choose folder','Add root','removeRoot','/api/roots/pick','/api/roots']) assert.ok(ui.includes(text));
  assert.ok(ui.includes("method:'DELETE'"));
});
test('approved cleanup exposes explicit restore control backed by the API',()=>{
  assert.ok(ui.includes('Restore quarantined folders'));
  assert.ok(ui.includes("'/api/restore'"));
  assert.ok(ui.includes('Restore from quarantine'));
});
test('disk page can switch the measured C: or D: drive without changing scan roots',()=>{
  assert.ok(ui.includes('Switch measured disk'));
  assert.ok(ui.includes("localStorage.setItem('devdoctor-drive'"));
  assert.ok(ui.includes("volumes.find(x=>x.mount===savedDrive)"));
  assert.ok(ui.includes('driveFree'));
});

