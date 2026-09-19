// Isolated exemption rendering checks; no browser or runtime database access.
// Optional candidate paths let the preserved live overlay remain untouched.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const htmlPath = process.argv[2] || path.join(__dirname, '../dashboard/dashboard.html');
const collectorPath = process.argv[3] || path.join(__dirname, '../scripts/collect.ps1');
const html = fs.readFileSync(htmlPath, 'utf8');
const collector = fs.readFileSync(collectorPath, 'utf8');
const marker = html.match(/\/\/ BEGIN EXEMPTION DISPLAY\r?\n([\s\S]*?)\/\/ END EXEMPTION DISPLAY/);
assert.ok(marker, 'The published page must include its independent exemption panel');
const script = marker[1];
const now = 2_000_000_000;
class Clock extends Date { static now() { return now * 1000; } }
function render(snapshot) {
  const elements = {};
  vm.runInNewContext(script, {
    window: {SENTINEL_EXEMPTIONS: snapshot}, Date: Clock,
    document: {getElementById(id) { return elements[id] ||= {}; }},
  });
  return elements;
}
const row = {id:'fixture', root_pid:4242, root_started:now-60, created_at:now-30,
  expires_at:now+600, revoked_at:null, state:'active', occupies_slot:true,
  session_name:'Fixture task', agent:'Claude', project:'fixture-project', session_id:'fixture-session',
  attribution_source:'claude_session_registry'};
const observation = (rows, changes={}) => ({version:1, observed_at:now,
  exemptions:{state:'ok', occupied:rows.filter(r=>r.occupies_slot).length, limit:3,
    next_expiry:rows[0]?.expires_at ?? null, leases:rows}, ...changes});
let result = render(observation([row]));
assert.match(result['exemption-summary'].textContent, /1／3/);
assert.match(result['exemption-active'].innerHTML, /Fixture task/);
assert.match(result['exemption-active'].innerHTML, /Claude · fixture-project/);
assert.match(result['exemption-active'].innerHTML, /PID 4242 · 原始到期/);
assert.match(html, /<div id="exemption-active"><\/div>\s*<details data-panel="exemptions">/,
  'Occupied sessions must remain visible outside the collapsed history');

result = render(observation([{...row, session_name:null, agent:null, project:null, state:'process_exited'}]));
assert.match(result['exemption-active'].innerHTML, /尚未記錄 session 名稱/);
assert.match(result['exemption-active'].innerHTML, /程序 · PID 4242/);
assert.match(result['exemption-active'].innerHTML, /占位 · process_exited/);

const history = [row,
  {...row,id:'expired',session_name:'Expired fixture',state:'expired',occupies_slot:false},
  {...row,id:'revoked',session_name:'Revoked fixture',state:'revoked',occupies_slot:false}];
result = render(observation(history));
assert.ok(!result['exemption-active'].innerHTML.includes('Expired fixture'));
assert.ok(!result['exemption-active'].innerHTML.includes('Revoked fixture'));
assert.match(result['exemption-details'].innerHTML, /Expired fixture/);
assert.match(result['exemption-details'].innerHTML, /Revoked fixture/);
assert.match(result['exemption-details'].innerHTML, /fixture-session/);

const unsafe = '<img src=x onerror="bad()">';
result = render(observation([1,2,3,4].map(id=>({...row,id:String(id), session_name:unsafe,
  project:unsafe,agent:unsafe,process_name:unsafe,session_id:unsafe,attribution_source:unsafe,state:unsafe}))));
assert.equal((result['exemption-active'].innerHTML.match(/<article /g)||[]).length,3);
assert.match(result['exemption-summary'].textContent, /4／3/, 'Do not hide excess occupancy in inconsistent data');
for (const id of ['exemption-active','exemption-details']) {
  assert.ok(!result[id].innerHTML.includes('<img'));
  assert.ok(result[id].innerHTML.includes('&lt;img'));
}

result = render(observation([{...row,expires_at:now-10}], {observed_at:now-600}));
assert.match(result['exemption-summary'].textContent, /資料延遲/);
assert.match(result['exemption-active'].innerHTML, /占位 · active/,
  'Client time must not revoke or release a lease');
assert.match(render(observation([]))['exemption-active'].innerHTML, /目前沒有占位/);
assert.ok(!render(observation([], {observed_at:now-600}))['exemption-active'].innerHTML.includes('目前沒有占位'));
assert.match(render(null)['exemption-summary'].textContent, /名額未知/);
const unknownLimit = observation([row]);
unknownLimit.exemptions.limit = null;
assert.match(render(unknownLimit)['exemption-summary'].textContent, /1／未知/);

assert.match(collector, /exemption-snapshot\.py/);
assert.match(collector, /Invoke-BoundedQuery \$leaseDisplayPython \$leaseDisplayArgs 3000/);
assert.match(collector, /window\.SENTINEL_EXEMPTIONS=/);
assert.match(collector, /\$leaseDisplayProcessSampleStarted = \[DateTimeOffset\]::Now\r?\n\$procs = Get-CimInstance/,
  'Freshness begins before the reused process enumeration');
assert.match(collector, /sampled_epoch = \$leaseDisplayProcessSampleStarted\.ToUnixTimeSeconds\(\)/);
assert.ok(!script.includes('fetch('), 'The panel consumes the existing publication only');
console.log('PASS: independent exemption panel, stale/unknown states, escaping and collector integration');
