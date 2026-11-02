/* Synthetic-only browser smoke tests. Requires a built app and Linux Chromium libraries.
 * This headless test runs without a browser sandbox; never use real or sensitive data.
 */
const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const {spawn, spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const http = require('node:http');
const chromium = require('@sparticuz/chromium');
const {chromium: playwright} = require('playwright-core');

const port = 32000 + Math.floor(Math.random()*10000);
const base = `http://127.0.0.1:${port}`;
let server, backend, backendResponse, temp, browserEnv, browserArgs;
const fixture = {mode:'synthetic-demo', notice:'fixture', records:[{
  id:'DEMO-001', title:'Suspicious infrastructure cluster', category:'Infrastructure', severity:'Critical',
  source:'Synthetic exercise', observed_at:'2026-10-31T09:42:00Z', confidence:78,
  description:'Example infrastructure relationship for training; not an observed threat.', synthetic:true,
}], sources:[{name:'CISA KEV',status:'not configured'}]};

before(async () => {
  // Amazon Linux bundle supplies NSS libraries absent from some minimal Linux images.
  temp = fs.mkdtempSync(path.join(os.tmpdir(),'cicc-browser-'));
  const bundle = path.resolve(path.dirname(require.resolve('@sparticuz/chromium')), '..', '..', 'bin', 'al2023.tar.br');
  const tar = path.join(temp,'libs.tar');
  fs.writeFileSync(tar,zlib.brotliDecompressSync(fs.readFileSync(bundle)));
  const unpack = spawnSync('tar',['-xf',tar,'-C',temp]);
  if (unpack.status !== 0) throw new Error('Unable to unpack test browser libraries');
  browserEnv = {...process.env, LD_LIBRARY_PATH:`${path.join(temp,'lib')}:${process.env.LD_LIBRARY_PATH || ''}`};
  backendResponse = JSON.stringify(fixture);
  backend = http.createServer((req,res)=>{res.setHeader('content-type','application/json');res.end(backendResponse)});
  await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
  let logs = '';
  server = spawn(process.execPath,[require.resolve('next/dist/bin/next'),'start','-H','127.0.0.1','-p',String(port)],
    {cwd:path.resolve(__dirname,'..'),env:{...process.env,API_INTERNAL_URL:`http://127.0.0.1:${backend.address().port}`},stdio:['ignore','pipe','pipe']});
  server.stdout.on('data', chunk => { logs += chunk; });
  server.stderr.on('data', chunk => { logs += chunk; });
  const deadline = Date.now()+20000;
  while (Date.now()<deadline) {
    if (server.exitCode !== null) throw new Error('Test server exited');
    if (logs.includes('Ready')) {
      try { if ((await fetch(base)).ok) break; } catch { /* Wait for startup. */ }
    }
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  if (Date.now()>=deadline) throw new Error('Test server did not start');
  browserArgs = chromium.args.filter(arg=>!['--disable-web-security','--allow-running-insecure-content'].includes(arg));

});

after(async () => {
  if (server) server.kill('SIGTERM');
  if (backend) await new Promise(resolve=>backend.close(resolve));
  if (temp) fs.rmSync(temp,{recursive:true,force:true});
});

async function launchBrowser() {
  return playwright.launch({executablePath:await chromium.executablePath(),args:browserArgs,env:browserEnv,headless:true});
}
async function newFixturePage(options={}) {
  const browser = await launchBrowser();
  const page = await browser.newPage(options);
  const external = [];
  await page.route('**/*', async route => {
    const url = route.request().url();
    if (url.startsWith(base+'/api/v1/overview')) return route.fulfill({json:fixture});
    if (url.startsWith(base+'/')) return route.continue();
    external.push(url); return route.abort();
  });
  try {
    await page.goto(base+'/',{waitUntil:'networkidle'});
    return {page,external,browser};
  } catch (error) { await browser.close(); throw error; }
}

test('Arabic and Persian locale, persistence, RTL and modal keyboard focus', async () => {
  const {page,external,browser} = await newFixturePage({viewport:{width:1280,height:900}});
  try {
    await page.selectOption('select','ar');
    assert.equal(await page.locator('.shell').getAttribute('dir'),'rtl');
    assert.equal(await page.locator('h1').innerText(),'مركز القيادة');
    const open = page.getByRole('button',{name:'عرض مجموعة بنية تحتية مشبوهة'});
    await open.focus(); await page.keyboard.press('Enter');
    assert.equal(await page.getByRole('dialog').count(),1);
    assert.equal(await page.locator('main').evaluate(el=>el.inert),true);
    assert.equal(await page.locator('aside').evaluate(el=>el.inert),true);
    await page.locator('select').evaluate(el=>el.focus());
    assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'إغلاق التفاصيل');
    assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'إغلاق التفاصيل');
    await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'إغلاق التفاصيل');
    await page.keyboard.press('Shift+Tab');
    assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'إغلاق التفاصيل');
    await page.keyboard.press('Escape');
    assert.equal(await page.getByRole('dialog').count(),0);
    assert.equal(await page.locator('main').evaluate(el=>el.inert),false);
    assert.equal(await page.locator('aside').evaluate(el=>el.inert),false);
    assert.equal(await page.evaluate(()=>document.activeElement?.getAttribute('aria-label')),'عرض مجموعة بنية تحتية مشبوهة');
    await page.reload({waitUntil:'networkidle'});
    assert.equal(await page.locator('select').inputValue(),'ar');
    await page.selectOption('select','fa');
    assert.equal(await page.locator('h1').innerText(),'مرکز فرماندهی');
    assert.equal(await page.locator('.shell').getAttribute('dir'),'rtl');
    assert.deepEqual(external,[]);
  } finally { await browser.close(); }
});

test('mobile RTL has no document overflow and demo badge remains visible', async () => {
  const {page,browser} = await newFixturePage({viewport:{width:390,height:844}});
  try {
    await page.selectOption('select','ar');
    const size = await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));
    assert.equal(size.scroll,size.width);
    const badge = page.locator('.demo-pill');
    assert.equal(await badge.isVisible(),true);
    const box = await badge.boundingBox();
    assert.ok(box && box.width > 70 && box.height < 40);
  } finally { await browser.close(); }
});

test('failed demo API is visible and no live status is invented', async () => {
  const browser = await launchBrowser();
  const page = await browser.newPage();
  try {
    await page.route('**/*', async route => {
      const url=route.request().url();
      if (url.startsWith(base+'/api/v1/overview')) return route.fulfill({status:503,json:{error:'unavailable'}});
      if (url.startsWith(base+'/')) return route.continue();
      return route.abort();
    });
    await page.goto(base+'/',{waitUntil:'networkidle'});
    assert.match(await page.getByRole('alert').filter({hasText:'Intelligence API unavailable'}).innerText(),/Intelligence API unavailable/);
    assert.equal(await page.locator('.metrics').count(),0);
  } finally { await browser.close(); }
});


test('proxy accepts only the bounded synthetic contract and does not cache errors', async () => {
  try {
    let response = await fetch(base+'/api/v1/overview');
    assert.equal(response.status,200);
    assert.deepEqual(await response.json(),fixture);
    assert.equal(response.headers.get('cache-control'),'no-store');
    for (const invalid of [
      JSON.stringify({...fixture,mode:'live'}),
      JSON.stringify({...fixture,records:[{...fixture.records[0],synthetic:false}]}),
      JSON.stringify({...fixture,secret:'should not be forwarded'}),
      '{broken json',
      ' '.repeat(256*1024+1),
    ]) {
      backendResponse = invalid;
      response = await fetch(base+'/api/v1/overview');
      assert.equal(response.status,502);
      assert.equal(response.headers.get('cache-control'),'no-store');
      assert.deepEqual(await response.json(),{error:'Intelligence API unavailable'});
    }
  } finally { backendResponse=JSON.stringify(fixture); }
});

test('malformed successful browser response shows error instead of rendering demo data', async () => {
  const browser = await launchBrowser();
  const page = await browser.newPage();
  try {
    await page.route('**/*', async route => {
      const url=route.request().url();
      if (url.startsWith(base+'/api/v1/overview')) return route.fulfill({json:{...fixture,records:[{...fixture.records[0],synthetic:false}]}});
      if (url.startsWith(base+'/')) return route.continue();
      return route.abort();
    });
    await page.goto(base+'/',{waitUntil:'networkidle'});
    assert.match(await page.getByRole('alert').filter({hasText:'Intelligence API unavailable'}).innerText(),/Intelligence API unavailable/);
    assert.equal(await page.locator('.metrics').count(),0);
  } finally { await browser.close(); }
});
