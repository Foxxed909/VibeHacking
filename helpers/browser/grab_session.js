#!/usr/bin/env node
/*
 * grab_session.js — capture your own verified browser session for the toolkit.
 *
 * Opens a REAL Chromium on YOUR machine. You solve any Cloudflare check and log
 * in normally — as yourself. It then exports your cookies + User-Agent so the
 * Python tools reuse that verified session. Nothing here fakes a fingerprint or
 * evades detection: it carries your own real session, the way a browser would.
 *
 * Requires (on your machine, one time):
 *     npm install playwright
 *     npx playwright install chromium
 *
 * Usage:
 *     node grab_session.js https://www.bridgemind.ai/ [session_auth.json]
 *
 * Then point the toolkit at the file it writes:
 *     export VIBE_AUTH_FILE=$PWD/session_auth.json      # macOS/Linux
 *     $env:VIBE_AUTH_FILE = "$PWD\session_auth.json"    # Windows PowerShell
 *     python TOOLS/authcheck.py --url https://app.bridgemind.ai/dashboard
 */
const { chromium } = require('playwright');
const fs = require('fs');
const readline = require('readline');

(async () => {
  const url = process.argv[2];
  const out = process.argv[3] || 'session_auth.json';
  if (!url) {
    console.error('usage: node grab_session.js <url> [outfile]');
    process.exit(2);
  }

  console.log('[*] Launching a real browser. This runs on YOUR machine, as YOU.');
  const browser = await chromium.launch({ headless: false });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(url, { waitUntil: 'domcontentloaded' }).catch(() => {});

  console.log('\n[*] In the browser window:');
  console.log('      1. Solve any "Just a moment…" / verify-human check.');
  console.log('      2. Log into your account (the bounty needs you authenticated).');
  console.log('      3. Navigate to the area you want to test.');
  console.log('[*] Then come back here and press ENTER to capture the session.\n');

  await new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('', () => { rl.close(); resolve(); });
  });

  const cookies = await ctx.cookies();
  const userAgent = await page.evaluate(() => navigator.userAgent).catch(() => '');
  const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join('; ');

  const session = {
    url,
    captured_at: new Date().toISOString(),
    user_agent: userAgent,
    cookie: cookieHeader,
    cookies: cookies.map((c) => ({ name: c.name, value: c.value, domain: c.domain, path: c.path })),
  };
  fs.writeFileSync(out, JSON.stringify(session, null, 2));

  const hasCf = cookies.some((c) => c.name === 'cf_clearance');
  console.log(`\n[+] Wrote ${out}`);
  console.log(`[+] ${cookies.length} cookie(s) captured${hasCf ? ' (incl. cf_clearance ✓)' : ''}.`);
  console.log(`[+] User-Agent: ${userAgent}`);
  console.log('\n[*] Next:');
  console.log(`      export VIBE_AUTH_FILE="$PWD/${out}"`);
  console.log('      python TOOLS/authcheck.py --url ' + url);
  console.log('[!] This file IS your live session — treat it like a password, do not commit or share it.');

  await browser.close();
})().catch((e) => { console.error('[-] ' + e.message); process.exit(1); });
