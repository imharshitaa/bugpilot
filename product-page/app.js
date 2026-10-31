// BugPilot product page — simulated terminal only.
// This runs entirely client-side, scripted transcript output, no network
// requests, no connection to any backend. It does not run the real scanner.

(function () {
  const output = document.getElementById('term-output');
  const input = document.getElementById('term-input');
  const history = [];
  let historyIndex = -1;
  let busy = false;

  const SAMPLE_URLS = [
    'http://testphp.vulnweb.com',
    'http://testhtml5.vulnweb.com',
    'http://zero.webappsecurity.com',
    'http://demo.testfire.net',
    'https://juice-shop.herokuapp.com',
  ];
  const SAMPLE_SET = new Set(SAMPLE_URLS);
  const SUBCOMMANDS = ['scan', 'crawl', 'recon', 'test', 'exploit'];

  const PATH_STATUSES = [
    ['/', 200],
    ['/login', 200],
    ['/search?q=test', 302],
    ['/api/v1/users', 200],
    ['/admin', 403],
    ['/robots.txt', 200],
    ['/sitemap.xml', 200],
  ];

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function scrollToBottom() {
    output.scrollTop = output.scrollHeight;
  }

  function line(text, cls) {
    const el = document.createElement('div');
    el.className = 'line ' + (cls || 'info');
    el.textContent = text;
    output.appendChild(el);
    scrollToBottom();
  }

  function pad(value, size) {
    const text = String(value);
    return text.length >= size ? text : text + ' '.repeat(size - text.length);
  }

  function fakeCode(seed) {
    const base = [200, 200, 301, 302, 403, 404];
    return base[seed % base.length];
  }

  function printVulnTable(target) {
    const host = new URL(target).hostname;
    line('[+] simulated findings:', 'running');
    line(
      pad('ID', 7) + '| ' + pad('Severity', 8) + '| ' + pad('Category', 20) + '| ' + pad('Endpoint', 34) + '| Evidence',
      'info'
    );
    line(pad('V-001', 7) + '| ' + pad('HIGH', 8) + '| ' + pad('SQLi', 20) + '| ' + pad(host + '/search?q=test', 34) + '| boolean/time response diff', 'vuln');
    line(pad('V-002', 7) + '| ' + pad('MEDIUM', 8) + '| ' + pad('Missing Headers', 20) + '| ' + pad(host + '/', 34) + '| CSP/X-Frame-Options absent', 'vuln');
    line(pad('V-003', 7) + '| ' + pad('MEDIUM', 8) + '| ' + pad('Weak Rate Limit', 20) + '| ' + pad(host + '/login', 34) + '| repeated auth accepted', 'vuln');
  }

  async function runScan(target) {
    const root = target.replace(/\/$/, '');
    line('[~] phase: discovery', 'running');
    await sleep(80);
    for (let i = 0; i < PATH_STATUSES.length; i++) {
      const [path, code] = PATH_STATUSES[i];
      line('[>] tested: ' + root + path + ' | status=' + code, 'info');
      await sleep(55);
    }
    line('[~] phase: active checks (confidence-gated)', 'running');
    await sleep(80);
    line('[>] module-set: xss, sqli, misconfig, rate_limit_bruteforce, ...', 'info');
    await sleep(80);
    line('[>] xss: findings=0 (confidence below threshold or no reflection observed)', 'info');
    line('[>] sqli: findings=1 confidence=0.80', 'vuln');
    line('[>] misconfig: findings=1 confidence=0.70', 'vuln');
    line('[>] rate_limit_bruteforce: findings=1 confidence=0.55 (suppressed by default min_confidence)', 'warn');
    printVulnTable(target);
  }

  async function runCrawl(target) {
    const root = target.replace(/\/$/, '');
    const found = ['/', '/login', '/account', '/api/v1', '/search', '/admin', '/logout'];
    line('[+] crawling target: ' + target, 'running');
    for (let i = 0; i < found.length; i++) {
      const u = root + found[i];
      line('[>] discovered: ' + u + ' | status=' + fakeCode(u.length + i), 'info');
      await sleep(55);
    }
    line('[+] total endpoints discovered: ' + found.length, 'running');
  }

  async function runRecon(target) {
    line('[+] recon target: ' + target, 'running');
    await sleep(90);
    line('[>] host: ' + new URL(target).hostname, 'info');
    line('[>] tls: checked | cert chain inspected (simulated)', 'info');
    line('[>] headers: Server, Content-Security-Policy, X-Frame-Options snapshot (simulated)', 'info');
  }

  async function runTest(target) {
    line('[~] running module pipeline (same engine as scan, --validate-findings none)', 'running');
    await sleep(100);
    await runScan(target);
  }

  async function runExploit(target) {
    line('[~] isolated validation started (--validate-findings all)', 'running');
    await sleep(120);
    line('[>] selected: V-001 SQLi', 'info');
    line('[+] validation evidence: injectable parameter confirmed (simulated)', 'vuln');
    line('[+] evidence file: reports/output/run_<timestamp>/findings.json (simulated path)', 'info');
  }

  async function runSimulated(sub, target) {
    busy = true;
    input.disabled = true;
    line('[~] SIMULATED_MODE — scripted transcript, no network requests made', 'warn');
    line('[~] ' + sub + ' started (target=' + target + ')', 'running');
    await sleep(150);

    if (sub === 'scan') await runScan(target);
    else if (sub === 'crawl') await runCrawl(target);
    else if (sub === 'recon') await runRecon(target);
    else if (sub === 'test') await runTest(target);
    else if (sub === 'exploit') await runExploit(target);

    await sleep(80);
    line('[+] simulated run finished', 'running');
    busy = false;
    input.disabled = false;
    input.focus();
  }

  function printHelp() {
    line('Use: bugpilot <scan|crawl|recon|test|exploit> <sample-url>', 'info');
    line('Sample URLs: ' + SAMPLE_URLS.join(', '), 'info');
    line('Other commands: help, clear', 'info');
  }

  function execute(raw) {
    const cmd = raw.trim();
    if (!cmd) return;

    if (cmd === 'clear') {
      output.innerHTML = '';
      return;
    }
    if (cmd === 'help' || cmd === 'bugpilot --help' || cmd === 'bugpilot help') {
      printHelp();
      return;
    }
    if (!/^bugpilot\s+/i.test(cmd)) {
      line('[!] unknown command. Type "help".', 'err');
      return;
    }

    const parts = cmd.trim().split(/\s+/);
    let sub = (parts[1] || '').toLowerCase();
    if (sub === 'expoit') sub = 'exploit';
    const target = parts[2] || '';

    if (!SUBCOMMANDS.includes(sub)) {
      line('[!] unsupported subcommand: ' + sub, 'err');
      return;
    }
    if (!target) {
      line('[!] missing target URL. Usage: bugpilot ' + sub + ' <sample-url>', 'err');
      return;
    }
    if (!SAMPLE_SET.has(target)) {
      line('[!] target blocked in SIMULATED_MODE — use one of the sample URLs above.', 'err');
      return;
    }

    line('[+] ' + sub + ' target: ' + target, 'running');
    runSimulated(sub, target);
  }

  input.addEventListener('keydown', (e) => {
    if (busy) return;
    if (e.key === 'Enter') {
      const value = input.value;
      if (value.trim()) {
        history.push(value.trim());
        historyIndex = history.length;
        line('>>> ' + value.trim(), 'info');
      }
      input.value = '';
      execute(value);
    } else if (e.key === 'ArrowUp') {
      if (!history.length) return;
      historyIndex = Math.max(0, historyIndex - 1);
      input.value = history[historyIndex] || '';
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      if (!history.length) return;
      historyIndex = Math.min(history.length, historyIndex + 1);
      input.value = history[historyIndex] || '';
      e.preventDefault();
    }
  });

  printHelp();
})();
