<?php
/**
 * Sender Infrastructure Analyzer
 * Checks PTR, MX, SPF, DKIM, DMARC, DNSBL, geolocation and gives a reputation score.
 * Requires PHP 8.0+. Run locally with: php -S localhost:8000
 * License: MIT
 */

declare(strict_types=1);

session_start();

// ---------- Configuration ----------
const DNSBLS = [
    'zen.spamhaus.org'         => 'Spamhaus ZEN',
    'bl.spamcop.net'           => 'SpamCop',
    'b.barracudacentral.org'   => 'Barracuda',
    'psbl.surriel.com'         => 'PSBL',
    'dnsbl-1.uceprotect.net'   => 'UCEPROTECT L1',
    'all.s5h.net'              => 'S5H',
    'dnsbl.dronebl.org'        => 'DroneBL',
];

const DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 's1', 's2',
    'mail', 'dkim', 'smtp', 'mandrill', 'mxvault', 'everlytickey1', 'sendgrid', 'zoho',
];

const RATE_LIMIT = 10;      // analyses allowed
const RATE_WINDOW = 60;     // per this many seconds

// ---------- Helpers ----------
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function normalize_target(string $raw): ?string
{
    $t = strtolower(trim($raw));
    $t = preg_replace('#^[a-z]+://#', '', $t);      // strip scheme
    $t = preg_replace('#[/?\#].*$#', '', $t);       // strip path/query
    if (str_contains($t, '@')) {                    // email -> domain
        $t = substr($t, strrpos($t, '@') + 1);
    }
    $t = rtrim($t, '.');
    if ($t === '' || strlen($t) > 253) {
        return null;
    }
    if (filter_var($t, FILTER_VALIDATE_IP)) {
        return $t;
    }
    if (preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $t)) {
        return $t;
    }
    return null;
}

function is_public_ipv4(string $ip): bool
{
    return (bool) filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
}

function dns(string $name, int $type): array
{
    $r = @dns_get_record($name, $type);
    return is_array($r) ? $r : [];
}

function txt_records(string $name): array
{
    $out = [];
    foreach (dns($name, DNS_TXT) as $rec) {
        $out[] = $rec['txt'] ?? implode('', $rec['entries'] ?? []);
    }
    return $out;
}

function rate_limited(): bool
{
    $now = time();
    $hits = array_filter($_SESSION['hits'] ?? [], fn($t) => $t > $now - RATE_WINDOW);
    if (count($hits) >= RATE_LIMIT) {
        $_SESSION['hits'] = $hits;
        return true;
    }
    $hits[] = $now;
    $_SESSION['hits'] = $hits;
    return false;
}

// ---------- Checks ----------
function check_ptr(string $ip): array
{
    $rev = implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
    $names = array_map(fn($r) => rtrim($r['target'] ?? '', '.'), dns($rev, DNS_PTR));
    if (!$names) {
        return ['status' => 'fail', 'summary' => 'No PTR record', 'detail' => 'Add reverse DNS for this IP at your provider.', 'names' => []];
    }
    $confirmed = false;
    foreach ($names as $n) {
        foreach (dns($n, DNS_A) as $a) {
            if (($a['ip'] ?? '') === $ip) {
                $confirmed = true;
            }
        }
    }
    return [
        'status'  => $confirmed ? 'pass' : 'warn',
        'summary' => $confirmed ? 'PTR matches forward DNS' : 'PTR does not resolve back to this IP',
        'detail'  => implode(', ', $names),
        'names'   => $names,
    ];
}

function check_mx(string $domain): array
{
    $mx = dns($domain, DNS_MX);
    usort($mx, fn($a, $b) => ($a['pri'] ?? 0) <=> ($b['pri'] ?? 0));
    if (!$mx) {
        return ['status' => 'fail', 'summary' => 'No MX records', 'detail' => 'The domain cannot receive mail.', 'hosts' => []];
    }
    $hosts = array_map(fn($r) => ($r['pri'] ?? 0) . ' ' . rtrim($r['target'] ?? '', '.'), $mx);
    return ['status' => 'pass', 'summary' => count($mx) . ' MX record(s)', 'detail' => implode("\n", $hosts), 'hosts' => $hosts];
}

function check_spf(string $domain): array
{
    $spf = array_values(array_filter(txt_records($domain), fn($t) => stripos($t, 'v=spf1') === 0));
    if (!$spf) {
        return ['status' => 'fail', 'summary' => 'No SPF record', 'detail' => 'Publish a TXT record starting with v=spf1.', 'flag' => 'missing'];
    }
    if (count($spf) > 1) {
        return ['status' => 'fail', 'summary' => 'Multiple SPF records', 'detail' => implode("\n", $spf), 'flag' => 'multiple'];
    }
    $rec = $spf[0];
    preg_match_all('/(?:^|\s)[+\-~?]?(include:|a\b|mx\b|ptr\b|exists:|redirect=)/i', $rec, $m);
    $lookups = count($m[0]);
    $flag = 'ok';
    $status = 'pass';
    $summary = 'SPF found';
    if (preg_match('/\s\+all\b/i', $rec) || preg_match('/\sall\b/i', $rec)) {
        $status = 'fail'; $flag = 'open'; $summary = 'SPF allows any sender (+all)';
    } elseif (preg_match('/\s\?all\b/i', $rec)) {
        $status = 'warn'; $flag = 'neutral'; $summary = 'SPF is neutral (?all)';
    } elseif (preg_match('/\s~all\b/i', $rec)) {
        $status = 'pass'; $flag = 'soft'; $summary = 'SPF found, softfail (~all)';
    } elseif (!preg_match('/\s-all\b|redirect=/i', $rec)) {
        $status = 'warn'; $flag = 'noall'; $summary = 'SPF has no "all" mechanism';
    } else {
        $summary = 'SPF found, strict (-all)';
    }
    if ($lookups > 10) {
        $status = 'fail'; $flag = 'lookups'; $summary .= ", but $lookups lookups (limit is 10)";
    }
    return ['status' => $status, 'summary' => $summary, 'detail' => $rec, 'flag' => $flag, 'lookups' => $lookups];
}

function check_dkim(string $domain): array
{
    $found = [];
    foreach (DKIM_SELECTORS as $sel) {
        foreach (txt_records("$sel._domainkey.$domain") as $t) {
            if (stripos($t, 'v=DKIM1') !== false || stripos($t, 'p=') !== false) {
                $found[$sel] = substr($t, 0, 90) . (strlen($t) > 90 ? '…' : '');
                break;
            }
        }
    }
    if (!$found) {
        return [
            'status' => 'warn',
            'summary' => 'No DKIM key found on common selectors',
            'detail' => 'Checked: ' . implode(', ', DKIM_SELECTORS) . '. Your selector may be custom.',
            'found' => [],
        ];
    }
    $lines = [];
    foreach ($found as $sel => $v) {
        $lines[] = "$sel: $v";
    }
    return ['status' => 'pass', 'summary' => count($found) . ' DKIM selector(s) found', 'detail' => implode("\n", $lines), 'found' => $found];
}

function check_dmarc(string $domain): array
{
    $rec = null;
    foreach (txt_records("_dmarc.$domain") as $t) {
        if (stripos($t, 'v=DMARC1') === 0) {
            $rec = $t;
            break;
        }
    }
    if ($rec === null) {
        return ['status' => 'fail', 'summary' => 'No DMARC record', 'detail' => 'Publish a TXT record at _dmarc.' . $domain, 'policy' => null];
    }
    $policy = preg_match('/\bp=(none|quarantine|reject)/i', $rec, $m) ? strtolower($m[1]) : null;
    $status = $policy === 'none' || $policy === null ? 'warn' : 'pass';
    $summary = $policy ? "DMARC policy: $policy" : 'DMARC record has no valid policy';
    if ($policy !== null && !preg_match('/\brua=/i', $rec)) {
        $summary .= ' (no reporting address)';
    }
    return ['status' => $status, 'summary' => $summary, 'detail' => $rec, 'policy' => $policy];
}

function check_dnsbl(string $ip): array
{
    $rev = implode('.', array_reverse(explode('.', $ip)));
    $results = [];
    $listed = 0;
    foreach (DNSBLS as $zone => $label) {
        $a = dns("$rev.$zone", DNS_A);
        if (!$a) {
            $results[] = ['name' => $label, 'state' => 'clean'];
            continue;
        }
        $code = $a[0]['ip'] ?? '';
        // Spamhaus and others answer 127.255.255.x when the resolver itself is blocked.
        if (str_starts_with($code, '127.255.255.')) {
            $results[] = ['name' => $label, 'state' => 'unknown'];
            continue;
        }
        $listed++;
        $results[] = ['name' => $label, 'state' => 'listed', 'code' => $code];
    }
    return [
        'status'  => $listed === 0 ? 'pass' : ($listed >= 2 ? 'fail' : 'warn'),
        'summary' => $listed === 0 ? 'Not listed on checked blocklists' : "Listed on $listed blocklist(s)",
        'listed'  => $listed,
        'results' => $results,
    ];
}

function check_geo(string $ip): array
{
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'ignore_errors' => true]]);
    $raw = @file_get_contents('https://ipwho.is/' . rawurlencode($ip), false, $ctx);
    $j = $raw ? json_decode($raw, true) : null;
    if (!is_array($j) || empty($j['success'])) {
        return ['status' => 'info', 'summary' => 'Geolocation unavailable', 'detail' => ''];
    }
    $place = implode(', ', array_filter([$j['city'] ?? '', $j['region'] ?? '', $j['country'] ?? '']));
    $org = $j['connection']['org'] ?? ($j['connection']['isp'] ?? '');
    return [
        'status'  => 'info',
        'summary' => $place ?: 'Unknown location',
        'detail'  => trim(($org ? "Network: $org" : '') . (isset($j['connection']['asn']) ? " (AS{$j['connection']['asn']})" : '')),
    ];
}

function score(array $r): array
{
    $s = 100;
    $notes = [];
    $deduct = function (int $n, string $why) use (&$s, &$notes) {
        $s -= $n;
        $notes[] = "-$n  $why";
    };
    if (isset($r['ptr'])) {
        if ($r['ptr']['status'] === 'fail') $deduct(10, 'No PTR record');
        if ($r['ptr']['status'] === 'warn') $deduct(5, 'PTR does not match forward DNS');
    }
    if (isset($r['mx']) && $r['mx']['status'] === 'fail') $deduct(10, 'No MX records');
    if (isset($r['spf'])) {
        $f = $r['spf']['flag'] ?? '';
        $map = ['missing' => 20, 'multiple' => 15, 'open' => 20, 'lookups' => 10, 'neutral' => 8, 'noall' => 5, 'soft' => 2];
        if (isset($map[$f])) $deduct($map[$f], 'SPF: ' . $r['spf']['summary']);
    }
    if (isset($r['dkim']) && $r['dkim']['status'] !== 'pass') $deduct(5, 'No DKIM found on common selectors');
    if (isset($r['dmarc'])) {
        if ($r['dmarc']['policy'] === null) $deduct(15, 'No valid DMARC policy');
        elseif ($r['dmarc']['policy'] === 'none') $deduct(5, 'DMARC policy is none');
    }
    if (isset($r['dnsbl']) && $r['dnsbl']['listed'] > 0) {
        $deduct(min(45, 20 * $r['dnsbl']['listed']), 'Blocklist listings: ' . $r['dnsbl']['listed']);
    }
    $s = max(0, min(100, $s));
    $grade = $s >= 90 ? 'Excellent' : ($s >= 75 ? 'Good' : ($s >= 55 ? 'Needs work' : 'Poor'));
    return ['value' => $s, 'grade' => $grade, 'notes' => $notes];
}

function analyze(string $target): array
{
    $isIp = (bool) filter_var($target, FILTER_VALIDATE_IP);
    $out = ['target' => $target, 'type' => $isIp ? 'ip' : 'domain'];
    $domain = $isIp ? null : $target;
    $ip = null;

    if ($isIp) {
        $ip = $target;
    } else {
        $a = dns($domain, DNS_A);
        $ip = $a[0]['ip'] ?? null;
    }

    if ($ip !== null && !is_public_ipv4($ip)) {
        $out['error'] = 'Only public IPv4 addresses can be analyzed.';
        return $out;
    }

    $out['ip'] = $ip;
    if ($ip) {
        $out['ptr'] = check_ptr($ip);
        $out['dnsbl'] = check_dnsbl($ip);
        $out['geo'] = check_geo($ip);
        // For an IP, try to use the PTR hostname's registered domain for mail checks.
        if ($isIp && !empty($out['ptr']['names'])) {
            $parts = explode('.', $out['ptr']['names'][0]);
            if (count($parts) >= 2) {
                $domain = implode('.', array_slice($parts, -2));
                $out['derived_domain'] = $domain;
            }
        }
    }
    if ($domain) {
        $out['mx'] = check_mx($domain);
        $out['spf'] = check_spf($domain);
        $out['dkim'] = check_dkim($domain);
        $out['dmarc'] = check_dmarc($domain);
    }
    $out['score'] = score($out);
    return $out;
}

// ---------- Request handling ----------
$raw = isset($_GET['target']) ? (string) $_GET['target'] : '';
$json = ($_GET['format'] ?? '') === 'json';
$result = null;
$error = null;

if ($raw !== '') {
    $target = normalize_target($raw);
    if ($target === null) {
        $error = 'Enter a valid domain (example.com), email address, or public IPv4 address.';
    } elseif (rate_limited()) {
        $error = 'Too many checks. Wait a minute and try again.';
    } else {
        $result = analyze($target);
        if (isset($result['error'])) {
            $error = $result['error'];
            $result = null;
        }
    }
}

if ($json) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($error ? ['error' => $error] : ($result ?? new stdClass()), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function card(string $title, array $r): void
{
    $status = $r['status'] ?? 'info';
    $labels = ['pass' => 'Pass', 'warn' => 'Review', 'fail' => 'Fix', 'info' => 'Info'];
    echo '<section class="card ' . h($status) . '">';
    echo '<header><h3>' . h($title) . '</h3><span class="badge">' . h($labels[$status] ?? 'Info') . '</span></header>';
    echo '<p class="sum">' . h($r['summary'] ?? '') . '</p>';
    if (!empty($r['detail'])) {
        echo '<pre>' . h($r['detail']) . '</pre>';
    }
    echo '</section>';
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sender Infrastructure Analyzer</title>
<style>
:root {
  --bg: #f4f6f8; --panel: #ffffff; --ink: #14202b; --mute: #5b6b7a; --line: #d9e0e6;
  --pass: #0f7b4f; --warn: #a36100; --fail: #b3261e; --info: #35566f; --accent: #0b5cad;
  --pass-bg: #e3f4ec; --warn-bg: #fbf0d9; --fail-bg: #fbe5e3; --info-bg: #e6eef4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e151b; --panel: #16212a; --ink: #e6edf3; --mute: #93a4b3; --line: #263543;
    --pass: #4cc38a; --warn: #e3b04b; --fail: #ff7b72; --info: #8fb4d1; --accent: #6cb2f5;
    --pass-bg: #12301f; --warn-bg: #3a2c0e; --fail-bg: #3b1816; --info-bg: #1a2a36;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 880px; margin: 0 auto; padding: 40px 20px 64px; }
h1 { font-size: 1.9rem; margin: 0 0 6px; letter-spacing: -0.01em; }
.lede { color: var(--mute); margin: 0 0 24px; max-width: 60ch; }
form { display: flex; gap: 10px; flex-wrap: wrap; }
input[type=text] { flex: 1 1 260px; padding: 12px 14px; font: inherit; color: var(--ink); background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
button { padding: 12px 20px; font: inherit; font-weight: 600; color: #fff; background: var(--accent); border: 0; border-radius: 8px; cursor: pointer; }
@media (prefers-color-scheme: dark) { button { color: #0e151b; } }
input:focus-visible, button:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.error { margin-top: 16px; padding: 12px 14px; border-radius: 8px; background: var(--fail-bg); color: var(--fail); }
.score { display: flex; align-items: center; gap: 20px; margin: 32px 0 8px; padding: 20px; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
.score .num { font-size: 3.2rem; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
.score .meta { color: var(--mute); }
.score .meta strong { color: var(--ink); font-size: 1.15rem; }
details { margin: 0 0 20px; color: var(--mute); }
details pre { margin: 8px 0 0; }
.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); }
@media (max-width: 520px) { .grid { grid-template-columns: 1fr; } }
.card { background: var(--panel); border: 1px solid var(--line); border-left-width: 5px; border-radius: 8px; padding: 14px 16px; min-width: 0; }
.card.pass { border-left-color: var(--pass); } .card.warn { border-left-color: var(--warn); }
.card.fail { border-left-color: var(--fail); } .card.info { border-left-color: var(--info); }
.card header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.card h3 { margin: 0; font-size: 1rem; }
.badge { font-size: .8rem; font-weight: 600; padding: 2px 10px; border-radius: 99px; }
.pass .badge { color: var(--pass); background: var(--pass-bg); } .warn .badge { color: var(--warn); background: var(--warn-bg); }
.fail .badge { color: var(--fail); background: var(--fail-bg); } .info .badge { color: var(--info); background: var(--info-bg); }
.sum { margin: 6px 0 0; }
pre { margin: 8px 0 0; padding: 8px 10px; background: var(--bg); border-radius: 6px; font: .82rem/1.45 ui-monospace, Consolas, monospace; white-space: pre-wrap; word-break: break-all; color: var(--mute); }
.bl { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.bl span { font-size: .82rem; padding: 3px 9px; border-radius: 6px; background: var(--pass-bg); color: var(--pass); }
.bl span.listed { background: var(--fail-bg); color: var(--fail); font-weight: 600; }
.bl span.unknown { background: var(--info-bg); color: var(--info); }
footer { margin-top: 36px; color: var(--mute); font-size: .88rem; }
</style>
</head>
<body>
<main>
  <h1>Sender Infrastructure Analyzer</h1>
  <p class="lede">Enter a sending domain or IP address to check reverse DNS, MX, SPF, DKIM, DMARC, blocklists and location in one report.</p>

  <form method="get" action="">
    <input type="text" name="target" value="<?= h($raw) ?>" placeholder="example.com or 203.0.113.25" aria-label="Domain or IP address" autocomplete="off" required>
    <button type="submit">Analyze</button>
  </form>

  <?php if ($error): ?>
    <div class="error" role="alert"><?= h($error) ?></div>
  <?php endif; ?>

  <?php if ($result): ?>
    <div class="score">
      <div class="num"><?= (int) $result['score']['value'] ?></div>
      <div class="meta">
        <strong><?= h($result['score']['grade']) ?></strong><br>
        Reputation score for <?= h($result['target']) ?>
        <?php if (!empty($result['ip']) && $result['type'] === 'domain'): ?> (resolves to <?= h($result['ip']) ?>)<?php endif; ?>
        <?php if (!empty($result['derived_domain'])): ?><br>Mail checks run on <?= h($result['derived_domain']) ?>, taken from the PTR hostname.<?php endif; ?>
      </div>
    </div>
    <?php if ($result['score']['notes']): ?>
      <details><summary>How the score was calculated</summary><pre><?= h(implode("\n", $result['score']['notes'])) ?></pre></details>
    <?php endif; ?>

    <div class="grid">
      <?php
      if (isset($result['ptr']))   card('Reverse DNS (PTR)', $result['ptr']);
      if (isset($result['mx']))    card('MX records', $result['mx']);
      if (isset($result['spf']))   card('SPF', $result['spf']);
      if (isset($result['dkim']))  card('DKIM', $result['dkim']);
      if (isset($result['dmarc'])) card('DMARC', $result['dmarc']);
      if (isset($result['geo']))   card('Geolocation', $result['geo']);
      ?>
      <?php if (isset($result['dnsbl'])): $d = $result['dnsbl']; ?>
        <section class="card <?= h($d['status']) ?>" style="grid-column: 1 / -1">
          <header><h3>Blocklists (DNSBL)</h3><span class="badge"><?= $d['listed'] === 0 ? 'Pass' : ($d['status'] === 'fail' ? 'Fix' : 'Review') ?></span></header>
          <p class="sum"><?= h($d['summary']) ?></p>
          <div class="bl">
            <?php foreach ($d['results'] as $b): ?>
              <span class="<?= h($b['state']) ?>"><?= h($b['name']) ?>: <?= $b['state'] === 'clean' ? 'clean' : ($b['state'] === 'listed' ? 'listed' : 'no answer') ?></span>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endif; ?>
    </div>
    <footer>DKIM is checked on common selectors only. A "Review" result means the setup may still be fine, so check your own selector. Add <code>&amp;format=json</code> to the URL for raw JSON.</footer>
  <?php endif; ?>
</main>
</body>
</html>