<?php
/**
 * Private Remote Video Gallery (videy.co / aceimg.com)
 * - Seluruh situs PRIVAT: tanpa login hanya tampil form masuk.
 * - Video TIDAK diunduh / disimpan; hanya metadata (link + direct URL) di videos.json.
 * - Mendukung folder & subfolder.
 *
 * Environment variable (Railway):
 *   ADMIN_PASS = password
 *   DATA_DIR   = /data   (lokasi Volume agar videos.json permanen)
 */
declare(strict_types=1);

/* ================= KONFIGURASI ================= */
define('ADMIN_PASS', getenv('ADMIN_PASS') ?: 'ganti-password-ini');
define('DATA_FILE', rtrim(getenv('DATA_DIR') ?: __DIR__, '/') . '/videos.json');
define('AUTH_COOKIE', 'vl_auth');
define('LOGIN_DAYS', 30);
const MAX_DEPTH    = 8;                            // kedalaman maksimum subfolder
const SITE_NAME    = 'Videos';
const SOURCE_HOSTS = ['videy.co', 'aceimg.com'];   // domain halaman sumber
const MEDIA_HOSTS  = ['videy.co', 'aceimg.com'];   // domain file video (CDN); tambah jika perlu
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36';
/* ================================================ */

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

/* ---------------- Autentikasi (cookie bertanda tangan) ---------------- */
function is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}
function sign(string $data): string { return hash_hmac('sha256', $data, ADMIN_PASS); }

function is_admin(): bool {
    $c = (string)($_COOKIE[AUTH_COOKIE] ?? '');
    if (!preg_match('/^(\d{9,11})\.([a-f0-9]{64})$/', $c, $m)) return false;
    if ((int)$m[1] < time()) return false;
    return hash_equals(sign('auth|' . $m[1]), $m[2]);
}
function login_cookie(): void {
    $exp = time() + 86400 * LOGIN_DAYS;
    setcookie(AUTH_COOKIE, $exp . '.' . sign('auth|' . $exp), [
        'expires' => $exp, 'path' => '/', 'httponly' => true,
        'samesite' => 'Lax', 'secure' => is_https(),
    ]);
}
function logout_cookie(): void {
    setcookie(AUTH_COOKIE, '', ['expires' => time() - 3600, 'path' => '/']);
}
function csrf(): string { return sign('csrf|' . (string)($_COOKIE[AUTH_COOKIE] ?? '')); }
function csrf_ok(): bool { return hash_equals(csrf(), (string)($_POST['csrf'] ?? '')); }

function flash(string $msg): void {
    setcookie('vl_flash', $msg, ['expires' => time() + 60, 'path' => '/', 'samesite' => 'Lax']);
}
function go(string $to = './'): void { header('Location: ' . $to); exit; }

/* ---------------- Logika penarikan video ---------------- */
function host_allowed(string $host, array $list): bool {
    $host = strtolower($host);
    foreach ($list as $d) {
        if ($host === $d || substr($host, -strlen($d) - 1) === '.' . $d) return true;
    }
    return false;
}

/** Cegah SSRF: host harus di whitelist & resolve ke IP publik. */
function url_safe(string $url, array $list): bool {
    $p = parse_url($url);
    if (!$p || empty($p['host']) || !in_array($p['scheme'] ?? '', ['http', 'https'], true)) return false;
    if (!host_allowed($p['host'], $list)) return false;
    $ip = gethostbyname($p['host']);
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

function http_get(string $url, bool $range = false): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER  => true,
        CURLOPT_FOLLOWLOCATION  => true,
        CURLOPT_MAXREDIRS       => 3,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT  => 8,
        CURLOPT_TIMEOUT         => 15,
        CURLOPT_USERAGENT       => UA,
        CURLOPT_ENCODING        => '',
        CURLOPT_HTTPHEADER      => $range ? ['Range: bytes=0-0'] : [],
        CURLOPT_MAXFILESIZE     => 3 * 1024 * 1024,
    ]);
    $body = curl_exec($ch);
    $info = [
        'code' => (int)curl_getinfo($ch, CURLINFO_HTTP_CODE),
        'type' => (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
        'url'  => (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL),
        'body' => $body === false ? '' : (string)$body,
    ];
    curl_close($ch);
    return $info;
}

function absolute_url(string $href, string $base): string {
    $href = html_entity_decode(str_replace('\\/', '/', $href));
    if (preg_match('~^https?://~i', $href)) return $href;
    $b = parse_url($base);
    $origin = $b['scheme'] . '://' . $b['host'];
    if (strpos($href, '//') === 0) return $b['scheme'] . ':' . $href;
    if ($href !== '' && $href[0] === '/') return $origin . $href;
    $dir = rtrim(dirname($b['path'] ?? '/'), '/');
    return $origin . $dir . '/' . $href;
}

function verify_video(string $url): bool {
    if (!url_safe($url, MEDIA_HOSTS)) return false;
    $r = http_get($url, true);
    if (!in_array($r['code'], [200, 206], true)) return false;
    $t = strtolower($r['type']);
    return strpos($t, 'video/') === 0 || strpos($t, 'application/octet-stream') === 0
        || strpos($t, 'mpegurl') !== false;
}

/** Dari link videy/aceimg -> direct URL video. */
function resolve_video(string $link): array {
    $link = trim($link);
    if (!url_safe($link, SOURCE_HOSTS)) {
        return ['ok' => false, 'error' => 'Link tidak valid atau domain tidak diizinkan (hanya videy.co & aceimg.com).'];
    }
    $p    = parse_url($link);
    $host = strtolower($p['host']);
    parse_str($p['query'] ?? '', $q);

    // 1) Link file video langsung
    if (preg_match('~\.(mp4|webm|m3u8)(\?|$)~i', $p['path'] ?? '')) {
        return verify_video($link)
            ? ['ok' => true, 'direct' => $link, 'title' => basename($p['path'])]
            : ['ok' => false, 'error' => 'File video tidak dapat diakses.'];
    }

    // 2) Pola videy: videy.co/v?id=XXXX -> cdn.videy.co/XXXX.mp4
    if (host_allowed($host, ['videy.co']) && !empty($q['id']) && preg_match('/^[A-Za-z0-9_-]{4,64}$/', $q['id'])) {
        $direct = 'https://cdn.videy.co/' . $q['id'] . '.mp4';
        if (verify_video($direct)) {
            return ['ok' => true, 'direct' => $direct, 'title' => 'videy-' . $q['id']];
        }
    }

    // 3) Scraping umum
    $page = http_get($link);
    if ($page['code'] !== 200 || $page['body'] === '') {
        return ['ok' => false, 'error' => 'Halaman sumber tidak bisa dibuka (HTTP ' . $page['code'] . ').'];
    }
    $html = $page['body'];
    $base = $page['url'] ?: $link;

    $patterns = [
        '~<meta[^>]+property=["\']og:video(?::secure_url|:url)?["\'][^>]+content=["\']([^"\']+)~i',
        '~<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:video~i',
        '~<source[^>]+src=["\']([^"\']+)~i',
        '~<video[^>]+src=["\']([^"\']+)~i',
        '~["\'](https?:\\\\?/\\\\?/[^"\'\s<>]+?\.(?:mp4|webm|m3u8)[^"\'\s<>]*)["\']~i',
    ];
    $found = [];
    foreach ($patterns as $re) {
        if (preg_match_all($re, $html, $m)) {
            foreach ($m[1] as $u) $found[] = absolute_url($u, $base);
        }
    }
    $found = array_values(array_unique($found));

    $title = 'Video';
    if (preg_match('~<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)~i', $html, $t)
        || preg_match('~<title>(.*?)</title>~is', $html, $t)) {
        $title = trim(html_entity_decode(strip_tags($t[1])));
    }
    foreach ($found as $cand) {
        if (verify_video($cand)) {
            return ['ok' => true, 'direct' => $cand, 'title' => mb_substr($title, 0, 120)];
        }
    }
    return ['ok' => false, 'error' => 'Tidak menemukan URL video di halaman tersebut. '
        . 'Jika CDN memakai domain lain, tambahkan ke MEDIA_HOSTS.'];
}

/* ---------------- Penyimpanan (JSON) ----------------
 * Format: {"folders": {id: {name, parent}}, "videos": {id: {title, source, direct, created, folder}}}
 * Format lama (daftar video saja) otomatis dimigrasikan saat dibaca.
 */
function load_db(): array {
    $d = is_file(DATA_FILE) ? json_decode((string)file_get_contents(DATA_FILE), true) : null;
    if (!is_array($d)) $d = [];
    if (!isset($d['videos']) && !isset($d['folders'])) {
        $d = ['folders' => [], 'videos' => $d];
    }
    $d['folders'] = is_array($d['folders'] ?? null) ? $d['folders'] : [];
    $d['videos']  = is_array($d['videos'] ?? null)  ? $d['videos']  : [];
    return $d;
}
function save_db(array $db): void {
    file_put_contents(DATA_FILE, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

/* ---------------- Helper folder ---------------- */
function fid(array $db, string $f): string {
    return ($f !== '' && isset($db['folders'][$f])) ? $f : '';
}
function folder_url(array $db, string $f): string {
    return fid($db, $f) !== '' ? '?f=' . rawurlencode($f) : './';
}
/** Jalur dari root ke folder: [[id, nama], ...] */
function folder_path(array $folders, string $f): array {
    $p = []; $g = 0;
    while ($f !== '' && isset($folders[$f]) && $g++ < 30) {
        array_unshift($p, [$f, (string)$folders[$f]['name']]);
        $f = (string)($folders[$f]['parent'] ?? '');
    }
    return $p;
}
/** Daftar datar semua folder (id => label berindent) untuk <select>. */
function folder_options(array $folders, string $parent = '', int $depth = 0): array {
    $kids = [];
    foreach ($folders as $id => $f) {
        if ((string)($f['parent'] ?? '') === $parent) $kids[$id] = $f;
    }
    uasort($kids, fn($a, $b) => strcasecmp((string)$a['name'], (string)$b['name']));
    $out = [];
    foreach ($kids as $id => $f) {
        $out[$id] = str_repeat('— ', $depth) . $f['name'];
        if ($depth < MAX_DEPTH + 2) $out += folder_options($folders, (string)$id, $depth + 1);
    }
    return $out;
}
function folder_select(array $db, string $name, string $selected, string $rootLabel, bool $auto = false): void {
    echo '<select name="' . e($name) . '"' . ($auto ? ' onchange="this.form.submit()"' : '') . '>';
    echo '<option value="">' . e($rootLabel) . '</option>';
    foreach (folder_options($db['folders']) as $id => $label) {
        echo '<option value="' . e((string)$id) . '"' . ((string)$id === $selected ? ' selected' : '') . '>' . e($label) . '</option>';
    }
    echo '</select>';
}

/* ======================= ACTIONS (POST) ======================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'login') {
        if (hash_equals(ADMIN_PASS, (string)($_POST['pass'] ?? ''))) {
            login_cookie();
            go('./');
        }
        sleep(1); // perlambat tebak password
        flash('Password salah.');
        go('./');
    }

    if (!is_admin() || !csrf_ok()) { flash('Sesi tidak valid. Silakan masuk lagi.'); go('./'); }

    if ($action === 'logout') { logout_cookie(); go('./'); }

    $db   = load_db();
    $back = fid($db, (string)($_POST['back'] ?? ''));

    if ($action === 'add') {
        $res = resolve_video((string)($_POST['link'] ?? ''));
        $folder = fid($db, (string)($_POST['folder'] ?? ''));
        if ($res['ok']) {
            $id     = substr(md5($res['direct']), 0, 10);
            $custom = trim((string)($_POST['title'] ?? ''));
            $db['videos'][$id] = [
                'title'   => $custom !== '' ? mb_substr($custom, 0, 120) : $res['title'],
                'source'  => trim((string)$_POST['link']),
                'direct'  => $res['direct'],
                'created' => date('c'),
                'folder'  => $folder,
            ];
            save_db($db);
            flash('Ditambahkan: ' . $db['videos'][$id]['title']);
        } else {
            flash('Gagal: ' . $res['error']);
        }
        go(folder_url($db, $folder));
    }

    if ($action === 'delete') {
        unset($db['videos'][(string)($_POST['id'] ?? '')]);
        save_db($db);
        flash('Video dihapus dari daftar.');
        go(folder_url($db, $back));
    }

    if ($action === 'move') {
        $id = (string)($_POST['id'] ?? '');
        if (isset($db['videos'][$id])) {
            $db['videos'][$id]['folder'] = fid($db, (string)($_POST['folder'] ?? ''));
            save_db($db);
            flash('Video dipindahkan.');
        }
        go(folder_url($db, $back));
    }

    if ($action === 'mkfolder') {
        $name   = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 60);
        $parent = fid($db, (string)($_POST['parent'] ?? ''));
        if ($name === '') {
            flash('Nama folder tidak boleh kosong.');
        } elseif (count(folder_path($db['folders'], $parent)) >= MAX_DEPTH) {
            flash('Kedalaman subfolder maksimum ' . MAX_DEPTH . ' tingkat.');
        } else {
            $id = 'f' . bin2hex(random_bytes(4));
            $db['folders'][$id] = ['name' => $name, 'parent' => $parent];
            save_db($db);
            flash('Folder dibuat: ' . $name);
        }
        go(folder_url($db, $parent));
    }

    if ($action === 'rename') {
        $id   = fid($db, (string)($_POST['id'] ?? ''));
        $name = mb_substr(trim((string)($_POST['name'] ?? '')), 0, 60);
        if ($id !== '' && $name !== '') {
            $db['folders'][$id]['name'] = $name;
            save_db($db);
            flash('Nama folder diubah.');
        }
        go(folder_url($db, $id));
    }

    if ($action === 'rmfolder') {
        $id = fid($db, (string)($_POST['id'] ?? ''));
        if ($id !== '') {
            $parent = (string)($db['folders'][$id]['parent'] ?? '');
            // isi folder dinaikkan ke folder induknya
            foreach ($db['folders'] as $k => $f) {
                if ((string)($f['parent'] ?? '') === $id) $db['folders'][$k]['parent'] = $parent;
            }
            foreach ($db['videos'] as $k => $v) {
                if ((string)($v['folder'] ?? '') === $id) $db['videos'][$k]['folder'] = $parent;
            }
            unset($db['folders'][$id]);
            save_db($db);
            flash('Folder dihapus. Isinya dipindah ke folder induk.');
            go(folder_url($db, $parent));
        }
        go('./');
    }
    go('./');
}

/* ======================= TAMPILAN ======================= */
$admin = is_admin();
$flash = (string)($_COOKIE['vl_flash'] ?? '');
if ($flash !== '') setcookie('vl_flash', '', ['expires' => time() - 3600, 'path' => '/']);

function page_start(string $title, bool $admin): void { ?>
<!doctype html>
<html lang="id"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow">
<title><?= e($title) ?></title>
<style>
:root{--bg:#fff;--fg:#000;--mute:#737373;--line:#e5e5e5;--soft:#f5f5f5}
@media (prefers-color-scheme:dark){:root{--bg:#000;--fg:#fff;--mute:#a3a3a3;--line:#262626;--soft:#111}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:inherit;text-decoration:none}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px}
header{border-bottom:1px solid var(--line)}
header .wrap{display:flex;align-items:center;justify-content:space-between;height:60px}
.brand{font-weight:700;letter-spacing:-.02em;font-size:18px}
nav.top{display:flex;align-items:center;gap:16px;color:var(--mute);font-size:14px}
main{padding:28px 0 64px}
h1{font-size:28px;letter-spacing:-.03em;margin:0 0 4px;overflow-wrap:anywhere}
.sub{color:var(--mute);margin:0 0 24px}
.crumbs{display:flex;flex-wrap:wrap;gap:6px;color:var(--mute);font-size:13px;margin:0 0 14px}
.crumbs a:hover{color:var(--fg)}
.crumbs b{color:var(--fg);font-weight:600}
input[type=text],input[type=url],input[type=password],input[type=search],select{
  width:100%;padding:11px 14px;background:var(--bg);color:var(--fg);
  border:1px solid var(--line);border-radius:8px;font:inherit;outline:none}
select{padding-right:8px}
input:focus,select:focus{border-color:var(--fg)}
button,.btn{display:inline-block;padding:11px 18px;background:var(--fg);color:var(--bg);
  border:1px solid var(--fg);border-radius:8px;font:inherit;font-weight:600;cursor:pointer;white-space:nowrap}
button:hover,.btn:hover{opacity:.85}
button.ghost{background:transparent;color:var(--fg);border-color:var(--line);font-weight:500;padding:7px 12px;font-size:13px}
button.ghost:hover{border-color:var(--fg);opacity:1}
button.link{background:none;border:0;padding:0;color:var(--mute);font-weight:400;font-size:14px}
button.link:hover{color:var(--fg);opacity:1}
.notice{border:1px solid var(--fg);border-radius:8px;padding:10px 14px;margin:0 0 20px;font-size:14px}
details.panel{border:1px solid var(--line);border-radius:12px;background:var(--soft);margin:0 0 10px}
details.panel>summary{cursor:pointer;padding:12px 16px;font-weight:600;font-size:14px;list-style:none}
details.panel>summary::-webkit-details-marker{display:none}
details.panel>summary:after{content:"+";float:right;color:var(--mute)}
details.panel[open]>summary:after{content:"\2013"}
.pbody{padding:0 16px 16px}
.fgrid4{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px}
.fgrid2{display:grid;grid-template-columns:1fr auto;gap:10px}
.inline{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.inline input{flex:1;min-width:160px}
@media(max-width:760px){.fgrid4,.fgrid2{grid-template-columns:1fr}}
.lbl{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mute);margin:26px 0 12px}
.bar{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:22px 0 0}
.bar input{max-width:320px}
.count{color:var(--mute);font-size:14px;white-space:nowrap}
.fgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px}
.fcard a{display:flex;gap:12px;align-items:center;padding:14px 16px;border:1px solid var(--line);border-radius:10px;height:100%}
.fcard a:hover{border-color:var(--fg)}
.fcard svg{flex:none}
.fname{font-weight:600;font-size:14px;overflow-wrap:anywhere}
.fcount{color:var(--mute);font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:20px}
.card{display:flex;flex-direction:column}
.thumb{position:relative;display:block;aspect-ratio:16/9;background:#000;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.thumb video{width:100%;height:100%;object-fit:cover;display:block;pointer-events:none}
.play{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity .15s;background:rgba(0,0,0,.35)}
.play i{width:44px;height:44px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center}
.play i:after{content:"";margin-left:3px;border-left:12px solid #000;border-top:8px solid transparent;border-bottom:8px solid transparent}
.thumb:hover .play{opacity:1}
.meta{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;padding-top:10px}
.meta .t{font-weight:600;font-size:14px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;word-break:break-word}
.meta .d{color:var(--mute);font-size:12px;margin-top:2px}
.move{margin-top:8px}
.move select{padding:6px 8px;font-size:13px}
.empty{border:1px dashed var(--line);border-radius:12px;padding:48px 20px;text-align:center;color:var(--mute);margin-top:24px}
.player video{width:100%;max-height:78vh;background:#000;border-radius:12px;display:block}
.pmeta{margin-top:16px}
.pmeta h1{font-size:22px}
.login{max-width:360px;margin:72px auto 0}
.login form{display:grid;gap:12px;margin-top:20px}
footer{border-top:1px solid var(--line);color:var(--mute);font-size:13px;padding:20px 0}
</style>
</head><body>
<header><div class="wrap">
  <a class="brand" href="./"><?= e(SITE_NAME) ?></a>
  <nav class="top">
  <?php if ($admin): ?>
    <form method="post" style="margin:0">
      <input type="hidden" name="action" value="logout">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <button class="link">Keluar</button>
    </form>
  <?php endif; ?>
  </nav>
</div></header>
<main><div class="wrap">
<?php }

function page_end(): void { ?>
</div></main>
<footer><div class="wrap"><?= e(SITE_NAME) ?></div></footer>
</body></html>
<?php }

function fmt_date(string $iso): string {
    $t = strtotime($iso);
    return $t ? date('d M Y', $t) : '';
}

/* ---------- Belum login: hanya tampil form masuk ---------- */
if (!$admin) {
    http_response_code(200);
    page_start('Masuk · ' . SITE_NAME, false); ?>
    <div class="login">
      <h1>Masuk</h1>
      <p class="sub">Halaman ini privat.</p>
      <?php if ($flash): ?><div class="notice"><?= e($flash) ?></div><?php endif; ?>
      <form method="post">
        <input type="hidden" name="action" value="login">
        <input type="password" name="pass" placeholder="Password" autofocus required autocomplete="current-password">
        <button>Masuk</button>
      </form>
    </div>
    <?php page_end(); exit;
}

$db = load_db();

/* ---------- Halaman pemutar ---------- */
if (isset($_GET['v'])) {
    $vid = $db['videos'][(string)$_GET['v']] ?? null;
    page_start(($vid['title'] ?? 'Tidak ditemukan') . ' · ' . SITE_NAME, true);
    if ($vid):
        $vf   = fid($db, (string)($vid['folder'] ?? ''));
        $path = folder_path($db['folders'], $vf); ?>
      <div class="crumbs">
        <a href="./">Beranda</a>
        <?php foreach ($path as [$pid, $pname]): ?> / <a href="?f=<?= e(rawurlencode($pid)) ?>"><?= e($pname) ?></a><?php endforeach; ?>
      </div>
      <div class="player">
        <video controls playsinline preload="metadata" referrerpolicy="no-referrer" autoplay>
          <source src="<?= e($vid['direct']) ?>">
          Browser Anda tidak mendukung pemutar video.
        </video>
        <div class="pmeta">
          <h1><?= e($vid['title']) ?></h1>
          <p class="sub"><?= e(fmt_date($vid['created'] ?? '')) ?> ·
            <a href="<?= e($vid['source']) ?>" target="_blank" rel="noopener noreferrer" style="text-decoration:underline">Sumber asli</a></p>
          <a class="btn" href="<?= e(folder_url($db, $vf)) ?>">← Kembali</a>
        </div>
      </div>
    <?php else: ?>
      <div class="empty">Video tidak ditemukan.<br><br><a class="btn" href="./">← Kembali</a></div>
    <?php endif;
    page_end(); exit;
}

/* ---------- Beranda / isi folder ---------- */
$cur = (string)($_GET['f'] ?? '');
if ($cur !== '' && !isset($db['folders'][$cur])) go('./');

$path = folder_path($db['folders'], $cur);

$subs = [];
foreach ($db['folders'] as $id => $f) {
    if ((string)($f['parent'] ?? '') === $cur) $subs[(string)$id] = $f;
}
uasort($subs, fn($a, $b) => strcasecmp((string)$a['name'], (string)$b['name']));

$vids = [];
foreach (array_reverse($db['videos'], true) as $id => $v) {
    if ((string)($v['folder'] ?? '') === $cur) $vids[(string)$id] = $v;
}

function folder_counts(array $db, string $f): string {
    $nv = 0; $nf = 0;
    foreach ($db['videos'] as $v)  if ((string)($v['folder'] ?? '') === $f) $nv++;
    foreach ($db['folders'] as $x) if ((string)($x['parent'] ?? '') === $f) $nf++;
    $parts = [$nv . ' video'];
    if ($nf) $parts[] = $nf . ' folder';
    return implode(' · ', $parts);
}

$title = $path ? end($path)[1] : SITE_NAME;
page_start($title . ' · ' . SITE_NAME, true);
?>
<div class="crumbs">
  <?php if ($path): ?>
    <a href="./">Beranda</a>
    <?php foreach ($path as $i => [$pid, $pname]): ?>
      / <?= $i === count($path) - 1 ? '<b>' . e($pname) . '</b>' : '<a href="?f=' . e(rawurlencode($pid)) . '">' . e($pname) . '</a>' ?>
    <?php endforeach; ?>
  <?php else: ?>
    <b>Beranda</b>
  <?php endif; ?>
</div>

<h1><?= e($title) ?></h1>
<p class="sub"><?= e(folder_counts($db, $cur)) ?></p>

<?php if ($flash): ?><div class="notice"><?= e($flash) ?></div><?php endif; ?>

<details class="panel" open>
  <summary>Tambah video</summary>
  <div class="pbody">
    <form class="fgrid4" method="post">
      <input type="hidden" name="action" value="add">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="url" name="link" placeholder="Tempel link videy.co / aceimg.com" required>
      <input type="text" name="title" placeholder="Judul (opsional)" maxlength="120">
      <?php folder_select($db, 'folder', $cur, 'Beranda (tanpa folder)'); ?>
      <button>Tambah</button>
    </form>
  </div>
</details>

<details class="panel">
  <summary>Folder baru<?= $path ? ' di “' . e($title) . '”' : '' ?></summary>
  <div class="pbody">
    <form class="inline" method="post">
      <input type="hidden" name="action" value="mkfolder">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="parent" value="<?= e($cur) ?>">
      <input type="text" name="name" placeholder="Nama folder" maxlength="60" required>
      <button>Buat folder</button>
    </form>
  </div>
</details>

<?php if ($cur !== ''): ?>
<details class="panel">
  <summary>Kelola folder ini</summary>
  <div class="pbody">
    <form class="inline" method="post">
      <input type="hidden" name="action" value="rename">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="id" value="<?= e($cur) ?>">
      <input type="text" name="name" value="<?= e($title) ?>" maxlength="60" required>
      <button>Ubah nama</button>
    </form>
    <form method="post" style="margin-top:12px"
          onsubmit="return confirm('Hapus folder ini? Video dan subfolder di dalamnya TIDAK dihapus, tetapi dipindah ke folder induk.')">
      <input type="hidden" name="action" value="rmfolder">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <input type="hidden" name="id" value="<?= e($cur) ?>">
      <button class="ghost">Hapus folder</button>
    </form>
  </div>
</details>
<?php endif; ?>

<?php if (!$subs && !$vids): ?>
  <div class="empty"><?= $cur === '' ? 'Belum ada video atau folder.' : 'Folder ini kosong.' ?></div>
<?php else: ?>

  <div class="bar">
    <input type="search" id="q" placeholder="Cari di halaman ini…" autocomplete="off">
    <span class="count"><span id="n"><?= count($vids) ?></span> video</span>
  </div>

  <?php if ($subs): ?>
    <div class="lbl">Folder</div>
    <div class="fgrid">
    <?php foreach ($subs as $id => $f): ?>
      <div class="fcard item" data-t="<?= e(mb_strtolower((string)$f['name'])) ?>">
        <a href="?f=<?= e(rawurlencode($id)) ?>">
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4.6l2 2.2H19.5A1.5 1.5 0 0 1 21 8.7v9.8a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/></svg>
          <div>
            <div class="fname"><?= e((string)$f['name']) ?></div>
            <div class="fcount"><?= e(folder_counts($db, $id)) ?></div>
          </div>
        </a>
      </div>
    <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <?php if ($vids): ?>
    <div class="lbl">Video</div>
    <div class="grid">
    <?php foreach ($vids as $id => $v): ?>
      <article class="card item vitem" data-t="<?= e(mb_strtolower((string)$v['title'])) ?>">
        <a class="thumb" href="?v=<?= e(rawurlencode($id)) ?>">
          <video muted playsinline preload="metadata" referrerpolicy="no-referrer" src="<?= e($v['direct']) ?>#t=0.5"></video>
          <span class="play"><i></i></span>
        </a>
        <div class="meta">
          <div>
            <a class="t" href="?v=<?= e(rawurlencode($id)) ?>"><?= e((string)$v['title']) ?></a>
            <div class="d"><?= e(fmt_date($v['created'] ?? '')) ?></div>
          </div>
          <form method="post" onsubmit="return confirm('Hapus video ini dari daftar?')" style="margin:0">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
            <input type="hidden" name="back" value="<?= e($cur) ?>">
            <input type="hidden" name="id" value="<?= e($id) ?>">
            <button class="ghost">Hapus</button>
          </form>
        </div>
        <form class="move" method="post">
          <input type="hidden" name="action" value="move">
          <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
          <input type="hidden" name="back" value="<?= e($cur) ?>">
          <input type="hidden" name="id" value="<?= e($id) ?>">
          <?php folder_select($db, 'folder', (string)($v['folder'] ?? ''), 'Pindah ke: Beranda', true); ?>
        </form>
      </article>
    <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <script>
  (function(){
    var q=document.getElementById('q'),n=document.getElementById('n'),
        items=[].slice.call(document.querySelectorAll('.item'));
    q.addEventListener('input',function(){
      var s=q.value.trim().toLowerCase(),c=0;
      items.forEach(function(el){
        var ok=el.getAttribute('data-t').indexOf(s)!==-1;
        el.style.display=ok?'':'none';
        if(ok&&el.classList.contains('vitem'))c++;
      });
      n.textContent=c;
    });
  })();
  </script>
<?php endif;
page_end();
