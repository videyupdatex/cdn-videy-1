<?php
/**
 * Remote Video Link Gallery (videy.co / aceimg.com)
 * - Video TIDAK diunduh / disimpan; hanya metadata (link + direct URL) di videos.json.
 * - Pengunjung: melihat galeri & memutar video.
 * - Admin: login sekali (cookie 30 hari), lalu bisa tambah / hapus video.
 *
 * Environment variable (Railway):
 *   ADMIN_PASS = password admin
 *   DATA_DIR   = /data   (lokasi Volume agar videos.json permanen)
 */
declare(strict_types=1);

/* ================= KONFIGURASI ================= */
define('ADMIN_PASS', getenv('ADMIN_PASS') ?: 'ganti-password-ini');
define('DATA_FILE', rtrim(getenv('DATA_DIR') ?: __DIR__, '/') . '/videos.json');
define('AUTH_COOKIE', 'vl_auth');
define('LOGIN_DAYS', 30);
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

/* ---------------- Penyimpanan (JSON) ---------------- */
function load_db(): array {
    if (!is_file(DATA_FILE)) return [];
    $d = json_decode((string)file_get_contents(DATA_FILE), true);
    return is_array($d) ? $d : [];
}
function save_db(array $db): void {
    file_put_contents(DATA_FILE, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
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
        go('?login');
    }

    if (!is_admin() || !csrf_ok()) { flash('Sesi tidak valid. Silakan masuk lagi.'); go('?login'); }

    if ($action === 'logout') { logout_cookie(); go('./'); }

    if ($action === 'add') {
        $res = resolve_video((string)($_POST['link'] ?? ''));
        if ($res['ok']) {
            $db  = load_db();
            $id  = substr(md5($res['direct']), 0, 10);
            $custom = trim((string)($_POST['title'] ?? ''));
            $db[$id] = [
                'title'   => $custom !== '' ? mb_substr($custom, 0, 120) : $res['title'],
                'source'  => trim((string)$_POST['link']),
                'direct'  => $res['direct'],
                'created' => date('c'),
            ];
            save_db($db);
            flash('Ditambahkan: ' . $db[$id]['title']);
        } else {
            flash('Gagal: ' . $res['error']);
        }
        go('./');
    }

    if ($action === 'delete') {
        $db = load_db();
        unset($db[(string)($_POST['id'] ?? '')]);
        save_db($db);
        flash('Video dihapus dari daftar.');
        go('./');
    }
    go('./');
}

/* ======================= TAMPILAN ======================= */
$admin = is_admin();
$flash = (string)($_COOKIE['vl_flash'] ?? '');
if ($flash !== '') setcookie('vl_flash', '', ['expires' => time() - 3600, 'path' => '/']);
$db = load_db();

function page_start(string $title, bool $admin): void { ?>
<!doctype html>
<html lang="id"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
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
nav{display:flex;align-items:center;gap:16px;color:var(--mute);font-size:14px}
nav a:hover{color:var(--fg)}
main{padding:32px 0 64px}
h1{font-size:28px;letter-spacing:-.03em;margin:0 0 4px}
.sub{color:var(--mute);margin:0 0 24px}
input[type=text],input[type=url],input[type=password],input[type=search]{
  width:100%;padding:11px 14px;background:var(--bg);color:var(--fg);
  border:1px solid var(--line);border-radius:8px;font:inherit;outline:none}
input:focus{border-color:var(--fg)}
button,.btn{display:inline-block;padding:11px 18px;background:var(--fg);color:var(--bg);
  border:1px solid var(--fg);border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
button:hover,.btn:hover{opacity:.85}
button.ghost{background:transparent;color:var(--fg);border-color:var(--line);font-weight:500;padding:7px 12px;font-size:13px}
button.ghost:hover{border-color:var(--fg);opacity:1}
button.link{background:none;border:0;padding:0;color:var(--mute);font-weight:400;font-size:14px}
button.link:hover{color:var(--fg);opacity:1}
.notice{border:1px solid var(--fg);border-radius:8px;padding:10px 14px;margin:0 0 20px;font-size:14px}
.add{display:grid;grid-template-columns:2fr 1fr auto;gap:10px;margin:0 0 32px;padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--soft)}
@media(max-width:720px){.add{grid-template-columns:1fr}}
.bar{display:flex;gap:12px;align-items:center;justify-content:space-between;margin:0 0 20px}
.bar input{max-width:320px}
.count{color:var(--mute);font-size:14px;white-space:nowrap}
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
.empty{border:1px dashed var(--line);border-radius:12px;padding:48px 20px;text-align:center;color:var(--mute)}
.player video{width:100%;max-height:78vh;background:#000;border-radius:12px;display:block}
.pmeta{margin-top:16px}
.pmeta h1{font-size:22px}
.login{max-width:360px;margin:64px auto 0}
.login form{display:grid;gap:12px;margin-top:20px}
footer{border-top:1px solid var(--line);color:var(--mute);font-size:13px;padding:20px 0}
</style>
</head><body>
<header><div class="wrap">
  <a class="brand" href="./"><?= e(SITE_NAME) ?></a>
  <nav>
  <?php if ($admin): ?>
    <span>Admin</span>
    <form method="post" style="margin:0">
      <input type="hidden" name="action" value="logout">
      <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
      <button class="link">Keluar</button>
    </form>
  <?php else: ?>
    <a href="?login">Masuk</a>
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

/* ---------- Halaman login ---------- */
if (isset($_GET['login'])) {
    if ($admin) go('./');
    page_start('Masuk · ' . SITE_NAME, false); ?>
    <div class="login">
      <h1>Masuk</h1>
      <p class="sub">Khusus admin.</p>
      <?php if ($flash): ?><div class="notice"><?= e($flash) ?></div><?php endif; ?>
      <form method="post">
        <input type="hidden" name="action" value="login">
        <input type="password" name="pass" placeholder="Password" autofocus required autocomplete="current-password">
        <button>Masuk</button>
      </form>
    </div>
    <?php page_end(); exit;
}

/* ---------- Halaman pemutar ---------- */
if (isset($_GET['v'])) {
    $vid = $db[(string)$_GET['v']] ?? null;
    page_start(($vid['title'] ?? 'Tidak ditemukan') . ' · ' . SITE_NAME, $admin);
    if ($vid): ?>
      <div class="player">
        <video controls playsinline preload="metadata" referrerpolicy="no-referrer" autoplay>
          <source src="<?= e($vid['direct']) ?>">
          Browser Anda tidak mendukung pemutar video.
        </video>
        <div class="pmeta">
          <h1><?= e($vid['title']) ?></h1>
          <p class="sub"><?= e(fmt_date($vid['created'] ?? '')) ?>
            <?php if ($admin): ?> · <a href="<?= e($vid['source']) ?>" target="_blank" rel="noopener noreferrer" style="text-decoration:underline">Sumber asli</a><?php endif; ?>
          </p>
          <a class="btn" href="./">← Semua video</a>
        </div>
      </div>
    <?php else: ?>
      <div class="empty">Video tidak ditemukan.<br><br><a class="btn" href="./">← Kembali</a></div>
    <?php endif;
    page_end(); exit;
}

/* ---------- Beranda (galeri) ---------- */
page_start(SITE_NAME, $admin);
?>
<h1><?= e(SITE_NAME) ?></h1>
<p class="sub">Koleksi video.</p>

<?php if ($flash): ?><div class="notice"><?= e($flash) ?></div><?php endif; ?>

<?php if ($admin): ?>
<form class="add" method="post">
  <input type="hidden" name="action" value="add">
  <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
  <input type="url" name="link" placeholder="Tempel link videy.co / aceimg.com" required>
  <input type="text" name="title" placeholder="Judul (opsional)" maxlength="120">
  <button>Tambah</button>
</form>
<?php endif; ?>

<?php if (!$db): ?>
  <div class="empty">Belum ada video.</div>
<?php else: ?>
  <div class="bar">
    <input type="search" id="q" placeholder="Cari video…" autocomplete="off">
    <span class="count"><span id="n"><?= count($db) ?></span> video</span>
  </div>
  <div class="grid" id="grid">
  <?php foreach (array_reverse($db, true) as $id => $v): ?>
    <article class="card" data-t="<?= e(mb_strtolower($v['title'])) ?>">
      <a class="thumb" href="?v=<?= e((string)$id) ?>">
        <video muted playsinline preload="metadata" referrerpolicy="no-referrer" src="<?= e($v['direct']) ?>#t=0.5"></video>
        <span class="play"><i></i></span>
      </a>
      <div class="meta">
        <div>
          <a class="t" href="?v=<?= e((string)$id) ?>"><?= e($v['title']) ?></a>
          <div class="d"><?= e(fmt_date($v['created'] ?? '')) ?></div>
        </div>
        <?php if ($admin): ?>
        <form method="post" onsubmit="return confirm('Hapus video ini dari daftar?')" style="margin:0">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="csrf" value="<?= e(csrf()) ?>">
          <input type="hidden" name="id" value="<?= e((string)$id) ?>">
          <button class="ghost">Hapus</button>
        </form>
        <?php endif; ?>
      </div>
    </article>
  <?php endforeach; ?>
  </div>
  <script>
  (function(){
    var q=document.getElementById('q'),n=document.getElementById('n'),
        cards=[].slice.call(document.querySelectorAll('.card'));
    q.addEventListener('input',function(){
      var s=q.value.trim().toLowerCase(),c=0;
      cards.forEach(function(el){
        var ok=el.getAttribute('data-t').indexOf(s)!==-1;
        el.style.display=ok?'':'none'; if(ok)c++;
      });
      n.textContent=c;
    });
  })();
  </script>
<?php endif;
page_end();
