<?php
/**
 * Remote Video Link Importer (videy.co / aceimg.com)
 * - Tidak mengunduh / menyimpan file video di hosting.
 * - Hanya menyimpan metadata (link sumber + direct URL) di videos.json.
 * - Video diputar langsung dari server sumber lewat <video>.
 *
 * Cara pakai: taruh file ini + (otomatis dibuat) videos.json di hosting PHP 7.4+
 * dengan ekstensi cURL aktif. Pastikan folder bisa ditulis oleh PHP.
 */
declare(strict_types=1);
session_start();

/* ================= KONFIGURASI ================= */
// Di Railway: set variabel ADMIN_PASS dan DATA_DIR (mis. /data, lokasi Volume)
define('ADMIN_PASS', getenv('ADMIN_PASS') ?: 'ganti-password-ini');
define('DATA_FILE', rtrim(getenv('DATA_DIR') ?: __DIR__, '/') . '/videos.json');
// Domain halaman sumber yang boleh dibaca
const SOURCE_HOSTS   = ['videy.co', 'aceimg.com'];
// Domain file video (CDN) yang boleh dipakai. Tambahkan jika CDN aceimg memakai domain lain.
const MEDIA_HOSTS    = ['videy.co', 'aceimg.com'];
const UA             = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36';
/* ================================================ */

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

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

/** HTTP GET sederhana. $range true = hanya ambil 1 byte (untuk cek file). */
function http_get(string $url, bool $range = false): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_USERAGENT      => UA,
        CURLOPT_ENCODING       => '',
        CURLOPT_HTTPHEADER     => $range ? ['Range: bytes=0-0'] : [],
        CURLOPT_MAXFILESIZE    => 3 * 1024 * 1024, // halaman HTML max 3MB
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

/** Cek apakah URL benar-benar file video yang bisa diakses. */
function verify_video(string $url): bool {
    if (!url_safe($url, MEDIA_HOSTS)) return false;
    $r = http_get($url, true);
    if (!in_array($r['code'], [200, 206], true)) return false;
    $t = strtolower($r['type']);
    return strpos($t, 'video/') === 0 || strpos($t, 'application/octet-stream') === 0
        || strpos($t, 'mpegurl') !== false;
}

/**
 * LOGIKA UTAMA: dari link videy/aceimg -> direct URL video.
 * @return array{ok:bool, direct?:string, title?:string, error?:string}
 */
function resolve_video(string $link): array {
    $link = trim($link);
    if (!url_safe($link, SOURCE_HOSTS)) {
        return ['ok' => false, 'error' => 'Link tidak valid / domain tidak diizinkan (hanya videy.co & aceimg.com).'];
    }
    $p    = parse_url($link);
    $host = strtolower($p['host']);
    parse_str($p['query'] ?? '', $q);

    // 1) Link sudah berupa file video langsung
    if (preg_match('~\.(mp4|webm|m3u8)(\?|$)~i', $p['path'] ?? '')) {
        return verify_video($link)
            ? ['ok' => true, 'direct' => $link, 'title' => basename($p['path'])]
            : ['ok' => false, 'error' => 'File video tidak dapat diakses.'];
    }

    // 2) Pola khusus videy: videy.co/v?id=XXXX  ->  cdn.videy.co/XXXX.mp4
    if (host_allowed($host, ['videy.co']) && !empty($q['id']) && preg_match('/^[A-Za-z0-9_-]{4,64}$/', $q['id'])) {
        $direct = 'https://cdn.videy.co/' . $q['id'] . '.mp4';
        if (verify_video($direct)) {
            return ['ok' => true, 'direct' => $direct, 'title' => 'videy-' . $q['id']];
        }
        // jika pola berubah, lanjut ke scraping umum di bawah
    }

    // 3) Scraping umum: baca halaman, cari og:video / <source> / <video> / URL .mp4
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

/* ============ Penyimpanan metadata (JSON) ============ */
function load_db(): array {
    if (!is_file(DATA_FILE)) return [];
    $d = json_decode((string)file_get_contents(DATA_FILE), true);
    return is_array($d) ? $d : [];
}
function save_db(array $db): void {
    file_put_contents(DATA_FILE, json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

/* ================== Routing ================== */
$db  = load_db();
$msg = '';
$csrf = $_SESSION['csrf'] ??= bin2hex(random_bytes(16));

// --- Halaman player ---
if (isset($_GET['v'])) {
    $vid = $db[$_GET['v']] ?? null;
    ?><!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title><?= e($vid['title'] ?? 'Video tidak ditemukan') ?></title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:20px auto;padding:0 12px}video{width:100%;background:#000;border-radius:8px}</style>
</head><body>
<?php if ($vid): ?>
  <h1><?= e($vid['title']) ?></h1>
  <video controls playsinline preload="metadata" referrerpolicy="no-referrer">
    <source src="<?= e($vid['direct']) ?>">
    Browser tidak mendukung video.
  </video>
  <p><a href="<?= e($vid['source']) ?>" rel="noopener noreferrer" target="_blank">Sumber asli</a> · <a href="./">Kembali</a></p>
<?php else: ?>
  <p>Video tidak ditemukan. <a href="./">Kembali</a></p>
<?php endif; ?>
</body></html><?php
    exit;
}

// --- Aksi tambah / hapus ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
        $msg = 'Token tidak valid.';
    } elseif (!hash_equals(ADMIN_PASS, (string)($_POST['pass'] ?? ''))) {
        $msg = 'Password salah.';
    } elseif (($_POST['action'] ?? '') === 'add') {
        $res = resolve_video((string)($_POST['link'] ?? ''));
        if ($res['ok']) {
            $id = substr(md5($res['direct']), 0, 10);
            $db[$id] = [
                'title'   => $res['title'],
                'source'  => trim((string)$_POST['link']),
                'direct'  => $res['direct'],
                'created' => date('c'),
            ];
            save_db($db);
            $msg = 'Berhasil ditambahkan: ' . $res['title'];
        } else {
            $msg = 'Gagal: ' . $res['error'];
        }
    } elseif (($_POST['action'] ?? '') === 'delete') {
        unset($db[$_POST['id'] ?? '']);
        save_db($db);
        $msg = 'Video dihapus dari daftar (file asli tidak terpengaruh).';
    }
}
?><!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Video via Link</title>
<style>
body{font-family:system-ui,sans-serif;max-width:800px;margin:20px auto;padding:0 12px}
input{padding:8px;margin:4px 0;width:100%;box-sizing:border-box}
button{padding:8px 14px;cursor:pointer}
.msg{background:#eef;padding:8px;border-radius:6px;margin:10px 0}
li{margin:8px 0}
</style></head><body>
<h1>Tambah Video via Link</h1>
<?php if ($msg): ?><div class="msg"><?= e($msg) ?></div><?php endif; ?>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <input type="hidden" name="action" value="add">
  <input name="link" placeholder="https://videy.co/v?id=xxxx atau link aceimg.com" required>
  <input type="password" name="pass" placeholder="Password admin" required>
  <button>Tambah</button>
</form>

<h2>Daftar Video</h2>
<ul>
<?php foreach (array_reverse($db, true) as $id => $v): ?>
  <li>
    <a href="?v=<?= e($id) ?>"><?= e($v['title']) ?></a>
    <form method="post" style="display:inline" onsubmit="return confirm('Hapus dari daftar?')">
      <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="<?= e($id) ?>">
      <input type="password" name="pass" placeholder="password" style="width:120px" required>
      <button>Hapus</button>
    </form>
  </li>
<?php endforeach; ?>
<?php if (!$db): ?><li>Belum ada video.</li><?php endif; ?>
</ul>
</body></html>