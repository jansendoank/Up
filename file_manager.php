<?php
/**
 * Single-File PHP File Manager untuk Kelola Berkas Web Hosting InfinityFree
 * Dilengkapi visual editor berbasis Ace Editor, pembuatan file baru,
 * pengunggahan file, penghapusan file/folder, serta enkripsi proteksi password yang handal.
 */

session_start();
ini_set('display_errors', 0);
error_reporting(E_ALL);

$base_dir = __DIR__;

/**
 * Fungsi rekursif untuk menghapus folder beserta seluruh isinya dengan aman
 */
function deleteDirectoryRecursive($dir) {
    if (!file_exists($dir)) return true;
    if (!is_dir($dir)) return @unlink($dir);
    $items = scandir($dir);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($path)) {
            if (!deleteDirectoryRecursive($path)) return false;
        } else {
            if (!@unlink($path)) return false;
        }
    }
    return @rmdir($dir);
}

/**
 * Keamanan Anti-Hack: Hanya izinkan ekstensi berkas web statis yang aman.
 * Menolak keras file PHP, CGI, shell script, atau backdoor eksekusi server.
 */
function is_safe_web_extension($filename) {
    $dangerous = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'inc', 'sh', 'bash', 'py', 'pl', 'cgi', 'exe', 'bat', 'cmd', 'htaccess', 'htpasswd', 'env', 'config', 'ini'];
    $basename = basename(strtolower($filename));
    
    if (strpos($basename, '.') === 0) {
        return false;
    }
    
    $parts = explode('.', $basename);
    if (count($parts) < 2) {
        return false;
    }
    
    foreach ($parts as $part) {
        if (in_array(trim($part), $dangerous, true)) {
            return false;
        }
    }
    
    $ext = end($parts);
    $allowed = [
        'html', 'htm', 'css', 'js', 'json', 'txt', 'svg', 'png', 'jpg', 'jpeg', 
        'gif', 'webp', 'ico', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'mp3', 'mp4', 
        'webm', 'ogg', 'wav', 'pdf', 'xml', 'md', 'csv'
    ];
    
    return in_array($ext, $allowed, true);
}

// Penanganan Logout
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    unset($_SESSION['ifree_logged_in'], $_SESSION['ifree_site_id']);
    unset($_SESSION['cwp_logged_in'], $_SESSION['cwp_site_id']);
    header('Location: file_manager.php');
    exit;
}

// Proses Login Otorisasi
$auth_err = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_submit'])) {
    $site_id = preg_replace('/[^a-zA-Z0-9\-_]/', '', isset($_POST['site_id']) ? (string)$_POST['site_id'] : '');
    $site_id = strtolower(trim($site_id));
    $password = isset($_POST['password']) ? trim((string)$_POST['password']) : '';

    if (empty($site_id) || empty($password)) {
        $auth_err = 'Nama website (Subfolder) dan Password wajib diisi.';
    } else {
        $target_dir = $base_dir . '/' . $site_id;
        $meta_file = $target_dir . '/.metadata.json';
        $lock_file = $target_dir . '/.password_lock';

        if (!file_exists($target_dir)) {
            $auth_err = 'Folder website tidak ditemukan di hosting ini. Silakan buat dulu di halaman utama.';
        } else {
            // Verifikasi Password
            $authorized = false;
            if (file_exists($meta_file)) {
                $raw = @file_get_contents($meta_file);
                $meta = json_decode($raw, true);
                if ($meta && isset($meta['password_hash'])) {
                    if (password_verify($password, $meta['password_hash'])) {
                        $authorized = true;
                    }
                }
            }
            
            // Fallback plain key checking
            if (!$authorized && file_exists($lock_file)) {
                $stored = trim((string)@file_get_contents($lock_file));
                if (hash_equals($stored, $password)) {
                    $authorized = true;
                }
            }

            if ($authorized) {
                $_SESSION['ifree_logged_in'] = true;
                $_SESSION['ifree_site_id'] = $site_id;
                header('Location: file_manager.php');
                exit;
            } else {
                $auth_err = 'Password salah! Pastikan menggunakan password yang dibuat saat mendaftarkan subfolder.';
            }
        }
    }
}

// Pre-fill site_id dari URL query parameter jika ada (?siteId=xxx)
$prefill_site_id = isset($_GET['siteId']) ? preg_replace('/[^a-zA-Z0-9\-_]/', '', $_GET['siteId']) : '';

// Cek apakah user sedang login
$is_logged_in = (isset($_SESSION['ifree_logged_in']) && $_SESSION['ifree_logged_in'] === true) || (isset($_SESSION['cwp_logged_in']) && $_SESSION['cwp_logged_in'] === true);

if (!$is_logged_in) {
    // TAMPILKAN PAGE LOGIN JIKA BELUM TERAUTENTIKASI
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login Pengelola Berkas - Web ku</title>
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: #6366f1;
                --primary-hover: #4f46e5;
                --bg-dark: #0b0f19;
                --text-muted: #94a3b8;
            }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                background-color: var(--bg-dark);
                color: #f1f5f9;
                font-family: 'Inter', system-ui, sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                background-image: 
                    radial-gradient(circle at 15% 15%, rgba(99, 102, 241, 0.15) 0%, transparent 45%),
                    radial-gradient(circle at 85% 85%, rgba(14, 165, 233, 0.12) 0%, transparent 45%),
                    radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.06) 0%, transparent 60%);
                background-attachment: fixed;
            }
            .glass-neo-elevated {
                background: rgba(22, 30, 48, 0.72);
                backdrop-filter: blur(22px) saturate(190%);
                -webkit-backdrop-filter: blur(22px) saturate(190%);
                border-top: 1px solid rgba(255, 255, 255, 0.22);
                border-left: 1px solid rgba(255, 255, 255, 0.15);
                border-right: 1px solid rgba(0, 0, 0, 0.4);
                border-bottom: 1px solid rgba(0, 0, 0, 0.6);
                box-shadow: 
                    -8px -8px 22px rgba(255, 255, 255, 0.04),
                    14px 18px 36px rgba(0, 0, 0, 0.65),
                    inset 0 1px 2px rgba(255, 255, 255, 0.2);
            }
            .glass-neo-inset {
                background: rgba(10, 14, 24, 0.7);
                backdrop-filter: blur(12px);
                border-top: 1px solid rgba(0, 0, 0, 0.6);
                border-left: 1px solid rgba(0, 0, 0, 0.5);
                border-right: 1px solid rgba(255, 255, 255, 0.06);
                border-bottom: 1px solid rgba(255, 255, 255, 0.09);
                box-shadow: 
                    inset 4px 4px 10px rgba(0, 0, 0, 0.65),
                    inset -3px -3px 8px rgba(255, 255, 255, 0.03);
            }
            .glass-neo-btn-primary {
                background: linear-gradient(135deg, rgba(99, 102, 241, 0.85) 0%, rgba(79, 70, 229, 0.85) 100%);
                backdrop-filter: blur(14px);
                border-top: 1px solid rgba(255, 255, 255, 0.35);
                border-left: 1px solid rgba(255, 255, 255, 0.25);
                border-right: 1px solid rgba(0, 0, 0, 0.35);
                border-bottom: 1px solid rgba(0, 0, 0, 0.5);
                box-shadow: 
                    -4px -4px 12px rgba(99, 102, 241, 0.15),
                    6px 10px 22px rgba(0, 0, 0, 0.5),
                    inset 0 1px 1px rgba(255, 255, 255, 0.3);
                color: white;
                cursor: pointer;
                transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            }
            .glass-neo-btn-primary:hover {
                background: linear-gradient(135deg, rgba(129, 140, 248, 0.9) 0%, rgba(99, 102, 241, 0.9) 100%);
                transform: translateY(-1px);
            }
            .login-card {
                border-radius: 24px;
                padding: 36px;
                width: 100%;
                max-width: 440px;
            }
            .login-header {
                text-align: center;
                margin-bottom: 28px;
            }
            .login-header h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 24px;
                font-weight: 700;
                color: white;
                margin-bottom: 6px;
                text-shadow: 0 2px 10px rgba(255, 255, 255, 0.15);
            }
            .login-header p {
                font-size: 13px;
                color: var(--text-muted);
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                font-size: 12px;
                font-weight: 700;
                color: #cbd5e1;
                margin-bottom: 6px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            input {
                width: 100%;
                background: transparent;
                border: none;
                padding: 12px 14px;
                color: white;
                font-size: 14px;
                outline: none;
            }
            .btn-login {
                width: 100%;
                border-radius: 12px;
                padding: 13px;
                font-weight: 700;
                font-size: 14px;
                margin-top: 6px;
            }
            .error-alert {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #fca5a5;
                padding: 10px 14px;
                border-radius: 10px;
                font-size: 13px;
                margin-bottom: 18px;
                line-height: 1.4;
            }
            .foot-link {
                text-align: center;
                margin-top: 20px;
                font-size: 13px;
            }
            .foot-link a {
                color: #818cf8;
                text-decoration: none;
            }
            .foot-link a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="login-card glass-neo-elevated">
            <div class="login-header">
                <h1>📁 Pengelola Berkas Web</h1>
                <p>Kelola file HTML, CSS, JS, dan gambar di subfolder situs Anda</p>
            </div>

            <?php if (!empty($auth_err)): ?>
                <div class="error-alert">⚠️ <?= htmlspecialchars($auth_err) ?></div>
            <?php endif; ?>

            <form action="file_manager.php" method="POST">
                <div class="form-group">
                    <label>Nama Subfolder Website (Site ID)</label>
                    <div class="glass-neo-inset" style="border-radius: 12px;">
                        <input type="text" name="site_id" required value="<?= htmlspecialchars($prefill_site_id) ?>" placeholder="contoh: portofolioku" autocomplete="off">
                    </div>
                </div>

                <div class="form-group">
                    <label>Password Keamanan</label>
                    <div class="glass-neo-inset" style="border-radius: 12px;">
                        <input type="password" name="password" required placeholder="Masukkan password pengunci">
                    </div>
                </div>

                <button type="submit" name="login_submit" class="btn-login glass-neo-btn-primary">Verifikasi & Buka Berkas</button>
            </form>

            <div class="foot-link">
                <a href="index.html">&larr; Kembali ke halaman hosting</a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}


// ==========================================
// SESI BERHASIL MASUK (AUTHORIZED VIEW)
// ==========================================

$site_id = isset($_SESSION['ifree_site_id']) ? $_SESSION['ifree_site_id'] : (isset($_SESSION['cwp_site_id']) ? $_SESSION['cwp_site_id'] : '');
$site_dir = $base_dir . '/' . $site_id;

// Proteksi jika folder dihapus secara manual setelah login
if (!file_exists($site_dir)) {
    unset($_SESSION['ifree_logged_in'], $_SESSION['ifree_site_id'], $_SESSION['cwp_logged_in'], $_SESSION['cwp_site_id']);
    header('Location: file_manager.php');
    exit;
}

// Handler AJAX API untuk membaca berkas, menyimpan, membuat file/folder, mengunggah, dan menghapus berkas
if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    $api_action = $_GET['api'];

    // 1. Dapatkan konten file
    if ($api_action === 'get_file') {
        $file = isset($_GET['file']) ? trim($_GET['file']) : '';
        if (strpos($file, '..') !== false || strpos($file, '/') === 0 || strpos($file, '\\') === 0) {
            echo json_encode(['error' => 'Akses berkas tidak diizinkan.']);
            exit;
        }

        $full_file_path = $site_dir . '/' . $file;
        if (file_exists($full_file_path) && !is_dir($full_file_path)) {
            echo json_encode([
                'success' => true,
                'content' => file_get_contents($full_file_path)
            ]);
        } else {
            echo json_encode(['error' => 'Berkas tidak ditemukan atau merupakan folder.']);
        }
        exit;
    }

    // 2. Simpan perubahan konten file
    if ($api_action === 'save_file' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        $file = isset($input['file']) ? trim($input['file']) : '';
        $content = isset($input['content']) ? $input['content'] : '';

        if (strpos($file, '..') !== false || strpos($file, '/') === 0 || empty($file)) {
            echo json_encode(['error' => 'Izin menulis berkas ditolak.']);
            exit;
        }

        if ($file === '.metadata.json' || $file === '.password_lock' || $file === '.htaccess') {
            echo json_encode(['error' => 'Izin ditolak untuk memodifikasi konfigurasi keamanan sistem.']);
            exit;
        }

        if (!is_safe_web_extension($file)) {
            echo json_encode(['error' => 'Ekstensi file ini diblokir demi keamanan server.']);
            exit;
        }

        $full_file_path = $site_dir . '/' . $file;
        if (@file_put_contents($full_file_path, $content) !== false) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['error' => 'Gagal menulis berkas. Cek hak akses direktori hosting.']);
        }
        exit;
    }

    // 3. Buat file baru
    if ($api_action === 'create_file' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        $filename = isset($input['filename']) ? trim($input['filename']) : '';

        if (strpos($filename, '..') !== false || strpos($filename, '/') === 0 || empty($filename)) {
            echo json_encode(['error' => 'Nama file tidak valid.']);
            exit;
        }

        if ($filename === '.metadata.json' || $filename === '.password_lock' || $filename === '.htaccess') {
            echo json_encode(['error' => 'Nama file tersebut dicadangkan untuk keamanan sistem.']);
            exit;
        }

        if (!is_safe_web_extension($filename)) {
            echo json_encode(['error' => 'Demi keamanan, hanya file web statis (.html, .css, .js, .json, .txt) yang diizinkan dibuat.']);
            exit;
        }

        $full_path = $site_dir . '/' . $filename;
        if (file_exists($full_path)) {
            echo json_encode(['error' => 'Berkas dengan nama tersebut sudah ada.']);
            exit;
        }

        $dir = dirname($full_path);
        if (!file_exists($dir)) {
            @mkdir($dir, 0755, true);
        }

        if (@file_put_contents($full_path, '') !== false) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['error' => 'Gagal membuat berkas baru.']);
        }
        exit;
    }

    // 4. Hapus file / folder
    if ($api_action === 'delete_file' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        $file = isset($input['file']) ? trim($input['file']) : '';

        if (strpos($file, '..') !== false || strpos($file, '/') === 0 || empty($file)) {
            echo json_encode(['error' => 'Izin menghapus ditolak.']);
            exit;
        }

        if ($file === '.metadata.json' || $file === '.password_lock' || $file === '.htaccess') {
            echo json_encode(['error' => 'File keamanan dilindungi dan dilarang untuk dihapus.']);
            exit;
        }

        $full_path = $site_dir . '/' . $file;
        if (file_exists($full_path)) {
            if (is_dir($full_path)) {
                if (deleteDirectoryRecursive($full_path)) {
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['error' => 'Gagal menghapus folder.']);
                }
            } else {
                if (@unlink($full_path)) {
                    echo json_encode(['success' => true]);
                } else {
                    echo json_encode(['error' => 'Gagal menghapus berkas.']);
                }
            }
        } else {
            echo json_encode(['error' => 'Berkas atau folder tidak ditemukan.']);
        }
        exit;
    }

    // 5. Upload file individu
    if ($api_action === 'upload_file' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            echo json_encode(['error' => 'Gagal mengunggah berkas.']);
            exit;
        }

        $original_name = basename($_FILES['file']['name']);
        if ($original_name === '.metadata.json' || $original_name === '.password_lock' || $original_name === '.htaccess') {
            echo json_encode(['error' => 'Nama file tidak diizinkan.']);
            exit;
        }

        if (!is_safe_web_extension($original_name)) {
            echo json_encode(['error' => 'Demi keamanan hosting, file script server (.php, .sh, .cgi, dll) dilarang diunggah.']);
            exit;
        }

        $destination = $site_dir . '/' . $original_name;
        if (move_uploaded_file($_FILES['file']['tmp_name'], $destination)) {
            echo json_encode(['success' => true, 'filename' => $original_name]);
        } else {
            echo json_encode(['error' => 'Gagal menyimpan berkas ke server hosting.']);
        }
        exit;
    }

    echo json_encode(['error' => 'Aksi API tidak valid.']);
    exit;
}

// Scan daftar berkas secara rekursif
function get_site_files($dir, $relative_path = '') {
    $results = [];
    $abs_path = empty($relative_path) ? $dir : $dir . '/' . $relative_path;
    if (!is_dir($abs_path)) return $results;
    $items = @scandir($abs_path);
    if ($items === false) return $results;

    $items = array_diff($items, array('.', '..'));

    foreach ($items as $item) {
        $path = empty($relative_path) ? $item : $relative_path . '/' . $item;
        $full_path = $abs_path . '/' . $item;
        
        // Sembunyikan file metadata rahasia
        if ($item === '.metadata.json' || $item === '.password_lock') {
            continue;
        }

        if (is_dir($full_path)) {
            $results[] = [
                'name' => $item,
                'path' => $path,
                'is_dir' => true,
                'children' => get_site_files($dir, $path)
            ];
        } else {
            $results[] = [
                'name' => $item,
                'path' => $path,
                'is_dir' => false,
                'size' => filesize($full_path)
            ];
        }
    }

    // Urutkan folder dulu kemudian file
    usort($results, function($a, $b) {
        if ($a['is_dir'] && !$b['is_dir']) return -1;
        if (!$a['is_dir'] && $b['is_dir']) return 1;
        return strcmp($a['name'], $b['name']);
    });

    return $results;
}

$file_tree = get_site_files($site_dir);
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pengelola Berkas: <?= htmlspecialchars($site_id) ?> - InfinityFree</title>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <!-- Ace Editor Library via CDN -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.15.0/ace.js" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <style>
        :root {
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --primary-glow: rgba(99, 102, 241, 0.15);
            --bg-dark: #0a0e17;
            --sidebar-bg: #111827;
            --editor-header: #1f2937;
            --border: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --success: #10b981;
            --danger: #ef4444;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Inter', system-ui, sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        header {
            background: #0d1321;
            border-bottom: 1px solid var(--border);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            z-index: 20;
        }

        .header-brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-brand h1 {
            font-family: 'Space Grotesk', sans-serif;
            font-size: 17px;
            font-weight: 700;
        }
        .badge-site {
            background: rgba(99, 102, 241, 0.15);
            color: #818cf8;
            border: 1px solid rgba(99, 102, 241, 0.3);
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            padding: 2px 8px;
            border-radius: 6px;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .btn-header {
            background: #1f2937;
            color: var(--text-main);
            border: 1px solid var(--border);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }
        .btn-header:hover {
            background: #374151;
        }
        .btn-header.primary {
            background: var(--primary);
            border-color: var(--primary);
            color: white;
        }
        .btn-header.primary:hover {
            background: var(--primary-hover);
        }

        .main-container {
            display: flex;
            flex: 1;
            height: calc(100vh - 61px);
        }

        /* Sidebar File Tree */
        .sidebar {
            width: 290px;
            background: var(--sidebar-bg);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
        }
        .sidebar-header {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .sidebar-tools {
            display: flex;
            gap: 6px;
        }
        .tool-btn {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-main);
            border-radius: 4px;
            padding: 3px 6px;
            font-size: 11px;
            cursor: pointer;
        }
        .tool-btn:hover {
            background: rgba(255,255,255,0.05);
        }

        .file-list {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }
        .file-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 6px 10px;
            border-radius: 6px;
            font-size: 13px;
            cursor: pointer;
            transition: all 0.15s;
            color: var(--text-main);
            user-select: none;
        }
        .file-item:hover {
            background: rgba(255,255,255,0.04);
        }
        .file-item.active {
            background: rgba(99, 102, 241, 0.15);
            color: #818cf8;
            font-weight: 500;
        }
        .file-info {
            display: flex;
            align-items: center;
            gap: 8px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .file-actions-hover {
            display: none;
        }
        .file-item:hover .file-actions-hover {
            display: flex;
            gap: 4px;
        }
        .action-icon {
            background: transparent;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 2px 4px;
            border-radius: 4px;
        }
        .action-icon:hover {
            color: var(--danger);
            background: rgba(239, 68, 68, 0.1);
        }

        /* Editor Area */
        .editor-wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-dark);
        }
        .editor-bar {
            background: var(--editor-header);
            border-bottom: 1px solid var(--border);
            padding: 8px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .current-file-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            color: #a5b4fc;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        #editor {
            flex: 1;
            width: 100%;
            height: 100%;
            font-size: 14px;
        }

        .save-indicator {
            font-size: 11px;
            color: var(--text-muted);
            display: none;
        }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100%;
            color: var(--text-muted);
            gap: 12px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <header>
        <div class="header-brand">
            <h1>📁 Pengelola Berkas</h1>
            <span class="badge-site">/<?= htmlspecialchars($site_id) ?>/</span>
        </div>
        <div class="header-actions">
            <a href="/<?= htmlspecialchars($site_id) ?>/" target="_blank" class="btn-header">🌐 Buka Situs</a>
            <a href="index.html" class="btn-header">🏠 Halaman Utama</a>
            <a href="file_manager.php?action=logout" class="btn-header">🚪 Keluar</a>
        </div>
    </header>

    <div class="main-container">
        <!-- Sidebar File Explorer -->
        <aside class="sidebar">
            <div class="sidebar-header">
                <span>Daftar File</span>
                <div class="sidebar-tools">
                    <button class="tool-btn" onclick="promptNewFile()" title="Buat File Baru">+ File</button>
                    <button class="tool-btn" onclick="document.getElementById('uploadInput').click()" title="Unggah File">↑ Upload</button>
                    <input type="file" id="uploadInput" style="display: none;" onchange="handleSidebarUpload(this)">
                </div>
            </div>

            <div class="file-list" id="fileTreeContainer">
                <?php if (empty($file_tree)): ?>
                    <p style="padding: 16px; font-size: 12px; color: var(--text-muted); text-align: center;">Folder masih kosong.</p>
                <?php else: ?>
                    <?php
                    function render_tree($items) {
                        foreach ($items as $item) {
                            $is_dir = $item['is_dir'];
                            $path = htmlspecialchars($item['path']);
                            $name = htmlspecialchars($item['name']);
                            if ($is_dir) {
                                echo '<div style="margin-left: 10px; margin-top: 4px;">';
                                echo '<div class="file-item" style="color: #fbbf24; font-weight: 500;">📁 ' . $name . '</div>';
                                if (!empty($item['children'])) {
                                    render_tree($item['children']);
                                }
                                echo '</div>';
                            } else {
                                echo '<div class="file-item" onclick="openFile(\'' . $path . '\', this)">';
                                echo '<div class="file-info">📄 <span>' . $name . '</span></div>';
                                echo '<div class="file-actions-hover">';
                                echo '<button class="action-icon" title="Hapus Berkas" onclick="deleteFile(\'' . $path . '\', event)">🗑️</button>';
                                echo '</div>';
                                echo '</div>';
                            }
                        }
                    }
                    render_tree($file_tree);
                    ?>
                <?php endif; ?>
            </div>
        </aside>

        <!-- Editor Area -->
        <main class="editor-wrapper">
            <div class="editor-bar">
                <div class="current-file-title" id="fileTitleHeader">
                    <span>Pilih berkas di sebelah kiri untuk melihat & mengedit</span>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span id="saveStatus" class="save-indicator">Tersimpan ✓</span>
                    <button id="saveBtn" class="btn-header primary" style="display: none;" onclick="saveCurrentFile()">💾 Simpan (Ctrl+S)</button>
                </div>
            </div>

            <div id="editor"></div>
            <div id="emptyNotice" class="empty-state">
                <p>Klik nama file di sebelah kiri untuk membuka editor kode interaktif.</p>
            </div>
        </main>
    </div>

    <script>
        let editor = ace.edit("editor");
        editor.setTheme("ace/theme/tomorrow_night");
        editor.session.setMode("ace/mode/html");
        editor.setOptions({
            fontSize: "14px",
            showPrintMargin: false,
            enableBasicAutocompletion: true,
            tabSize: 2
        });

        // Sembunyikan editor pada awal
        document.getElementById('editor').style.display = 'none';

        let currentActiveFilePath = '';

        function getAceMode(filename) {
            const ext = filename.split('.').pop().toLowerCase();
            switch (ext) {
                case 'html': case 'htm': return 'ace/mode/html';
                case 'css': return 'ace/mode/css';
                case 'js': return 'ace/mode/javascript';
                case 'json': return 'ace/mode/json';
                case 'php': return 'ace/mode/php';
                case 'md': return 'ace/mode/markdown';
                case 'xml': return 'ace/mode/xml';
                case 'svg': return 'ace/mode/svg';
                default: return 'ace/mode/text';
            }
        }

        async function openFile(filePath, element) {
            document.querySelectorAll('.file-item').forEach(el => el.classList.remove('active'));
            if (element) element.classList.add('active');

            try {
                const res = await fetch(`file_manager.php?api=get_file&file=${encodeURIComponent(filePath)}`);
                const data = await res.json();

                if (data.error) {
                    alert('Gagal membuka file: ' + data.error);
                    return;
                }

                currentActiveFilePath = filePath;
                document.getElementById('emptyNotice').style.display = 'none';
                document.getElementById('editor').style.display = 'block';
                document.getElementById('saveBtn').style.display = 'inline-flex';
                document.getElementById('fileTitleHeader').innerHTML = `📄 <strong>${filePath}</strong>`;

                editor.session.setMode(getAceMode(filePath));
                editor.setValue(data.content, -1);
                editor.focus();
            } catch (err) {
                alert('Gagal memuat file.');
            }
        }

        async function saveCurrentFile() {
            if (!currentActiveFilePath) return;

            const saveBtn = document.getElementById('saveBtn');
            const saveStatus = document.getElementById('saveStatus');
            saveBtn.disabled = true;
            saveBtn.innerText = 'Menyimpan...';

            try {
                const res = await fetch('file_manager.php?api=save_file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        file: currentActiveFilePath,
                        content: editor.getValue()
                    })
                });

                const data = await res.json();
                if (data.success) {
                    saveStatus.style.display = 'inline';
                    saveStatus.innerText = 'Tersimpan ✓';
                    setTimeout(() => { saveStatus.style.display = 'none'; }, 2500);
                } else {
                    alert('Gagal menyimpan: ' + (data.error || 'Unknown error'));
                }
            } catch (err) {
                alert('Gagal menyimpan file.');
            } finally {
                saveBtn.disabled = false;
                saveBtn.innerText = '💾 Simpan (Ctrl+S)';
            }
        }

        // Shortcut Ctrl+S / Cmd+S
        window.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                saveCurrentFile();
            }
        });

        async function promptNewFile() {
            const filename = prompt('Masukkan nama file baru (contoh: style.css atau about.html):');
            if (!filename) return;

            try {
                const res = await fetch('file_manager.php?api=create_file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename: filename })
                });
                const data = await res.json();
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (err) {
                alert('Gagal membuat file.');
            }
        }

        async function deleteFile(filePath, event) {
            event.stopPropagation();
            if (!confirm(`Yakin ingin menghapus berkas ${filePath}? Tindakan ini tidak dapat dibatalkan.`)) {
                return;
            }

            try {
                const res = await fetch('file_manager.php?api=delete_file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ file: filePath })
                });
                const data = await res.json();
                if (data.success) {
                    if (currentActiveFilePath === filePath) {
                        currentActiveFilePath = '';
                        document.getElementById('editor').style.display = 'none';
                        document.getElementById('emptyNotice').style.display = 'flex';
                        document.getElementById('saveBtn').style.display = 'none';
                        document.getElementById('fileTitleHeader').innerText = 'Pilih berkas di sebelah kiri';
                    }
                    location.reload();
                } else {
                    alert('Error: ' + data.error);
                }
            } catch (err) {
                alert('Gagal menghapus file.');
            }
        }

        async function handleSidebarUpload(input) {
            const file = input.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('file', file);

            try {
                const res = await fetch('file_manager.php?api=upload_file', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                if (data.success) {
                    location.reload();
                } else {
                    alert('Upload gagal: ' + (data.error || ''));
                }
            } catch (err) {
                alert('Gagal mengunggah berkas.');
            } finally {
                input.value = '';
            }
        }
    </script>
</body>
</html>
