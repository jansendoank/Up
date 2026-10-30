<?php
/**
 * REST API Backend untuk Deploy Website Instan di InfinityFree & Shared Web Hosting
 * Mendukung pembuatan folder otomatis, file saving, dan ekstrak .ZIP
 * Dilengkapi dengan enkripsi hash password untuk perlindungan berkas tersimpan.
 *
 * Kompatibel dengan: InfinityFree, cPanel, CyberPanel, DirectAdmin, Apache PHP 7.4 - 8.3+
 */

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Content-Type: application/json; charset=utf-8');

// Matikan log error langsung ke browser agar respons JSON tetap murni & valid
ini_set('display_errors', 0);
error_reporting(E_ALL);

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit(0);
}

$action = isset($_GET['action']) ? $_GET['action'] : 'deploy';
$base_dir = __DIR__;

/**
 * Validasi Site ID / Nama Subfolder agar aman dari karakter berbahaya
 */
function validate_site_id($site_id) {
    $clean_id = preg_replace('/[^a-zA-Z0-9\-_]/', '', (string)$site_id);
    return strtolower(trim($clean_id));
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

/**
 * Validasi password dengan metadata tersimpan
 */
function verify_site_password($site_dir, $password) {
    $meta_file = $site_dir . '/.metadata.json';
    $legacy_lock = $site_dir . '/.password_lock';

    if (file_exists($meta_file)) {
        $raw = file_get_contents($meta_file);
        $meta = json_decode($raw, true);
        if ($meta && isset($meta['password_hash'])) {
            return password_verify($password, $meta['password_hash']);
        }
    }
    
    // Fallback bila password diletakkan sebagai plain text lama
    if (file_exists($legacy_lock)) {
        $stored = trim(file_get_contents($legacy_lock));
        return hash_equals($stored, $password);
    }

    return true; // Folder baru belum memiliki password
}

/**
 * Dapatkan base URL direktori saat ini
 */
function get_current_base_url() {
    $is_https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443) || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    $protocol = $is_https ? 'https://' : 'http://';
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    
    $script_dir = dirname($_SERVER['SCRIPT_NAME']);
    $script_dir = str_replace('\\', '/', $script_dir);
    $script_dir = rtrim($script_dir, '/');
    
    return $protocol . $host . ($script_dir ? $script_dir : '');
}

/**
 * AKSI 1: DEPLOY JSON (Upload langsung kode HTML / file mentah)
 */
if ($action === 'deploy') {
    $raw_input = file_get_contents('php://input');
    $input = json_decode($raw_input, true);
    if (!$input) {
        $input = $_POST;
    }

    $site_id = isset($input['siteId']) ? validate_site_id($input['siteId']) : '';
    $password = isset($input['password']) ? trim($input['password']) : '';
    $files = isset($input['files']) && is_array($input['files']) ? $input['files'] : [];

    if (empty($site_id)) {
        echo json_encode(['error' => 'Nama website (Site ID) tidak valid. Gunakan huruf, angka, dan tanda hubung saja.']);
        exit;
    }

    if (strlen($password) < 4) {
        echo json_encode(['error' => 'Password terlalu pendek! Demi keamanan, gunakan minimal 4 karakter.']);
        exit;
    }

    // Larang penggunaan nama sistem terlarang untuk subfolder
    $reserved = ['htdocs', 'cgi-bin', 'api', 'file_manager', 'assets', '.well-known', 'config', 'vendor'];
    if (in_array($site_id, $reserved, true)) {
        echo json_encode(['error' => "Nama '$site_id' tidak dapat digunakan karena merupakan nama folder sistem cadangan."]);
        exit;
    }

    $site_dir = $base_dir . '/' . $site_id;
    $meta_file = $site_dir . '/.metadata.json';

    // Periksa otorisasi folder bila sudah pernah dibuat
    if (file_exists($site_dir) && (file_exists($meta_file) || file_exists($site_dir . '/.password_lock'))) {
        if (!verify_site_password($site_dir, $password)) {
            echo json_encode(['error' => 'Website ini sudah terdaftar oleh pengguna lain atau password yang dimasukkan salah!']);
            exit;
        }
    }

    // Jika folder belum ada, buat foldernya terlebih dahulu
    if (!file_exists($site_dir)) {
        if (!@mkdir($site_dir, 0755, true)) {
            echo json_encode(['error' => 'Gagal membuat folder di hosting InfinityFree. Pastikan izin folder htdocs adalah 755.']);
            exit;
        }
    }

    // Perbarui metadata sandi dengan hash aman
    $meta_data = [
        'siteId' => $site_id,
        'created_at' => date('Y-m-d H:i:s'),
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'server' => 'InfinityFree / Apache PHP'
    ];
    @file_put_contents($meta_file, json_encode($meta_data, JSON_PRETTY_PRINT));
    @file_put_contents($site_dir . '/.password_lock', $password);

    // Pasang proteksi anti-hack di subfolder agar PHP tidak bisa dieksekusi di situs buatan user
    $sub_sec = $site_dir . '/.htaccess';
    if (!file_exists($sub_sec)) {
        $sec_rules = "# Proteksi Anti-Hack: Blokir eksekusi script server di subfolder\n"
                   . "<FilesMatch \"\\.(php|phtml|php3|php4|php5|phar|cgi|pl|sh)$\">\n"
                   . "    Order allow,deny\n"
                   . "    Deny from all\n"
                   . "</FilesMatch>\n"
                   . "Options -ExecCGI\n";
        @file_put_contents($sub_sec, $sec_rules);
    }

    // Simpan berkas HTML / JS / CSS satu per satu
    $written_count = 0;
    foreach ($files as $file) {
        $file_path = isset($file['path']) ? trim($file['path']) : '';
        
        // Proteksi directory traversal keamanan server
        if (empty($file_path) || strpos($file_path, '..') !== false || strpos($file_path, '/') === 0 || strpos($file_path, '\\') === 0) {
            continue;
        }

        // Jangan izinkan menimpa metadata kunci atau file konfigurasi
        if ($file_path === '.metadata.json' || $file_path === '.password_lock' || $file_path === '.htaccess') {
            continue;
        }

        // Cek keamanan ekstensi: Dilarang keras upload PHP / script server
        if (!is_safe_web_extension($file_path)) {
            continue;
        }

        $full_path = $site_dir . '/' . $file_path;
        $dir_name = dirname($full_path);

        if (!file_exists($dir_name)) {
            @mkdir($dir_name, 0755, true);
        }

        $content = isset($file['content']) ? $file['content'] : '';
        if (isset($file['encoding']) && $file['encoding'] === 'base64') {
            $content = base64_decode($content);
        }

        if (@file_put_contents($full_path, $content) !== false) {
            $written_count++;
        }
    }

    $base_url = get_current_base_url();

    echo json_encode([
        'success' => true,
        'siteId' => $site_id,
        'files_written' => $written_count,
        'url' => $base_url . '/' . $site_id . '/',
        'relative_url' => $site_id . '/'
    ]);
    exit;
}

/**
 * AKSI 2: EXTRAK ZIP DEPLOY (Mengunggah berkas ZIP utuh)
 */
if ($action === 'zip_deploy') {
    $site_id = isset($_POST['siteId']) ? validate_site_id($_POST['siteId']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';

    if (empty($site_id) || empty($password)) {
        echo json_encode(['error' => 'Nama website (Site ID) dan password pelindung wajib dilengkapi.']);
        exit;
    }

    if (strlen($password) < 4) {
        echo json_encode(['error' => 'Password minimal 4 karakter.']);
        exit;
    }

    // Cek error upload file
    if (!isset($_FILES['zipfile'])) {
        echo json_encode(['error' => 'Tidak ada berkas ZIP yang diunggah.']);
        exit;
    }

    $upload_error = $_FILES['zipfile']['error'];
    if ($upload_error !== UPLOAD_ERR_OK) {
        $msg = 'Gagal mengunggah berkas.';
        if ($upload_error === UPLOAD_ERR_INI_SIZE || $upload_error === UPLOAD_ERR_FORM_SIZE) {
            $msg = 'Ukuran berkas ZIP melebihi batas upload PHP hosting (Maksimal 10MB di InfinityFree). Kurangi ukuran file Anda.';
        } elseif ($upload_error === UPLOAD_ERR_NO_FILE) {
            $msg = 'Tidak ada berkas yang dipilih.';
        }
        echo json_encode(['error' => $msg]);
        exit;
    }

    $site_dir = $base_dir . '/' . $site_id;
    $meta_file = $site_dir . '/.metadata.json';

    // Validasi folder lama
    if (file_exists($site_dir) && (file_exists($meta_file) || file_exists($site_dir . '/.password_lock'))) {
        if (!verify_site_password($site_dir, $password)) {
            echo json_encode(['error' => 'Website ini sudah terdaftar. Masukkan password yang benar atau gunakan nama folder lain.']);
            exit;
        }
    }

    if (!file_exists($site_dir)) {
        if (!@mkdir($site_dir, 0755, true)) {
            echo json_encode(['error' => 'Gagal membuat folder di hosting InfinityFree. Periksa izin direktori htdocs.']);
            exit;
        }
    }

    // Perbarui metadata sandi
    $meta_data = [
        'siteId' => $site_id,
        'created_at' => date('Y-m-d H:i:s'),
        'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        'server' => 'InfinityFree / Apache PHP'
    ];
    @file_put_contents($meta_file, json_encode($meta_data, JSON_PRETTY_PRINT));
    @file_put_contents($site_dir . '/.password_lock', $password);

    // Proses bongkar ekstensi ZIP
    if (!class_exists('ZipArchive')) {
        echo json_encode(['error' => 'Fitur ekstensi ZipArchive tidak aktif pada versi PHP saat ini.']);
        exit;
    }

    // Pasang proteksi anti-hack di subfolder agar PHP tidak bisa dieksekusi di situs buatan user
    $sub_sec = $site_dir . '/.htaccess';
    if (!file_exists($sub_sec)) {
        $sec_rules = "# Proteksi Anti-Hack: Blokir eksekusi script server di subfolder\n"
                   . "<FilesMatch \"\\.(php|phtml|php3|php4|php5|phar|cgi|pl|sh)$\">\n"
                   . "    Order allow,deny\n"
                   . "    Deny from all\n"
                   . "</FilesMatch>\n"
                   . "Options -ExecCGI\n";
        @file_put_contents($sub_sec, $sec_rules);
    }

    $zip = new ZipArchive;
    $tmp_file = $_FILES['zipfile']['tmp_name'];
    
    if ($zip->open($tmp_file) === TRUE) {
        $files_extracted = 0;
        
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $filename = $zip->getNameIndex($i);

            // Bersihkan file temporary bawaan OS Mac / DS Store
            if (strpos($filename, '__MACOSX') === 0 || strpos($filename, '.DS_Store') !== false) {
                continue;
            }

            // Keamanan filter path traversal berkas jahat
            if (strpos($filename, '..') !== false || strpos($filename, '/') === 0 || strpos($filename, '\\') === 0) {
                continue;
            }

            // Jangan biarkan menimpa file metadata kunci atau konfigurasi server
            if ($filename === '.metadata.json' || $filename === '.password_lock' || $filename === '.htaccess' || basename($filename) === '.htaccess') {
                continue;
            }

            // Jika item adalah folder (berakhiran /), biarkan dibuat
            if (substr($filename, -1) === '/') {
                $zip->extractTo($site_dir, $filename);
                continue;
            }

            // Cek keamanan ekstensi: Dilarang keras ekstrak PHP / backdoor / shell script
            if (!is_safe_web_extension($filename)) {
                continue;
            }

            // Ekstrak file dengan aman
            if ($zip->extractTo($site_dir, $filename)) {
                $files_extracted++;
            }
        }
        $zip->close();

        $base_url = get_current_base_url();

        echo json_encode([
            'success' => true,
            'siteId' => $site_id,
            'files_extracted' => $files_extracted,
            'url' => $base_url . '/' . $site_id . '/',
            'relative_url' => $site_id . '/'
        ]);
    } else {
        echo json_encode(['error' => 'Berkas ZIP rusak atau tidak dapat diekstrak oleh server PHP.']);
    }
    exit;
}

/**
 * AKSI 3: LIST DIREKTORI SITUS (Daftar seluruh website yang terdaftar)
 */
if ($action === 'list_sites') {
    $sites = [];
    $dirs = @scandir($base_dir);
    $reserved = ['htdocs', 'cgi-bin', 'api', 'file_manager', 'assets', '.well-known', 'config', 'vendor', '.', '..'];
    $base_url = get_current_base_url();

    if ($dirs) {
        foreach ($dirs as $d) {
            if ($d[0] === '.' || in_array($d, $reserved, true)) {
                continue;
            }
            $dir_path = $base_dir . '/' . $d;
            if (!is_dir($dir_path)) {
                continue;
            }

            $meta_file = $dir_path . '/.metadata.json';
            $created_at = date('Y-m-d H:i', @filemtime($dir_path));
            if (file_exists($meta_file)) {
                $meta = json_decode(@file_get_contents($meta_file), true);
                if ($meta && isset($meta['created_at'])) {
                    $created_at = $meta['created_at'];
                }
            }

            // Hitung berkas dalam folder
            $file_count = 0;
            $subfiles = @scandir($dir_path);
            if ($subfiles) {
                foreach ($subfiles as $sf) {
                    if ($sf !== '.' && $sf !== '..' && $sf[0] !== '.') {
                        $file_count++;
                    }
                }
            }

            $sites[] = [
                'siteId' => $d,
                'url' => $base_url . '/' . $d . '/',
                'created_at' => $created_at,
                'fileCount' => $file_count
            ];
        }
    }

    echo json_encode(['success' => true, 'sites' => $sites]);
    exit;
}

/**
 * AKSI 4: HAPUS WEBSITE BESERTA FOLDERNYA
 */
if ($action === 'delete_site') {
    $raw_input = file_get_contents('php://input');
    $input = json_decode($raw_input, true);
    if (!$input) {
        $input = $_POST;
    }

    $site_id = isset($input['siteId']) ? validate_site_id($input['siteId']) : '';
    $password = isset($input['password']) ? trim($input['password']) : '';

    if (empty($site_id)) {
        echo json_encode(['error' => 'Nama website (Site ID) tidak valid.']);
        exit;
    }

    $site_dir = $base_dir . '/' . $site_id;
    if (!file_exists($site_dir) || !is_dir($site_dir)) {
        echo json_encode(['error' => 'Website tidak ditemukan di server.']);
        exit;
    }

    if (!verify_site_password($site_dir, $password)) {
        echo json_encode(['error' => 'Password salah! Tidak dapat menghapus website ini.']);
        exit;
    }

    // Fungsi rekursif hapus folder
    function rrmdir_api($dir) {
        if (is_dir($dir)) {
            $objects = scandir($dir);
            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    $path = $dir . DIRECTORY_SEPARATOR . $object;
                    if (is_dir($path) && !is_link($path)) {
                        rrmdir_api($path);
                    } else {
                        @unlink($path);
                    }
                }
            }
            @rmdir($dir);
            return true;
        }
        return false;
    }

    if (rrmdir_api($site_dir)) {
        echo json_encode(['success' => true, 'message' => "Website '$site_id' berhasil dihapus."]);
    } else {
        echo json_encode(['error' => 'Gagal menghapus folder website dari server hosting.']);
    }
    exit;
}

echo json_encode(['error' => 'Permintaan API ditolak. Aksi API tidak dikenali.']);
