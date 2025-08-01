<?php
/*
 * SAID_TÉCH PREMIUM INTERNET Web Management Interface
 * Powered by joshuasaid.tech
 * 
 * This interface provides web-based management for the VPN server
 * including user management, service monitoring, and configuration
 */

session_start();

// Configuration
define('DB_PATH', '/etc/saidtech/configs/users.db');
define('CONFIG_DIR', '/etc/saidtech/configs');
define('LOG_DIR', '/var/log/saidtech');
define('BRAND_NAME', 'SAID_TÉCH PREMIUM INTERNET');
define('AUTHOR_SITE', 'joshuasaid.tech');

// Authentication check
if (!isset($_SESSION['authenticated']) && basename($_SERVER['PHP_SELF']) !== 'login.php') {
    header('Location: login.php');
    exit;
}

class SaidTechManager {
    private $db;
    
    public function __construct() {
        try {
            $this->db = new PDO('sqlite:' . DB_PATH);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die('Database connection failed: ' . $e->getMessage());
        }
    }
    
    public function getUsers($active_only = false) {
        $sql = "SELECT * FROM users";
        if ($active_only) {
            $sql .= " WHERE is_active = 1";
        }
        $sql .= " ORDER BY created_at DESC";
        
        $stmt = $this->db->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function getUserStats() {
        $stats = [];
        
        // Total users
        $stmt = $this->db->prepare("SELECT COUNT(*) as count FROM users");
        $stmt->execute();
        $stats['total'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        // Active users
        $stmt = $this->db->prepare("SELECT COUNT(*) as count FROM users WHERE is_active = 1");
        $stmt->execute();
        $stats['active'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        // Expired users
        $stmt = $this->db->prepare("SELECT COUNT(*) as count FROM users WHERE expires_at < datetime('now')");
        $stmt->execute();
        $stats['expired'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        return $stats;
    }
    
    public function getServiceStatus() {
        $services = ['v2ray', 'nginx', 'ssh', 'shadowsocks-libev', 'openvpn@server-tcp', 'trojan-go'];
        $status = [];
        
        foreach ($services as $service) {
            $command = "systemctl is-active $service 2>/dev/null";
            $output = shell_exec($command);
            $status[$service] = trim($output) === 'active';
        }
        
        return $status;
    }
    
    public function getSystemInfo() {
        $info = [];
        
        // Server IP
        $info['server_ip'] = trim(shell_exec("curl -s ifconfig.me 2>/dev/null || echo 'Unknown'"));
        
        // Uptime
        $info['uptime'] = trim(shell_exec("uptime -p"));
        
        // Memory usage
        $memory = shell_exec("free -m | grep Mem:");
        if (preg_match('/Mem:\s+(\d+)\s+(\d+)/', $memory, $matches)) {
            $total = $matches[1];
            $used = $matches[2];
            $info['memory_usage'] = round(($used / $total) * 100, 1);
            $info['memory_total'] = $total;
            $info['memory_used'] = $used;
        }
        
        // Disk usage
        $disk = shell_exec("df -h / | tail -1");
        if (preg_match('/(\d+)%/', $disk, $matches)) {
            $info['disk_usage'] = $matches[1];
        }
        
        // Load average
        $load = shell_exec("uptime | awk -F'load average:' '{print $2}'");
        $info['load_average'] = trim($load);
        
        return $info;
    }
    
    public function createUser($username, $protocol, $expires_days = 30, $max_connections = 2) {
        try {
            // Generate password
            $password = $this->generatePassword();
            
            // Calculate expiry date
            $expires_at = date('Y-m-d H:i:s', strtotime("+{$expires_days} days"));
            
            $stmt = $this->db->prepare("
                INSERT INTO users (username, password, protocol, expires_at, max_connections, is_active) 
                VALUES (?, ?, ?, ?, ?, 1)
            ");
            
            $result = $stmt->execute([$username, $password, $protocol, $expires_at, $max_connections]);
            
            if ($result) {
                $this->logAction("User created: $username ($protocol)");
                return ['success' => true, 'password' => $password];
            }
            
            return ['success' => false, 'error' => 'Failed to create user'];
            
        } catch (PDOException $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    public function deleteUser($username) {
        try {
            $stmt = $this->db->prepare("DELETE FROM users WHERE username = ?");
            $result = $stmt->execute([$username]);
            
            if ($result) {
                $this->logAction("User deleted: $username");
                return ['success' => true];
            }
            
            return ['success' => false, 'error' => 'Failed to delete user'];
            
        } catch (PDOException $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    public function updateUser($id, $data) {
        try {
            $fields = [];
            $values = [];
            
            foreach ($data as $field => $value) {
                if (in_array($field, ['username', 'expires_at', 'max_connections', 'is_active'])) {
                    $fields[] = "$field = ?";
                    $values[] = $value;
                }
            }
            
            if (empty($fields)) {
                return ['success' => false, 'error' => 'No valid fields to update'];
            }
            
            $values[] = $id;
            $sql = "UPDATE users SET " . implode(', ', $fields) . " WHERE id = ?";
            
            $stmt = $this->db->prepare($sql);
            $result = $stmt->execute($values);
            
            if ($result) {
                $this->logAction("User updated: ID $id");
                return ['success' => true];
            }
            
            return ['success' => false, 'error' => 'Failed to update user'];
            
        } catch (PDOException $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    public function generateConfig($username, $protocol) {
        $user = $this->getUser($username);
        if (!$user) {
            return ['success' => false, 'error' => 'User not found'];
        }
        
        $server_ip = trim(shell_exec("curl -s ifconfig.me"));
        $configs = $this->loadPortConfigs();
        
        switch ($protocol) {
            case 'v2ray':
                return $this->generateV2RayConfig($user, $server_ip, $configs);
            case 'ssh':
                return $this->generateSSHConfig($user, $server_ip, $configs);
            case 'shadowsocks':
                return $this->generateShadowsocksConfig($user, $server_ip, $configs);
            case 'openvpn':
                return $this->generateOpenVPNConfig($user, $server_ip, $configs);
            default:
                return ['success' => false, 'error' => 'Unsupported protocol'];
        }
    }
    
    private function getUser($username) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    
    private function loadPortConfigs() {
        $configs = [];
        $config_files = [
            'v2ray_ports.conf',
            'ssh_ports.conf',
            'shadowsocks.conf',
            'openvpn.conf'
        ];
        
        foreach ($config_files as $file) {
            $path = CONFIG_DIR . '/' . $file;
            if (file_exists($path)) {
                $content = file_get_contents($path);
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    if (strpos($line, '=') !== false) {
                        list($key, $value) = explode('=', $line, 2);
                        $configs[trim($key)] = trim($value);
                    }
                }
            }
        }
        
        return $configs;
    }
    
    private function generateV2RayConfig($user, $server_ip, $configs) {
        $uuid = $this->generateUUID();
        
        $config = [
            'v' => '2',
            'ps' => 'SAID_TECH-' . $user['username'],
            'add' => $server_ip,
            'port' => $configs['VMESS_PORT'] ?? '10443',
            'id' => $uuid,
            'aid' => '0',
            'net' => 'tcp',
            'type' => 'none',
            'host' => '',
            'path' => '',
            'tls' => 'tls'
        ];
        
        return [
            'success' => true,
            'config' => base64_encode('vmess://' . base64_encode(json_encode($config))),
            'qr_data' => 'vmess://' . base64_encode(json_encode($config))
        ];
    }
    
    private function generateSSHConfig($user, $server_ip, $configs) {
        $config = [
            'name' => 'SAID_TECH SSH-' . $user['username'],
            'server' => $server_ip,
            'port' => $configs['SSH_WS_PORT'] ?? '8080',
            'username' => $user['username'],
            'password' => $user['password'],
            'payload' => 'GET / HTTP/1.1[crlf]Host: zero.facebook.com[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]'
        ];
        
        return [
            'success' => true,
            'config' => json_encode($config, JSON_PRETTY_PRINT)
        ];
    }
    
    private function generatePassword($length = 12) {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $password;
    }
    
    private function generateUUID() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
    
    private function logAction($message) {
        $timestamp = date('Y-m-d H:i:s');
        $log_entry = "[$timestamp] [WEB] $message\n";
        file_put_contents(LOG_DIR . '/web_interface.log', $log_entry, FILE_APPEND);
    }
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    $manager = new SaidTechManager();
    
    switch ($_GET['action']) {
        case 'get_users':
            echo json_encode($manager->getUsers());
            break;
            
        case 'get_stats':
            echo json_encode([
                'users' => $manager->getUserStats(),
                'services' => $manager->getServiceStatus(),
                'system' => $manager->getSystemInfo()
            ]);
            break;
            
        case 'create_user':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $data = json_decode(file_get_contents('php://input'), true);
                $result = $manager->createUser(
                    $data['username'],
                    $data['protocol'],
                    $data['expires_days'] ?? 30,
                    $data['max_connections'] ?? 2
                );
                echo json_encode($result);
            }
            break;
            
        case 'delete_user':
            if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
                $username = $_GET['username'];
                $result = $manager->deleteUser($username);
                echo json_encode($result);
            }
            break;
            
        case 'generate_config':
            $username = $_GET['username'];
            $protocol = $_GET['protocol'];
            $result = $manager->generateConfig($username, $protocol);
            echo json_encode($result);
            break;
            
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo BRAND_NAME; ?> - Management Interface</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .brand {
            font-size: 1.5rem;
            font-weight: bold;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .author {
            color: #666;
            font-size: 0.9rem;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1.5rem;
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card i {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .stat-label {
            color: #666;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }
        
        .panel {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .panel-header {
            padding: 1.5rem;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .panel-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #333;
        }
        
        .panel-content {
            padding: 1.5rem;
        }
        
        .btn {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-block;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b, #ee5a52);
        }
        
        .btn-success {
            background: linear-gradient(45deg, #51cf66, #40c057);
        }
        
        .user-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        .user-table th,
        .user-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }
        
        .user-table th {
            background: rgba(102, 126, 234, 0.1);
            font-weight: 600;
        }
        
        .status {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-active {
            background: rgba(81, 207, 102, 0.2);
            color: #40c057;
        }
        
        .status-inactive {
            background: rgba(255, 107, 107, 0.2);
            color: #ee5a52;
        }
        
        .status-running {
            background: rgba(81, 207, 102, 0.2);
            color: #40c057;
        }
        
        .status-stopped {
            background: rgba(255, 107, 107, 0.2);
            color: #ee5a52;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
        }
        
        .form-input {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
            z-index: 1000;
        }
        
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            min-width: 400px;
        }
        
        .modal-header {
            margin-bottom: 1.5rem;
        }
        
        .modal-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #333;
        }
        
        .close {
            float: right;
            font-size: 1.5rem;
            cursor: pointer;
            color: #aaa;
        }
        
        .close:hover {
            color: #333;
        }
        
        .config-output {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .qr-code {
            text-align: center;
            margin: 1rem 0;
        }
        
        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 1rem;
            }
            
            .header-content {
                flex-direction: column;
                gap: 0.5rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div>
                <div class="brand"><?php echo BRAND_NAME; ?></div>
                <div class="author">Powered by <?php echo AUTHOR_SITE; ?></div>
            </div>
            <div>
                <button class="btn" onclick="logout()">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </button>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Statistics Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <i class="fas fa-users"></i>
                <div class="stat-number" id="total-users">-</div>
                <div class="stat-label">Total Users</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-user-check"></i>
                <div class="stat-number" id="active-users">-</div>
                <div class="stat-label">Active Users</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-server"></i>
                <div class="stat-number" id="running-services">-</div>
                <div class="stat-label">Running Services</div>
            </div>
            <div class="stat-card">
                <i class="fas fa-memory"></i>
                <div class="stat-number" id="memory-usage">-%</div>
                <div class="stat-label">Memory Usage</div>
            </div>
        </div>

        <div class="main-content">
            <!-- User Management Panel -->
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">
                        <i class="fas fa-users"></i> User Management
                    </h3>
                    <button class="btn" onclick="showAddUserModal()">
                        <i class="fas fa-plus"></i> Add User
                    </button>
                </div>
                <div class="panel-content">
                    <div style="max-height: 400px; overflow-y: auto;">
                        <table class="user-table" id="users-table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Protocol</th>
                                    <th>Status</th>
                                    <th>Expires</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <!-- Users will be loaded here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Service Status Panel -->
            <div class="panel">
                <div class="panel-header">
                    <h3 class="panel-title">
                        <i class="fas fa-cogs"></i> Service Status
                    </h3>
                    <button class="btn" onclick="refreshData()">
                        <i class="fas fa-sync-alt"></i> Refresh
                    </button>
                </div>
                <div class="panel-content">
                    <div id="services-status">
                        <!-- Service status will be loaded here -->
                    </div>
                    
                    <div style="margin-top: 2rem;">
                        <h4>System Information</h4>
                        <div id="system-info">
                            <!-- System info will be loaded here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add User Modal -->
    <div id="addUserModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close" onclick="closeModal('addUserModal')">&times;</span>
                <h3 class="modal-title">Add New User</h3>
            </div>
            <form id="addUserForm">
                <div class="form-group">
                    <label class="form-label">Username</label>
                    <input type="text" class="form-input" name="username" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Protocol</label>
                    <select class="form-input" name="protocol" required>
                        <option value="v2ray">V2Ray</option>
                        <option value="ssh">SSH WebSocket</option>
                        <option value="shadowsocks">Shadowsocks</option>
                        <option value="openvpn">OpenVPN</option>
                        <option value="trojan">Trojan-Go</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Expires (days)</label>
                    <input type="number" class="form-input" name="expires_days" value="30" min="1" max="365">
                </div>
                <div class="form-group">
                    <label class="form-label">Max Connections</label>
                    <input type="number" class="form-input" name="max_connections" value="2" min="1" max="10">
                </div>
                <div style="text-align: center; margin-top: 1.5rem;">
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-plus"></i> Create User
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Config Modal -->
    <div id="configModal" class="modal">
        <div class="modal-content" style="min-width: 600px;">
            <div class="modal-header">
                <span class="close" onclick="closeModal('configModal')">&times;</span>
                <h3 class="modal-title">Client Configuration</h3>
            </div>
            <div id="config-content">
                <!-- Configuration will be displayed here -->
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrious/4.0.2/qrious.min.js"></script>
    <script>
        // Initialize the dashboard
        document.addEventListener('DOMContentLoaded', function() {
            refreshData();
            
            // Auto-refresh every 30 seconds
            setInterval(refreshData, 30000);
        });

        function refreshData() {
            fetch('?action=get_stats')
                .then(response => response.json())
                .then(data => {
                    updateStats(data);
                    updateServices(data.services);
                    updateSystemInfo(data.system);
                })
                .catch(error => console.error('Error:', error));
            
            loadUsers();
        }

        function updateStats(data) {
            document.getElementById('total-users').textContent = data.users.total;
            document.getElementById('active-users').textContent = data.users.active;
            
            // Count running services
            const runningServices = Object.values(data.services).filter(status => status).length;
            document.getElementById('running-services').textContent = runningServices;
            
            document.getElementById('memory-usage').textContent = data.system.memory_usage + '%';
        }

        function updateServices(services) {
            const container = document.getElementById('services-status');
            container.innerHTML = '';
            
            Object.entries(services).forEach(([service, status]) => {
                const serviceDiv = document.createElement('div');
                serviceDiv.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid #eee;';
                
                serviceDiv.innerHTML = `
                    <span>${service}</span>
                    <span class="status ${status ? 'status-running' : 'status-stopped'}">
                        ${status ? 'Running' : 'Stopped'}
                    </span>
                `;
                
                container.appendChild(serviceDiv);
            });
        }

        function updateSystemInfo(system) {
            const container = document.getElementById('system-info');
            container.innerHTML = `
                <div style="margin-top: 1rem;">
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
                        <span>Server IP:</span>
                        <span>${system.server_ip}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
                        <span>Uptime:</span>
                        <span>${system.uptime}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
                        <span>Memory:</span>
                        <span>${system.memory_used}MB / ${system.memory_total}MB</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
                        <span>Disk Usage:</span>
                        <span>${system.disk_usage}%</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
                        <span>Load Average:</span>
                        <span>${system.load_average}</span>
                    </div>
                </div>
            `;
        }

        function loadUsers() {
            fetch('?action=get_users')
                .then(response => response.json())
                .then(users => {
                    const tbody = document.querySelector('#users-table tbody');
                    tbody.innerHTML = '';
                    
                    users.forEach(user => {
                        const row = document.createElement('tr');
                        const expiresDate = new Date(user.expires_at);
                        const isExpired = expiresDate < new Date();
                        
                        row.innerHTML = `
                            <td>${user.username}</td>
                            <td>${user.protocol}</td>
                            <td>
                                <span class="status ${user.is_active && !isExpired ? 'status-active' : 'status-inactive'}">
                                    ${user.is_active && !isExpired ? 'Active' : 'Inactive'}
                                </span>
                            </td>
                            <td>${expiresDate.toLocaleDateString()}</td>
                            <td>
                                <button class="btn" style="padding: 0.25rem 0.5rem; margin: 0 0.25rem; font-size: 0.8rem;" 
                                        onclick="generateConfig('${user.username}', '${user.protocol}')">
                                    <i class="fas fa-download"></i>
                                </button>
                                <button class="btn btn-danger" style="padding: 0.25rem 0.5rem; margin: 0 0.25rem; font-size: 0.8rem;" 
                                        onclick="deleteUser('${user.username}')">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        `;
                        
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error:', error));
        }

        function showAddUserModal() {
            document.getElementById('addUserModal').style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        document.getElementById('addUserForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const data = Object.fromEntries(formData);
            
            fetch('?action=create_user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    alert(`User created successfully!\nPassword: ${result.password}`);
                    closeModal('addUserModal');
                    this.reset();
                    loadUsers();
                    refreshData();
                } else {
                    alert('Error: ' + result.error);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while creating the user.');
            });
        });

        function deleteUser(username) {
            if (confirm(`Are you sure you want to delete user "${username}"?`)) {
                fetch(`?action=delete_user&username=${username}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        alert('User deleted successfully!');
                        loadUsers();
                        refreshData();
                    } else {
                        alert('Error: ' + result.error);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while deleting the user.');
                });
            }
        }

        function generateConfig(username, protocol) {
            fetch(`?action=generate_config&username=${username}&protocol=${protocol}`)
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        displayConfig(username, protocol, result);
                    } else {
                        alert('Error: ' + result.error);
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('An error occurred while generating the configuration.');
                });
        }

        function displayConfig(username, protocol, result) {
            const modal = document.getElementById('configModal');
            const content = document.getElementById('config-content');
            
            let configHtml = `
                <h4>${protocol.toUpperCase()} Configuration for ${username}</h4>
                <div class="config-output">${result.config}</div>
            `;
            
            if (result.qr_data) {
                configHtml += `
                    <div class="qr-code">
                        <canvas id="qr-canvas" width="200" height="200"></canvas>
                        <p>Scan with your VPN client</p>
                    </div>
                `;
            }
            
            configHtml += `
                <div style="text-align: center; margin-top: 1rem;">
                    <button class="btn" onclick="copyToClipboard(this.previousElementSibling.previousElementSibling.textContent)">
                        <i class="fas fa-copy"></i> Copy Configuration
                    </button>
                </div>
            `;
            
            content.innerHTML = configHtml;
            
            if (result.qr_data) {
                const qr = new QRious({
                    element: document.getElementById('qr-canvas'),
                    value: result.qr_data,
                    size: 200,
                    foreground: '#333',
                    background: '#fff'
                });
            }
            
            modal.style.display = 'block';
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Configuration copied to clipboard!');
            }, function(err) {
                console.error('Could not copy text: ', err);
                alert('Failed to copy configuration.');
            });
        }

        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                window.location.href = 'logout.php';
            }
        }

        // Close modals when clicking outside
        window.onclick = function(event) {
            const modals = document.querySelectorAll('.modal');
            modals.forEach(modal => {
                if (event.target === modal) {
                    modal.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>