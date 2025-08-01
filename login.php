<?php
session_start();

// Configuration
define('BRAND_NAME', 'SAID_TÉCH PREMIUM INTERNET');
define('AUTHOR_SITE', 'joshuasaid.tech');
define('ADMIN_PASSWORD_FILE', '/etc/saidtech/configs/.admin_password');

// Check if already authenticated
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    header('Location: index.php');
    exit;
}

$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Default credentials
    $valid_username = 'admin';
    $valid_password = 'admin123';
    
    // Try to read password from file
    if (file_exists(ADMIN_PASSWORD_FILE)) {
        $stored_password = trim(file_get_contents(ADMIN_PASSWORD_FILE));
        if (!empty($stored_password)) {
            $valid_password = $stored_password;
        }
    }
    
    if ($username === $valid_username && $password === $valid_password) {
        $_SESSION['authenticated'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = time();
        
        // Log successful login
        $log_entry = "[" . date('Y-m-d H:i:s') . "] [WEB] Successful login from " . $_SERVER['REMOTE_ADDR'] . "\n";
        file_put_contents('/var/log/saidtech/web_interface.log', $log_entry, FILE_APPEND);
        
        header('Location: index.php');
        exit;
    } else {
        $error_message = 'Invalid username or password';
        
        // Log failed login attempt
        $log_entry = "[" . date('Y-m-d H:i:s') . "] [WEB] Failed login attempt for '$username' from " . $_SERVER['REMOTE_ADDR'] . "\n";
        file_put_contents('/var/log/saidtech/web_interface.log', $log_entry, FILE_APPEND);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo BRAND_NAME; ?> - Login</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
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
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }

        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.2);
            width: 100%;
            max-width: 400px;
        }

        .brand-section {
            text-align: center;
            margin-bottom: 2rem;
        }

        .brand {
            font-size: 1.8rem;
            font-weight: bold;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }

        .author {
            color: #666;
            font-size: 0.9rem;
        }

        .login-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .login-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #333;
            margin-bottom: 0.5rem;
        }

        .login-subtitle {
            color: #666;
            font-size: 0.9rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
        }

        .form-input {
            width: 100%;
            padding: 1rem;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.8);
        }

        .form-input:focus {
            outline: none;
            border-color: #667eea;
            background: rgba(255, 255, 255, 1);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }

        .input-icon {
            position: relative;
        }

        .input-icon i {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: #667eea;
        }

        .input-icon .form-input {
            padding-left: 3rem;
        }

        .btn {
            width: 100%;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 1rem;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-top: 1rem;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .error-message {
            background: rgba(255, 107, 107, 0.1);
            color: #e74c3c;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid rgba(255, 107, 107, 0.3);
            text-align: center;
            font-size: 0.9rem;
        }

        .default-credentials {
            background: rgba(52, 152, 219, 0.1);
            color: #3498db;
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            border: 1px solid rgba(52, 152, 219, 0.3);
            font-size: 0.85rem;
            text-align: center;
        }

        .features {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }

        .feature-item {
            display: flex;
            align-items: center;
            margin-bottom: 0.75rem;
            font-size: 0.9rem;
            color: #666;
        }

        .feature-item i {
            color: #667eea;
            margin-right: 0.75rem;
            width: 16px;
        }

        @media (max-width: 480px) {
            .login-container {
                margin: 1rem;
                padding: 2rem;
            }
        }

        .animated-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .animated-bg::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            animation: float 6s ease-in-out infinite;
        }

        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
    </style>
</head>
<body>
    <div class="animated-bg"></div>
    
    <div class="login-container">
        <div class="brand-section">
            <div class="brand"><?php echo BRAND_NAME; ?></div>
            <div class="author">Powered by <?php echo AUTHOR_SITE; ?></div>
        </div>

        <div class="login-header">
            <h2 class="login-title">
                <i class="fas fa-shield-alt"></i> Management Portal
            </h2>
            <p class="login-subtitle">Secure access to your VPN server</p>
        </div>

        <?php if (!empty($error_message)): ?>
            <div class="error-message">
                <i class="fas fa-exclamation-triangle"></i>
                <?php echo htmlspecialchars($error_message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <div class="form-group">
                <label class="form-label">Username</label>
                <div class="input-icon">
                    <i class="fas fa-user"></i>
                    <input type="text" name="username" class="form-input" required 
                           value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
                           placeholder="Enter username">
                </div>
            </div>

            <div class="form-group">
                <label class="form-label">Password</label>
                <div class="input-icon">
                    <i class="fas fa-lock"></i>
                    <input type="password" name="password" class="form-input" required 
                           placeholder="Enter password">
                </div>
            </div>

            <button type="submit" class="btn">
                <i class="fas fa-sign-in-alt"></i> Login
            </button>
        </form>

        <div class="default-credentials">
            <i class="fas fa-info-circle"></i>
            <strong>Default:</strong> admin / admin123
            <br><small>Change password after first login</small>
        </div>

        <div class="features">
            <div class="feature-item">
                <i class="fas fa-users"></i>
                User management and monitoring
            </div>
            <div class="feature-item">
                <i class="fas fa-server"></i>
                Service status and control
            </div>
            <div class="feature-item">
                <i class="fas fa-download"></i>
                Client configuration generator
            </div>
            <div class="feature-item">
                <i class="fas fa-chart-line"></i>
                Real-time statistics
            </div>
            <div class="feature-item">
                <i class="fas fa-shield-alt"></i>
                Security monitoring
            </div>
        </div>
    </div>

    <script>
        // Auto-focus on username field
        document.addEventListener('DOMContentLoaded', function() {
            const usernameField = document.querySelector('input[name="username"]');
            if (usernameField && !usernameField.value) {
                usernameField.focus();
            }
        });

        // Add some interactive effects
        document.querySelectorAll('.form-input').forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.style.transform = 'scale(1.02)';
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.style.transform = 'scale(1)';
            });
        });
    </script>
</body>
</html>