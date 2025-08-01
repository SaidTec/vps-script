<?php
session_start();

// Log logout if user was authenticated
if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true) {
    $log_entry = "[" . date('Y-m-d H:i:s') . "] [WEB] User logout from " . $_SERVER['REMOTE_ADDR'] . "\n";
    file_put_contents('/var/log/saidtech/web_interface.log', $log_entry, FILE_APPEND);
}

// Destroy the session
session_destroy();

// Clear session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Redirect to login page
header('Location: login.php');
exit;
?>