<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
include '../utils/utilityFunctions.php';


setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    setCorsHeaders();
    http_response_code(200);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';

$conn = getConnection();
log_action("=== ADMIN RESET PASSWORD ATTEMPT START ===");

try {
    $data = getRequestBody();
    log_action("Raw Input: " . json_encode($data));

    $email = trim($data['email'] ?? '');
    $otp = trim($data['otp'] ?? '');
    $newPassword = $data['new_password'] ?? '';

    if (!$email || !$otp || !$newPassword) {
        log_action("Validation failed: missing fields");
        echo generateResponse(false, "Email, OTP, and new password are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        log_action("Validation failed: invalid email");
        echo generateResponse(false, "Invalid email address.", null, 400);
        closeConnection($conn);
        exit;
    }

    if (strlen($newPassword) < 8) {
        log_action("Validation failed: password too short");
        echo generateResponse(false, "Password must be at least 8 characters.", null, 400);
        closeConnection($conn);
        exit;
    }

    $adminCheck = $conn->query("SELECT id, otp, otp_expires_at, otp_attempts FROM admins WHERE email = '$email' AND soft_delete = 0");
    if (!$adminCheck || $adminCheck->num_rows === 0) {
        log_action("Reset password: email not found - $email");
        echo generateResponse(false, "Invalid email or OTP.", null, 400);
        closeConnection($conn);
        exit;
    }
    $admin = $adminCheck->fetch_assoc();

    if ($admin['otp'] !== $otp) {
        $newAttempts = (int) $admin['otp_attempts'] + 1;
        $conn->query("UPDATE admins SET otp_attempts = $newAttempts WHERE id = {$admin['id']}");
        log_action("OTP mismatch for admin id={$admin['id']}, attempts=$newAttempts");
        echo generateResponse(false, "Invalid OTP.", null, 400);
        closeConnection($conn);
        exit;
    }

    if (time() > strtotime($admin['otp_expires_at'])) {
        log_action("OTP expired for admin id={$admin['id']}");
        echo generateResponse(false, "OTP has expired. Please request a new one.", null, 400);
        closeConnection($conn);
        exit;
    }

    if ($admin['otp_attempts'] >= 3) {
        log_action("OTP attempts exceeded for admin id={$admin['id']}");
        echo generateResponse(false, "Too many attempts. Please request a new OTP.", null, 400);
        closeConnection($conn);
        exit;
    }

    $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
    $updateSql = "UPDATE admins SET password = '$hashedPassword', otp = NULL, otp_expires_at = NULL, otp_attempts = 0 WHERE id = {$admin['id']}";
    if (!$conn->query($updateSql)) {
        log_action("Failed to update password: " . $conn->error);
        throw new Exception("Failed to reset password.");
    }

    log_action("Admin password reset successful for id={$admin['id']}");
    echo generateResponse(true, "Password has been reset successfully.", null, 200);
} catch (\Throwable $e) {
    log_action("Admin reset password exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== ADMIN RESET PASSWORD ATTEMPT END ===");
}
