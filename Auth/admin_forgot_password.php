<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
require_once __DIR__ . '/../utils/utilityFunctions.php';

setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';

$conn = getConnection();
log_action("=== ADMIN FORGOT PASSWORD ATTEMPT START ===");

try {
    $data = getRequestBody();
    log_action("Raw Input: " . json_encode($data));

    $email = trim($data['email'] ?? '');
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        log_action("Validation failed: invalid email");
        echo generateResponse(false, "Valid email is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    $adminCheck = $conn->query("SELECT id, firstname FROM admins WHERE email = '$email' AND soft_delete = 0");
    if (!$adminCheck || $adminCheck->num_rows === 0) {
        log_action("Forgot password: email not found - $email");
        echo generateResponse(true, "If the email exists, an OTP has been sent.", null, 200);
        closeConnection($conn);
        exit;
    }
    $admin = $adminCheck->fetch_assoc();

    $otp = generateRandomNumbersString();
    $otpExpires = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    $updateSql = "UPDATE admins SET otp = '$otp', otp_expires_at = '$otpExpires', otp_attempts = 0 WHERE id = {$admin['id']}";
    if (!$conn->query($updateSql)) {
        log_action("Failed to update OTP: " . $conn->error);
        throw new Exception("Failed to process request.");
    }

    $mailSent = sendMails($otp, $email);
    if (!$mailSent) {
        log_action("Failed to send OTP email to $email");
    }

    log_action("Admin forgot password OTP sent to $email");
    echo generateResponse(true, "If the email exists, an OTP has been sent.", null, 200);
} catch (\Throwable $e) {
    log_action("Admin forgot password exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== ADMIN FORGOT PASSWORD ATTEMPT END ===");
}
