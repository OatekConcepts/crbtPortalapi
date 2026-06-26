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
require_once __DIR__ . '/../jwt.php';

$conn = getConnection();
log_action("=== ADMIN VERIFY 2FA ATTEMPT START ===");

try {
    $data = getRequestBody();
    log_action("Raw Input: " . json_encode($data));

    $tempToken = trim($data['temp_token'] ?? '');
    $otp = trim($data['otp'] ?? '');

    if (!$tempToken || !$otp) {
        log_action("Validation failed: missing temp_token or otp");
        echo generateResponse(false, "Temp token and OTP are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    $adminCheck = $conn->query("SELECT id, firstname, lastname, email, role, two_fa, otp, otp_expires_at, otp_attempts, token_expires_at 
                                FROM admins WHERE token = '$tempToken' AND soft_delete = 0");
    if (!$adminCheck || $adminCheck->num_rows === 0) {
        log_action("Verify 2FA: temp token not found");
        echo generateResponse(false, "Invalid or expired temp token.", null, 400);
        closeConnection($conn);
        exit;
    }
    $admin = $adminCheck->fetch_assoc();

    // Check temp token expiry
    if (time() > strtotime($admin['token_expires_at'])) {
        log_action("Temp token expired for admin id={$admin['id']}");
        echo generateResponse(false, "Temp token has expired. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify OTP
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
        echo generateResponse(false, "OTP has expired. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    if ($admin['otp_attempts'] >= 3) {
        log_action("OTP attempts exceeded for admin id={$admin['id']}");
        echo generateResponse(false, "Too many attempts. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Generate final JWT
    $payload = [
        'id' => (int) $admin['id'],
        'email' => $admin['email'],
        'role' => $admin['role'],
        'iat' => time(),
        'exp' => time() + 1800
    ];
    $jwt = generateJWT($payload);

    $tokenExpires = date('Y-m-d H:i:s', $payload['exp']);
    $conn->query("UPDATE admins SET 
                  token = '$jwt',
                  token_expires_at = '$tokenExpires',
                  otp = NULL,
                  otp_expires_at = NULL,
                  otp_attempts = 0
                  WHERE id = {$admin['id']}");

    log_action("2FA verification successful for admin id={$admin['id']}");
    echo generateResponse(true, "Login successful.", [
        'token' => $jwt,
        'user' => [
            'id' => $admin['id'],
            'firstname' => $admin['firstname'],
            'lastname' => $admin['lastname'],
            'email' => $admin['email'],
            'role' => $admin['role'],
            'two_fa' => (int) $admin['two_fa']
        ]
    ], 200);
} catch (\Throwable $e) {
    log_action("Admin verify 2FA exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== ADMIN VERIFY 2FA ATTEMPT END ===");
}
