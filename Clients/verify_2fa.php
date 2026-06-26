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
log_action("=== CLIENT VERIFY 2FA ATTEMPT START ===");

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

    // Find client by temp token
    $clientCheck = $conn->query("SELECT id, name, email, role, two_fa, otp, otp_expires_at, otp_attempts, token_expires_at 
                                 FROM clients 
                                 WHERE token = '$tempToken' AND soft_delete = 0");
    if (!$clientCheck || $clientCheck->num_rows === 0) {
        log_action("Verify 2FA: temp token not found");
        echo generateResponse(false, "Invalid or expired temp token.", null, 400);
        closeConnection($conn);
        exit;
    }
    $client = $clientCheck->fetch_assoc();

    // Check if temp token expired
    $tokenExp = strtotime($client['token_expires_at']);
    if (time() > $tokenExp) {
        log_action("Temp token expired for client id={$client['id']}");
        echo generateResponse(false, "Temp token has expired. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify OTP
    if ($client['otp'] !== $otp) {
        $newAttempts = (int) $client['otp_attempts'] + 1;
        $conn->query("UPDATE clients SET otp_attempts = $newAttempts WHERE id = {$client['id']}");
        log_action("OTP mismatch for client id={$client['id']}, attempts=$newAttempts");
        echo generateResponse(false, "Invalid OTP.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check OTP expiry
    $otpExp = strtotime($client['otp_expires_at']);
    if (time() > $otpExp) {
        log_action("OTP expired for client id={$client['id']}");
        echo generateResponse(false, "OTP has expired. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    if ($client['otp_attempts'] >= 3) {
        log_action("OTP attempts exceeded for client id={$client['id']}");
        echo generateResponse(false, "Too many attempts. Please login again.", null, 400);
        closeConnection($conn);
        exit;
    }

    // OTP valid – generate final JWT
    $payload = [
        'id'    => (int) $client['id'],
        'email' => $client['email'],
        'role'  => $client['role'],
        'iat'   => time(),
        'exp'   => time() + 1800
    ];
    $jwt = generateJWT($payload);

    // Update client: clear temp token, set final JWT
    $tokenExpires = date('Y-m-d H:i:s', $payload['exp']);
    $conn->query("UPDATE clients SET 
                  token = '$jwt', 
                  token_expires_at = '$tokenExpires',
                  otp = NULL, 
                  otp_expires_at = NULL, 
                  otp_attempts = 0 
                  WHERE id = {$client['id']}");

    // Fetch organisation name for response (optional)
    $orgQuery = $conn->query("SELECT name FROM organisations WHERE id = (SELECT organisation_id FROM clients WHERE id = {$client['id']})");
    $orgName = $orgQuery ? $orgQuery->fetch_assoc()['name'] : null;

    log_action("2FA verification successful for client id={$client['id']}");
    echo generateResponse(true, "Login successful.", [
        'token' => $jwt,
        'user' => [
            'id'                => $client['id'],
            'name'              => $client['name'],
            'email'             => $client['email'],
            'role'              => $client['role'],
            'two_fa'            => (int) $client['two_fa'],
            'organisation_name' => $orgName
        ]
    ], 200);
} catch (\Throwable $e) {
    log_action("Verify 2FA exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT VERIFY 2FA ATTEMPT END ===");
}
