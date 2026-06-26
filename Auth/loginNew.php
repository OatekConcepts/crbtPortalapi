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
log_action("=== ADMIN LOGIN ATTEMPT START ===");

try {
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    $email = trim($conn->real_escape_string($data['email'] ?? ''));
    $password = $data['password'] ?? '';

    if (!$email || !$password) {
        log_action("Validation failed: Missing email or password.");
        echo generateResponse(false, "Missing email or password", null, 400);
        closeConnection($conn);
        exit;
    }

    $sql = "SELECT id, firstname, lastname, email, password, role, two_fa, soft_delete FROM admins WHERE email='$email'";
    log_action("Executing SQL query: $sql");

    $result = $conn->query($sql);

    if (!$result) {
        log_action("Query failed: " . $conn->error);
        echo generateResponse(false, "Database error occurred.", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Query executed. Rows found: " . $result->num_rows);

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        log_action("User record fetched for: $email");

        if ((int) $user['soft_delete'] === 1) {
            log_action("Login blocked: user does not exist (soft deleted): $email");
            echo generateResponse(false, "User does not exist", null, 404);
            closeConnection($conn);
            exit;
        }

        if (password_verify($password, $user['password'])) {
            log_action("Password verified successfully for user ID: {$user['id']}");

            // ---- 2FA CHECK ----
            if ((int) $user['two_fa'] === 1) {
                // Generate 6-digit OTP
                $otp = generateRandomNumbersString();
                $otpExpires = date('Y-m-d H:i:s', strtotime('+5 minutes'));

                // Generate a temporary token (random string)
                $tempToken = bin2hex(random_bytes(32)); // 64 hex chars
                $tempExpires = date('Y-m-d H:i:s', strtotime('+5 minutes'));

                // Update admin with temp token and OTP
                $updateSql = "UPDATE admins SET 
                              token = '$tempToken', 
                              token_expires_at = '$tempExpires',
                              otp = '$otp', 
                              otp_expires_at = '$otpExpires', 
                              otp_attempts = 0 
                              WHERE id = {$user['id']}";
                if (!$conn->query($updateSql)) {
                    log_action("Failed to update OTP/token: " . $conn->error);
                    throw new Exception("Failed to process request.");
                }

                // Send OTP via Postmark (or email)
                $mailSent = sendMails($otp, $email); // uses Postmark – no PHPMailer needed
                if (!$mailSent) {
                    log_action("Failed to send OTP email to $email");
                    // Optionally, you can still proceed to avoid leaking info
                }

                log_action("2FA OTP sent to $email, temp token generated");
                echo generateResponse(true, "Two-factor authentication required. OTP sent to your email.", [
                    'two_fa_required' => true,
                    'temp_token'      => $tempToken,
                    'expires_in'      => '5 minutes'
                ], 200);
                closeConnection($conn);
                exit;
            }

            // ---- 2FA NOT ENABLED – proceed with normal login ----
            $payload = [
                'id'    => $user['id'],
                'email' => $user['email'],
                'role'  => $user['role'],
                'iat'   => time(),
                'exp'   => time() + 1800
            ];

            $jwt = generateJWT($payload);
            log_action("JWT generated for user ID: {$user['id']}");

            $tokenExpiresAt = date('Y-m-d H:i:s', $payload['exp']);
            $jwtEscaped = $conn->real_escape_string($jwt);

            $updateSql = "UPDATE admins SET token='$jwtEscaped', token_expires_at='$tokenExpiresAt' WHERE id={$user['id']}";

            if (!$conn->query($updateSql)) {
                log_action("Failed to update token for user ID: {$user['id']} | Error: " . $conn->error);
            }

            try {
                $fullName = $user['firstname'] . ' ' . $user['lastname'];
                audit_log($conn, $user['id'], $fullName, getLogMessage('login'), 1);
            } catch (\Throwable $e) {
                log_action("Audit log call failed: " . $e->getMessage());
            }

            echo generateResponse(true, "Login successful.", [
                "token" => $jwt,
                "user" => [
                    "id"        => $user["id"],
                    "firstname" => $user["firstname"],
                    "lastname"  => $user["lastname"],
                    "email"     => $user["email"],
                    "role"      => $user["role"],
                    "two_fa"    => (int) $user["two_fa"]
                ]
            ], 200);
        } else {
            log_action("Password mismatch for email: $email");
            echo generateResponse(false, "Username or password is wrong", null, 401);
        }
    } else {
        log_action("Login failed: No matching user for email: $email");
        echo generateResponse(false, "Request cannot be processed.", null, 401);
    }
} catch (\Throwable $e) {
    log_action("Admin login exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== ADMIN LOGIN ATTEMPT END ===");
}
