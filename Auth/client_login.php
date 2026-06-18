<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
require_once __DIR__ . '/../utils/utilityFunctions.php';

// Set CORS and content-type headers
setCorsHeaders();

// Reject non-POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

$conn = getConnection();
log_action("=== CLIENT LOGIN ATTEMPT START ===");

try {
    // Read request body
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    // Sanitize input
    $email    = trim($conn->real_escape_string($data['email'] ?? ''));
    $password = $data['password'] ?? '';
    $url      = trim($data['url'] ?? '');

    // Validate required fields
    if (!$email || !$password || !$url) {
        log_action("Validation failed: Missing email, password or url.");
        echo generateResponse(false, "Missing email, password or url", null, 400);
        closeConnection($conn);
        exit;
    }

    $sql = "SELECT c.id, c.organisation_id, o.name AS organisation_name, o.url AS organisation_url, c.name, c.email, c.password, c.role, c.two_fa, c.soft_delete FROM clients c LEFT JOIN organisations o ON c.organisation_id = o.id WHERE c.email='$email'";
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
        $client = $result->fetch_assoc();
        log_action("Client record fetched for: $email");

        if ((int) $client['soft_delete'] === 1) {
            log_action("Login blocked: client does not exist (soft deleted): $email");
            echo generateResponse(false, "User does not exist", null, 404);
            closeConnection($conn);
            exit;
        }

        // Verify URL matches organisation
        // if (getBaseUrl($url) !== getBaseUrl($client['organisation_url'])) {
        //     log_action("Login blocked: user logging in into the wrong company. email=$email submitted=" . getBaseUrl($url) . " org=" . getBaseUrl($client['organisation_url']));
        //     echo generateResponse(false, "Invalid credentials.", null, 401);
        //     closeConnection($conn);
        //     exit;
        // }

        if (password_verify($password, $client['password'])) {
            log_action("Password verified successfully for client ID: {$client['id']}");

            if ((int) $client['two_fa'] === 1) {
                echo generateResponse(false, "Two-factor authentication required", [
                    "two_fa_required" => true
                ], 200);
                exit;
            }

            $payload = [
                'id'    => $client['id'],
                'email' => $client['email'],
                'role'  => $client['role'],
                'iat'   => time(),
                'exp'   => time() + 1800
            ];

            $jwt = generateJWT($payload);
            log_action("JWT generated for client ID: {$client['id']}");

            $tokenExpiresAt = date('Y-m-d H:i:s', $payload['exp']);
            $jwtEscaped     = $conn->real_escape_string($jwt);

            $updateSql = "UPDATE clients SET token='$jwtEscaped', token_expires_at='$tokenExpiresAt' WHERE id={$client['id']}";
            if (!$conn->query($updateSql)) {
                log_action("Failed to update token for client ID: {$client['id']} | Error: " . $conn->error);
            }

            try {
                // Write to activity log
                audit_log($conn, $client['id'], $client['name'], getLogMessage('clientLoggedIn'), 1);
            } catch (\Throwable $e) {
                log_action("Audit log call failed: " . $e->getMessage());
            }

            echo generateResponse(true, "Login successful.", [
                "token" => $jwt,
                "user"  => [
                    "id"                => $client['id'],
                    "organisation_id"   => $client['organisation_id'],
                    "organisation_name" => $client['organisation_name'],
                    "name"              => $client['name'],
                    "email"             => $client['email'],
                    "role"              => $client['role'],
                    "two_fa"            => (int) $client['two_fa']
                ]
            ], 200);
        } else {
            log_action("Password mismatch for email: $email");
            echo generateResponse(false, "Username or password is wrong", null, 401);
        }
    } else {
        log_action("Login failed: No matching client for email: $email");
        echo generateResponse(false, "Request cannot be processed.", null, 401);
    }
} catch (\Throwable $e) {
    log_action("Client login exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT LOGIN ATTEMPT END ===");
}
