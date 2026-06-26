<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
include '../utils/utilityFunctions.php';


// Set CORS and content-type headers
setCorsHeaders();

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    setCorsHeaders();
    http_response_code(200);
    exit;
}

// Reject non-POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo generateResponse(false, "Method not allowed. Use POST.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

// Open DB connection
$conn = getConnection();
log_action("=== CREATE CLIENT ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read request body
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    // Sanitize input
    $organisationId = isset($data['organisation_id']) ? (int) $data['organisation_id'] : 0;
    $name           = trim($conn->real_escape_string($data['name']     ?? ''));
    $email          = trim($conn->real_escape_string($data['email']    ?? ''));
    $password       = $data['password'] ?? '';

    // Validate required fields
    if (!$organisationId || !$name || !$email || !$password) {
        echo generateResponse(false, "organisation_id, name, email and password are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        log_action("Validation failed: invalid email format - $email");
        echo generateResponse(false, "Invalid email address.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify organisation exists
    $orgCheck = $conn->query("SELECT id FROM organisations WHERE id=$organisationId");

    if (!$orgCheck) {
        log_action("Organisation check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($orgCheck->num_rows === 0) {
        log_action("Create client failed: organisation id=$organisationId not found");
        echo generateResponse(false, "Organisation not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    // Check email uniqueness
    $emailCheck = $conn->query("SELECT id FROM clients WHERE email='$email'");

    if (!$emailCheck) {
        log_action("Email check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($emailCheck->num_rows > 0) {
        log_action("Create client failed: email already in use - $email");
        echo generateResponse(false, "Email already in use.", null, 409);
        closeConnection($conn);
        exit;
    }

    // Hash password
    $hashedPassword = $conn->real_escape_string(password_hash($password, PASSWORD_BCRYPT));

    // Insert client record
    $insertSql = "INSERT INTO clients (organisation_id, name, email, password)
                  VALUES ($organisationId, '$name', '$email', '$hashedPassword')";

    if (!$conn->query($insertSql)) {
        log_action("Failed to create client: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $clientId = $conn->insert_id;
    log_action("Client created successfully: id=$clientId, email=$email");

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('createdClient', ['name' => $name]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Client created successfully.", [
        "client" => [
            "id"              => $clientId,
            "organisation_id" => $organisationId,
            "name"            => $name,
            "email"           => $email,
            "role"            => "user"
        ]
    ], 201);
} catch (\Throwable $e) {
    log_action("Create client exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CREATE CLIENT ATTEMPT END ===");
}
