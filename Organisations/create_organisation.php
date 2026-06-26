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
log_action("=== CREATE ORGANISATION ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read request body
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    // Sanitize input
    $name  = trim($conn->real_escape_string($data['name']  ?? ''));
    $email = trim($conn->real_escape_string($data['email'] ?? ''));
    $url   = trim($conn->real_escape_string($data['url']   ?? ''));

    // Validate required fields
    if (!$name || !$email || !$url) {
        echo generateResponse(false, "Name, email and url are required.", null, 400);
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

    // Validate URL format
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        log_action("Validation failed: invalid url format - $url");
        echo generateResponse(false, "Invalid url.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check email uniqueness
    $checkResult = $conn->query("SELECT id FROM organisations WHERE email='$email'");

    if (!$checkResult) {
        log_action("Email check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows > 0) {
        log_action("Create organisation failed: email already in use - $email");
        echo generateResponse(false, "Email already in use.", null, 409);
        closeConnection($conn);
        exit;
    }

    // Insert organisation record
    $insertSql = "INSERT INTO organisations (name, email, url) VALUES ('$name', '$email', '$url')";

    if (!$conn->query($insertSql)) {
        log_action("Failed to create organisation: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $orgId = $conn->insert_id;
    log_action("Organisation created successfully: id=$orgId, name=$name");

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('createdOrganisation', ['name' => $name]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Organisation created successfully.", [
        "organisation" => [
            "id"    => $orgId,
            "name"  => $name,
            "email" => $email,
            "url"   => $url
        ]
    ], 201);
} catch (\Throwable $e) {
    log_action("Create organisation exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CREATE ORGANISATION ATTEMPT END ===");
}
