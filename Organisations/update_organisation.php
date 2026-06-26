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
log_action("=== UPDATE ORGANISATION ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read request body
    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    $targetId = isset($data['id']) ? (int) $data['id'] : 0;

    // Validate target id
    if (!$targetId) {
        echo generateResponse(false, "Organisation id is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    $fields = [];

    // Sanitize provided fields
    $name  = isset($data['name'])  ? trim($conn->real_escape_string($data['name']))  : null;
    $email = isset($data['email']) ? trim($conn->real_escape_string($data['email'])) : null;
    $url   = isset($data['url'])   ? trim($conn->real_escape_string($data['url']))   : null;

    if ($name !== null) {
        if ($name === '') {
            echo generateResponse(false, "Name cannot be empty.", null, 400);
            closeConnection($conn);
            exit;
        }
        $fields[] = "name='$name'";
    }

    if ($email !== null) {
        // Validate email format
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            log_action("Validation failed: invalid email format - $email");
            echo generateResponse(false, "Invalid email address.", null, 400);
            closeConnection($conn);
            exit;
        }

        // Check email not already used by another organisation
        $emailCheck = $conn->query("SELECT id FROM organisations WHERE email='$email' AND id!=$targetId");
        if (!$emailCheck) {
            log_action("Email check query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }
        if ($emailCheck->num_rows > 0) {
            echo generateResponse(false, "Email already in use.", null, 409);
            closeConnection($conn);
            exit;
        }

        $fields[] = "email='$email'";
    }

    if ($url !== null) {
        // Validate URL format
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            log_action("Validation failed: invalid url format - $url");
            echo generateResponse(false, "Invalid url.", null, 400);
            closeConnection($conn);
            exit;
        }
        $fields[] = "url='$url'";
    }

    // At least one field must be provided
    if (empty($fields)) {
        echo generateResponse(false, "No fields to update. Provide at least one of: name, email, url.", null, 400);
        closeConnection($conn);
        exit;
    }

    $fields[] = "updated_at=NOW()";

    // Verify organisation exists
    $checkResult = $conn->query("SELECT name FROM organisations WHERE id=$targetId");

    if (!$checkResult) {
        log_action("Update organisation check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Update organisation failed: id=$targetId not found");
        echo generateResponse(false, "Organisation not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $existingOrg = $checkResult->fetch_assoc();
    $orgName = $name ?? $existingOrg['name'];

    $setClause = implode(', ', $fields);

    // Update organisation record
    if (!$conn->query("UPDATE organisations SET $setClause WHERE id=$targetId")) {
        log_action("Update organisation query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Organisation updated successfully: id=$targetId by caller id={$decoded['id']}");

    // Fetch updated record to return in response
    $updated = $conn->query(
        "SELECT id, name, email, url, created_at, updated_at FROM organisations WHERE id=$targetId"
    );
    $organisation = $updated ? $updated->fetch_assoc() : null;

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('updatedOrganisation', ['name' => $orgName]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Organisation updated successfully.", ["organisation" => $organisation], 200);
} catch (\Throwable $e) {
    log_action("Update organisation exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== UPDATE ORGANISATION ATTEMPT END ===");
}
