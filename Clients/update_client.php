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
log_action("=== UPDATE CLIENT ATTEMPT START ===");

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
        echo generateResponse(false, "Client id is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify client exists and is not soft-deleted
    $checkResult = $conn->query("SELECT name FROM clients WHERE id=$targetId AND soft_delete=0");

    if (!$checkResult) {
        log_action("Update client check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Update client failed: id=$targetId not found");
        echo generateResponse(false, "Client not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $existing = $checkResult->fetch_assoc();
    $fields = [];

    // Sanitize provided fields
    $name           = isset($data['name'])            ? trim($conn->real_escape_string($data['name']))  : null;
    $email          = isset($data['email'])           ? trim($conn->real_escape_string($data['email'])) : null;
    $organisationId = isset($data['organisation_id']) ? (int) $data['organisation_id']                  : null;

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

        // Check email not already used by another client
        $emailCheck = $conn->query("SELECT id FROM clients WHERE email='$email' AND id!=$targetId");
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

    if ($organisationId !== null) {
        // Verify new organisation exists
        $orgCheck = $conn->query("SELECT id FROM organisations WHERE id=$organisationId");
        if (!$orgCheck) {
            log_action("Organisation check query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }
        if ($orgCheck->num_rows === 0) {
            echo generateResponse(false, "Organisation not found.", null, 404);
            closeConnection($conn);
            exit;
        }
        $fields[] = "organisation_id=$organisationId";
    }

    // At least one field must be provided
    if (empty($fields)) {
        echo generateResponse(false, "No fields to update. Provide at least one of: name, email, organisation_id.", null, 400);
        closeConnection($conn);
        exit;
    }

    $fields[] = "updated_at=NOW()";
    $setClause = implode(', ', $fields);

    // Update client record
    if (!$conn->query("UPDATE clients SET $setClause WHERE id=$targetId")) {
        log_action("Update client query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Client updated successfully: id=$targetId by caller id={$decoded['id']}");

    // Fetch updated record to return in response
    $updated = $conn->query(
        "SELECT id, organisation_id, name, email, role, created_at, updated_at FROM clients WHERE id=$targetId"
    );
    $client = $updated ? $updated->fetch_assoc() : null;

    // Fetch caller info for audit log
    $clientName = $name ?? $existing['name'];
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('updatedClient', ['name' => $clientName]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Client updated successfully.", ["client" => $client], 200);
} catch (\Throwable $e) {
    log_action("Update client exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== UPDATE CLIENT ATTEMPT END ===");
}
