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
log_action("=== DELETE ORGANISATION ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to super_admin only
    requireRole($decoded, 'super_admin');

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

    // Verify organisation exists
    $checkResult = $conn->query("SELECT name FROM organisations WHERE id=$targetId");

    if (!$checkResult) {
        log_action("Delete organisation check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Delete organisation failed: id=$targetId not found");
        echo generateResponse(false, "Organisation not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $org = $checkResult->fetch_assoc();
    $orgName = $org['name'];

    // Verify organisation has no active clients
    $clientCheck = $conn->query("SELECT COUNT(*) AS total FROM clients WHERE organisation_id=$targetId AND soft_delete=0");

    if (!$clientCheck) {
        log_action("Delete organisation client check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $clientCount = (int) $clientCheck->fetch_assoc()['total'];

    if ($clientCount > 0) {
        log_action("Delete organisation blocked: $clientCount active client(s) attached to id=$targetId ($orgName)");
        echo generateResponse(false, "Cannot delete organisation. There are $clientCount active client(s) attached to this organisation. Please remove them first.", null, 409);
        closeConnection($conn);
        exit;
    }

    // Hard-delete the organisation
    if (!$conn->query("DELETE FROM organisations WHERE id=$targetId")) {
        log_action("Delete organisation query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Organisation deleted successfully: id=$targetId ($orgName) by caller id={$decoded['id']}");

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('deletedOrganisation', ['name' => $orgName]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Organisation deleted successfully.", null, 200);
} catch (\Throwable $e) {
    log_action("Delete organisation exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== DELETE ORGANISATION ATTEMPT END ===");
}
