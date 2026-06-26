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
log_action("=== UPDATE CATEGORY ATTEMPT START ===");

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
        echo generateResponse(false, "Category id is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Sanitize input
    $name = isset($data['name']) ? trim($conn->real_escape_string($data['name'])) : null;

    // Validate required fields
    if ($name === null || $name === '') {
        echo generateResponse(false, "Name is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Verify category exists
    $checkResult = $conn->query("SELECT id FROM categories WHERE id=$targetId");

    if (!$checkResult) {
        log_action("Update category check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Update category failed: id=$targetId not found");
        echo generateResponse(false, "Category not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    // Check name not already used by another category
    $nameCheck = $conn->query("SELECT id FROM categories WHERE name='$name' AND id!=$targetId");

    if (!$nameCheck) {
        log_action("Name check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($nameCheck->num_rows > 0) {
        echo generateResponse(false, "A category with that name already exists.", null, 409);
        closeConnection($conn);
        exit;
    }

    // Update category record
    if (!$conn->query("UPDATE categories SET name='$name', updated_at=NOW() WHERE id=$targetId")) {
        log_action("Update category query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Category updated successfully: id=$targetId name=$name by caller id={$decoded['id']}");

    // Fetch caller info for audit log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            audit_log($conn, $callerId, $callerFullName, getLogMessage('updatedCategory', ['name' => $name]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Category updated successfully.", [
        "category" => ["id" => $targetId, "name" => $name]
    ], 200);
} catch (\Throwable $e) {
    log_action("Update category exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== UPDATE CATEGORY ATTEMPT END ===");
}
