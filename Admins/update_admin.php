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
log_action("=== UPDATE ADMIN ATTEMPT START ===");

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
        echo generateResponse(false, "Admin id is required.", null, 400);
        closeConnection($conn);
        exit;
    }

    $callerId   = (int) $decoded['id'];
    $callerRole = $decoded['role'];

    // Regular admins can only update their own record
    if ($callerRole !== 'super_admin' && $callerId !== $targetId) {
        log_action("Update admin blocked: caller id=$callerId attempted to update id=$targetId");
        echo generateResponse(false, "You are not authorized to update another admin.", null, 403);
        closeConnection($conn);
        exit;
    }

    // Collect fields to update
    $fields = [];

    // Sanitize provided fields
    $firstname = isset($data['firstname']) ? trim($conn->real_escape_string($data['firstname'])) : null;
    $lastname  = isset($data['lastname'])  ? trim($conn->real_escape_string($data['lastname']))  : null;
    $password  = $data['password'] ?? null;

    if ($firstname !== null) {
        if ($firstname === '') {
            echo generateResponse(false, "Firstname cannot be empty.", null, 400);
            closeConnection($conn);
            exit;
        }
        $fields[] = "firstname='$firstname'";
    }

    if ($lastname !== null) {
        if ($lastname === '') {
            echo generateResponse(false, "Lastname cannot be empty.", null, 400);
            closeConnection($conn);
            exit;
        }
        $fields[] = "lastname='$lastname'";
    }

    if ($password !== null) {
        // Only super_admin can change passwords
        if ($callerRole !== 'super_admin') {
            log_action("Update admin blocked: caller id=$callerId attempted to change password without super_admin role");
            echo generateResponse(false, "Only super admins can change passwords.", null, 403);
            closeConnection($conn);
            exit;
        }
        // Hash new password
        $hashedPassword = $conn->real_escape_string(password_hash($password, PASSWORD_BCRYPT));
        $fields[] = "password='$hashedPassword'";
    }

    // At least one field must be provided
    if (empty($fields)) {
        echo generateResponse(false, "No fields to update. Provide at least one of: firstname, lastname, password.", null, 400);
        closeConnection($conn);
        exit;
    }

    $fields[] = "updated_at=NOW()";

    // Verify target admin exists and is not soft-deleted
    $checkResult = $conn->query("SELECT id FROM admins WHERE id=$targetId AND soft_delete=0");

    if (!$checkResult) {
        log_action("Update admin check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows === 0) {
        log_action("Update admin failed: id=$targetId not found");
        echo generateResponse(false, "Admin not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $setClause = implode(', ', $fields);

    // Update admin record
    if (!$conn->query("UPDATE admins SET $setClause WHERE id=$targetId")) {
        log_action("Update admin query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Admin updated successfully: id=$targetId by caller id=$callerId");

    // Fetch updated record to return in response
    $updated = $conn->query(
        "SELECT id, firstname, lastname, email, role FROM admins WHERE id=$targetId"
    );
    $admin = $updated ? $updated->fetch_assoc() : null;

    // Fetch caller info for audit log
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if ($callerResult && $callerResult->num_rows > 0) {
        $caller = $callerResult->fetch_assoc();
        $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];
        try {
            // Write to activity log
            $targetName = $admin ? $admin['firstname'] . ' ' . $admin['lastname'] : '';
            audit_log($conn, $callerId, $callerFullName, getLogMessage('updatedAdmin', ['name' => $targetName]), 1);
        } catch (\Throwable $e) {
            log_action("Audit log call failed: " . $e->getMessage());
        }
    }

    echo generateResponse(true, "Admin updated successfully.", ["admin" => $admin], 200);
} catch (\Throwable $e) {
    log_action("Update admin exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== UPDATE ADMIN ATTEMPT END ===");
}
