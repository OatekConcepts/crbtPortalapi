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
log_action("=== CLIENT CHANGE PASSWORD ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to user role only
    requireRole($decoded, 'user');

    // Read request body
    $data = getRequestBody();

    $oldPassword     = $data['old_password']     ?? '';
    $newPassword     = $data['new_password']     ?? '';
    $confirmPassword = $data['confirm_password'] ?? '';

    // Validate required fields
    if (!$oldPassword || !$newPassword || !$confirmPassword) {
        echo generateResponse(false, "old_password, new_password and confirm_password are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Confirm new password matches
    if ($newPassword !== $confirmPassword) {
        echo generateResponse(false, "New password and confirm password do not match.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Extract caller id from token
    $id = (int) $decoded['id'];

    // Fetch current hashed password — exclude soft-deleted accounts
    $result = $conn->query("SELECT password FROM clients WHERE id=$id AND soft_delete=0");

    if (!$result) {
        log_action("Client change password query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($result->num_rows === 0) {
        log_action("Client change password failed: id=$id not found");
        echo generateResponse(false, "User not found.", null, 404);
        closeConnection($conn);
        exit;
    }

    $client = $result->fetch_assoc();

    // Verify old password against stored hash
    if (!password_verify($oldPassword, $client['password'])) {
        log_action("Client change password failed: old password mismatch for id=$id");
        echo generateResponse(false, "Old password is incorrect.", null, 401);
        closeConnection($conn);
        exit;
    }

    // Hash new password
    $hashedPassword = $conn->real_escape_string(password_hash($newPassword, PASSWORD_BCRYPT));

    // Update password in DB
    if (!$conn->query("UPDATE clients SET password='$hashedPassword', updated_at=NOW() WHERE id=$id")) {
        log_action("Client change password update failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    log_action("Client password changed successfully for id=$id");

    echo generateResponse(true, "Password changed successfully.", null, 200);
} catch (\Throwable $e) {
    log_action("Client change password exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CLIENT CHANGE PASSWORD ATTEMPT END ===");
}
