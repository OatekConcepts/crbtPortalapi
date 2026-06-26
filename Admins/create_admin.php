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
log_action("=== CREATE ADMIN ATTEMPT START ===");

try {
    $decoded = authenticateRequest($conn);
    //check if the person is super admin
    requireRole($decoded, 'super_admin');

    // Fetch the calling admin's name for the activity log
    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");

    if (!$callerResult || $callerResult->num_rows === 0) {
        log_action("Create admin blocked: caller id=$callerId not found");
        echo generateResponse(false, "Invalid or expired token.", null, 401);
        closeConnection($conn);
        exit;
    }

    $caller = $callerResult->fetch_assoc();
    $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];

    $data = getRequestBody();
    log_action("Raw Input Data: " . json_encode($data));

    // Sanitize input
    $firstname = trim($conn->real_escape_string($data['firstname'] ?? ''));
    $lastname = trim($conn->real_escape_string($data['lastname'] ?? ''));
    $email = trim($conn->real_escape_string($data['email'] ?? ''));
    $password = $data['password'] ?? '';
    $role = trim($conn->real_escape_string($data['role'] ?? 'admin'));

    // Validation: required fields
    if (!$firstname || !$lastname || !$email || !$password) {
        log_action("Validation failed: Missing required fields.");
        echo generateResponse(false, "Firstname, lastname, email and password are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        log_action("Validation failed: Invalid email format - $email");
        echo generateResponse(false, "Invalid email address.", null, 400);
        closeConnection($conn);
        exit;
    }

    $allowedRoles = ['admin', 'super_admin'];
    if (!in_array($role, $allowedRoles)) {
        log_action("Validation failed: Invalid role - $role");
        echo generateResponse(false, "Invalid role specified.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check if email already exists
    $checkResult = $conn->query("SELECT id FROM admins WHERE email='$email'");

    if (!$checkResult) {
        log_action("Email check query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    if ($checkResult->num_rows > 0) {
        log_action("Create admin failed: email already in use - $email");
        echo generateResponse(false, "Email already in use.", null, 409);
        closeConnection($conn);
        exit;
    }

    $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

    $insertSql = "INSERT INTO admins (firstname, lastname, email, password, role)
            VALUES ('$firstname', '$lastname', '$email', '$hashedPassword', '$role')";

    if (!$conn->query($insertSql)) {
        log_action("Failed to create admin: " . $conn->error);
        echo generateResponse(false, "Error creating admin.", null, 500);
        closeConnection($conn);
        exit;
    }

    $adminId = $conn->insert_id;
    log_action("Admin created successfully: id=$adminId, email=$email, role=$role");

    try {
        audit_log($conn, $callerId, $callerFullName, getLogMessage('createdAdmin', ['name' => "$firstname $lastname"]), 1);
    } catch (\Throwable $e) {
        log_action("Audit log call failed: " . $e->getMessage());
    }

    echo generateResponse(true, "Admin created successfully.", [
        "admin" => [
            "id" => $adminId,
            "firstname" => $firstname,
            "lastname" => $lastname,
            "email" => $email,
            "role" => $role
        ]
    ], 201);
} catch (\Throwable $e) {
    log_action("Create admin exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== CREATE ADMIN ATTEMPT END ===");
}
