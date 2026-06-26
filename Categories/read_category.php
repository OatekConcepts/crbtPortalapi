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

// Reject non-GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo generateResponse(false, "Method not allowed. Use GET.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

// Open DB connection
$conn = getConnection();
log_action("=== READ CATEGORY ATTEMPT START ===");

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read query params
    $id = $_GET['id'] ?? null;

    // Single category lookup by id
    if ($id !== null) {
        if (!ctype_digit((string) $id)) {
            log_action("Validation failed: invalid id - $id");
            echo generateResponse(false, "Invalid category id.", null, 400);
            closeConnection($conn);
            exit;
        }

        $id = (int) $id;
        $result = $conn->query(
            "SELECT id, name, created_at, updated_at FROM categories WHERE id=$id"
        );

        if (!$result) {
            log_action("Read category query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }

        if ($result->num_rows === 0) {
            log_action("Read category failed: id=$id not found");
            echo generateResponse(false, "Category not found.", null, 404);
            closeConnection($conn);
            exit;
        }

        $category = $result->fetch_assoc();
        log_action("Category retrieved successfully: id=$id");
        echo generateResponse(true, "Category retrieved successfully.", ["category" => $category], 200);
        closeConnection($conn);
        exit;
    }

    // Fetch all categories
    $result = $conn->query("SELECT id, name, created_at, updated_at FROM categories");

    if (!$result) {
        log_action("Read categories query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $categories = [];
    while ($row = $result->fetch_assoc()) {
        $categories[] = $row;
    }

    log_action("Categories retrieved successfully: count=" . count($categories));
    echo generateResponse(true, "Categories retrieved successfully.", ["categories" => $categories], 200);
} catch (\Throwable $e) {
    log_action("Read category exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== READ CATEGORY ATTEMPT END ===");
}
