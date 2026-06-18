<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../utils/response.php';
require_once __DIR__ . '/../utils/utilityFunctions.php';

// Set CORS and content-type headers
setCorsHeaders();

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
log_action("=== READ ACTIVITY LOGS ATTEMPT START ===");

// Map integer status codes to human-readable labels
$statusLabels = [0 => 'pending', 1 => 'successful', 2 => 'failed'];

try {
    // Authenticate request via JWT
    $decoded = authenticateRequest($conn);

    // Restrict to admins only
    requireAdminRole($decoded);

    // Read query params
    $id       = $_GET['id']        ?? null;
    $page     = $_GET['page']      ?? 1;
    $perPage  = $_GET['per_page']  ?? 20;
    $dateFrom = $_GET['date_from'] ?? null;
    $dateTo   = $_GET['date_to']   ?? null;

    // Validate pagination params
    $page    = max(1, (int) $page);
    $perPage = min(100, max(1, (int) $perPage));
    $offset  = ($page - 1) * $perPage;

    // Validate date range params
    $dateConditions = [];
    if ($dateFrom !== null) {
        $d = DateTime::createFromFormat('Y-m-d', $dateFrom);
        if (!$d || $d->format('Y-m-d') !== $dateFrom) {
            log_action("Validation failed: invalid date_from - $dateFrom");
            echo generateResponse(false, "Invalid date_from format. Use YYYY-MM-DD.", null, 400);
            closeConnection($conn);
            exit;
        }
        $dateFrom = $conn->real_escape_string($dateFrom);
        $dateConditions[] = "DATE(created_at) >= '$dateFrom'";
    }
    if ($dateTo !== null) {
        $d = DateTime::createFromFormat('Y-m-d', $dateTo);
        if (!$d || $d->format('Y-m-d') !== $dateTo) {
            log_action("Validation failed: invalid date_to - $dateTo");
            echo generateResponse(false, "Invalid date_to format. Use YYYY-MM-DD.", null, 400);
            closeConnection($conn);
            exit;
        }
        $dateTo = $conn->real_escape_string($dateTo);
        $dateConditions[] = "DATE(created_at) <= '$dateTo'";
    }
    if ($dateFrom !== null && $dateTo !== null && $dateFrom > $dateTo) {
        log_action("Validation failed: date_from ($dateFrom) is after date_to ($dateTo)");
        echo generateResponse(false, "date_from cannot be after date_to.", null, 400);
        closeConnection($conn);
        exit;
    }
    $whereClause = !empty($dateConditions) ? "WHERE " . implode(" AND ", $dateConditions) : "";

    // Single log lookup by id
    if ($id !== null) {
        if (!ctype_digit((string) $id)) {
            log_action("Validation failed: invalid id - $id");
            echo generateResponse(false, "Invalid log id.", null, 400);
            closeConnection($conn);
            exit;
        }

        $id = (int) $id;
        $result = $conn->query(
            "SELECT full_name, activity, status, created_at FROM activity_logs WHERE id=$id"
        );

        if (!$result) {
            log_action("Read activity log query failed: " . $conn->error);
            echo generateResponse(false, "An error occured", null, 500);
            closeConnection($conn);
            exit;
        }

        if ($result->num_rows === 0) {
            log_action("Read activity log failed: id=$id not found");
            echo generateResponse(false, "Log not found.", null, 404);
            closeConnection($conn);
            exit;
        }

        $log = $result->fetch_assoc();
        // Map status integer to label
        $log['status'] = $statusLabels[(int) $log['status']] ?? 'unknown';

        log_action("Activity log retrieved successfully: id=$id");
        echo generateResponse(true, "Activity log retrieved successfully.", ["log" => $log], 200);
        closeConnection($conn);
        exit;
    }

    // Count total logs for pagination metadata
    $countResult = $conn->query("SELECT COUNT(*) AS total FROM activity_logs $whereClause");

    if (!$countResult) {
        log_action("Read activity logs count query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $total = (int) $countResult->fetch_assoc()['total'];
    $pages = $perPage > 0 ? (int) ceil($total / $perPage) : 1;

    // Fetch paginated logs, newest first
    $result = $conn->query(
        "SELECT full_name, activity, status, created_at FROM activity_logs $whereClause ORDER BY created_at DESC LIMIT $perPage OFFSET $offset"
    );

    if (!$result) {
        log_action("Read activity logs query failed: " . $conn->error);
        echo generateResponse(false, "An error occured", null, 500);
        closeConnection($conn);
        exit;
    }

    $logs = [];
    while ($row = $result->fetch_assoc()) {
        // Map status integer to label
        $row['status'] = $statusLabels[(int) $row['status']] ?? 'unknown';
        $logs[] = $row;
    }

    log_action("Activity logs retrieved successfully: page=$page per_page=$perPage total=$total");
    echo generateResponse(true, "Activity logs retrieved successfully.", [
        "logs"       => $logs,
        "pagination" => [
            "total"    => $total,
            "page"     => $page,
            "per_page" => $perPage,
            "pages"    => $pages
        ]
    ], 200);
} catch (\Throwable $e) {
    log_action("Read activity logs exception: " . $e->getMessage());
    echo generateResponse(false, "An error occured", null, 500);
} finally {
    closeConnection($conn);
    log_action("=== READ ACTIVITY LOGS ATTEMPT END ===");
}
