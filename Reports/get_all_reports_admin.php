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

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    echo generateResponse(false, "Method not allowed. Use GET.", null, 405);
    exit;
}

require_once __DIR__ . '/../utils/conn.php';
require_once __DIR__ . '/../log.php';
require_once __DIR__ . '/../jwt.php';

$conn = getConnection();
log_action("=== GET REPORTS ATTEMPT START ===");

try {
    // Authenticate and authorise
    $decoded = authenticateRequest($conn);
    requireAdminRole($decoded);

    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if (!$callerResult || $callerResult->num_rows === 0) {
        log_action("Get reports blocked: caller id=$callerId not found");
        echo generateResponse(false, "Invalid or expired token.", null, 401);
        closeConnection($conn);
        exit;
    }
    $caller = $callerResult->fetch_assoc();
    $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];


    // Parse query parameters (for filtering and pagination)
    $limit  = isset($_GET['limit']) ? (int) $_GET['limit'] : 50;
    $offset = isset($_GET['offset']) ? (int) $_GET['offset'] : 0;
    $orgId  = isset($_GET['organisation_id']) ? (int) $_GET['organisation_id'] : null;
    $catId  = isset($_GET['category_id']) ? (int) $_GET['category_id'] : null;

    // Build WHERE clause
    $where = [];
    if ($orgId) $where[] = "ru.organisation_id = $orgId";
    if ($catId) $where[] = "ru.category_id = $catId";
    $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';


    // Build the main query (join with upload, org, category)

    $sql = "SELECT 
                r.*,
                ru.id AS upload_id,
                ru.name AS upload_name,
                ru.filename,
                ru.file_path,
                ru.month,
                ru.year,
                ru.gross_revenue,
                ru.revenue_ex_vat,
                ru.revenue_share_percentage,
                ru.revenue_share_amount,
                ru.uploaded_at,
                ru.status AS upload_status,
                org.id AS organisation_id,
                org.name AS organisation_name,
                cat.id AS category_id,
                cat.name AS category_name
            FROM reports r
            INNER JOIN report_uploads ru ON r.report_upload_id = ru.id
            LEFT JOIN organisations org ON ru.organisation_id = org.id
            LEFT JOIN categories cat ON ru.category_id = cat.id
            $whereClause
            ORDER BY r.id DESC
            LIMIT $limit OFFSET $offset";

    $result = $conn->query($sql);
    if (!$result) {
        log_action("Query failed: " . $conn->error);
        throw new Exception("Database error: " . $conn->error);
    }

    $reports = [];
    while ($row = $result->fetch_assoc()) {
        $reports[] = $row;
    }


    // Get total count (for pagination)

    $countSql = "SELECT COUNT(*) AS total FROM reports r 
                 INNER JOIN report_uploads ru ON r.report_upload_id = ru.id
                 $whereClause";
    $countResult = $conn->query($countSql);
    $total = $countResult ? (int) $countResult->fetch_assoc()['total'] : 0;


    // Audit log (optional)

    try {
        audit_log($conn, $callerId, $callerFullName, "Fetched reports (total: $total)", 1);
    } catch (\Throwable $e) {
        log_action("Audit log call failed: " . $e->getMessage());
    }

    log_action("Get reports successful: returned " . count($reports) . " records out of $total total.");
    echo generateResponse(true, "Reports retrieved successfully.", [
        'reports' => $reports,
        'total'   => $total,
        'limit'   => $limit,
        'offset'  => $offset
    ], 200);
} catch (\Throwable $e) {
    log_action("Get reports exception: " . $e->getMessage());
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    if (isset($conn)) closeConnection($conn);
    log_action("=== GET REPORTS ATTEMPT END ===");
}
