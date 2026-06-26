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
log_action("=== UPLOAD REPORT ATTEMPT START ===");

try {
    // Authenticate and authorise
    $decoded = authenticateRequest($conn);
    // requireRole($decoded, ['super_admin', 'admin']);
    requireAdminRole($decoded);

    $callerId = (int) $decoded['id'];
    $callerResult = $conn->query("SELECT firstname, lastname FROM admins WHERE id=$callerId");
    if (!$callerResult || $callerResult->num_rows === 0) {
        log_action("Upload blocked: caller id=$callerId not found");
        echo generateResponse(false, "Invalid or expired token.", null, 401);
        closeConnection($conn);
        exit;
    }
    $caller = $callerResult->fetch_assoc();
    $callerFullName = $caller['firstname'] . ' ' . $caller['lastname'];


    //Validate file upload

    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        log_action("No file uploaded or upload error: " . ($_FILES['file']['error'] ?? 'no file'));
        echo generateResponse(false, "No file uploaded or upload error.", null, 400);
        closeConnection($conn);
        exit;
    }

    $file = $_FILES['file'];
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowed = ['csv', 'xlsx', 'xls'];
    if (!in_array($extension, $allowed)) {
        log_action("Invalid file type: $extension");
        echo generateResponse(false, "Invalid file type. Allowed: CSV, XLSX, XLS.", null, 400);
        closeConnection($conn);
        exit;
    }


    //Validate metadata fields (and verify IDs exist)

    $organisation_id = (int) ($_POST['organisation_id'] ?? 0);
    $category_id     = (int) ($_POST['category_id'] ?? 0);
    $name            = trim($_POST['name'] ?? '');
    $month           = trim($_POST['month'] ?? '');
    $year            = (int) ($_POST['year'] ?? 0);
    $gross_revenue   = (float) ($_POST['gross_revenue'] ?? 0);
    $revenue_ex_vat  = (float) ($_POST['revenue_ex_vat'] ?? 0);
    $share_percent   = (float) ($_POST['revenue_share_percentage'] ?? 0);
    $share_amount    = (float) ($_POST['revenue_share_amount'] ?? 0);

    // Required fields
    if (
        !$organisation_id || !$category_id || !$name ||
        !$month || !$year || !$gross_revenue || !$revenue_ex_vat
        || !$share_percent || !$share_amount
    ) {
        log_action("Validation failed: Missing required metadata fields.");
        echo generateResponse(false, "All fields are required.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check if organisation exists
    $orgCheck = $conn->query("SELECT id FROM organisations WHERE id = $organisation_id");
    if (!$orgCheck || $orgCheck->num_rows === 0) {
        log_action("Invalid organisation_id: $organisation_id");
        echo generateResponse(false, "Invalid organisation.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Check if category exists
    $catCheck = $conn->query("SELECT id FROM categories WHERE id = $category_id");
    if (!$catCheck || $catCheck->num_rows === 0) {
        log_action("Invalid category_id: $category_id");
        echo generateResponse(false, "Invalid category.", null, 400);
        closeConnection($conn);
        exit;
    }


    // Parse file content

    $rows = [];
    if ($extension === 'csv') {
        $rows = parseCSV($file['tmp_name']);
    } else {
        if (!class_exists('PhpOffice\PhpSpreadsheet\IOFactory')) {
            log_action("PhpSpreadsheet not installed");
            echo generateResponse(false, "XLSX/XLS support not available. Please install PhpSpreadsheet or upload CSV.", null, 500);
            closeConnection($conn);
            exit;
        }
        $rows = parseSpreadsheet($file['tmp_name']);
    }

    if (empty($rows)) {
        log_action("File parsed but no data rows found.");
        echo generateResponse(false, "The file appears empty or has no data rows.", null, 400);
        closeConnection($conn);
        exit;
    }

    // Validate headers
    $expectedHeaders = ['SPNAME', 'SINGER', 'TONENAME', 'TONE_CD', 'COUNT', 'CHARGE'];
    $firstRowKeys = array_keys($rows[0]);
    $headerMatch = true;
    foreach ($expectedHeaders as $i => $h) {
        if (strtoupper(trim($firstRowKeys[$i] ?? '')) !== $h) {
            $headerMatch = false;
            break;
        }
    }
    if (!$headerMatch) {
        log_action("Header mismatch. Expected: " . implode(',', $expectedHeaders) . " Got: " . implode(',', $firstRowKeys));
        echo generateResponse(false, "Invalid column headers. Expected: SPNAME, SINGER, TONENAME, TONE_CD, COUNT, CHARGE.", null, 400);
        closeConnection($conn);
        exit;
    }
    array_shift($rows); // remove header row


    // Store the uploaded file physically

    //$uploadDir = '/var/www/html/crbtportal/uploads/'; will have to craete this on live but use the local own now

    $uploadDir = __DIR__ . '/../uploads/reports/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }
    $storedFilename = time() . '_' . basename($file['name']);
    $filePath = $uploadDir . $storedFilename;
    if (!move_uploaded_file($file['tmp_name'], $filePath)) {
        log_action("Failed to move uploaded file to $filePath");
        throw new Exception("Failed to save file.");
    }
    $dbFilePath = 'uploads/reports/' . $storedFilename;

    //Insert into report_upload (with all metadata)

    $conn->begin_transaction();

    $filename = $conn->real_escape_string($file['name']);
    $totalRows = count($rows);
    $nameEsc = $conn->real_escape_string($name);
    $monthEsc = $conn->real_escape_string($month);
    $filePathEsc = $conn->real_escape_string($dbFilePath);

    $uploadSql = "INSERT INTO report_uploads
                  (organisation_id, category_id, name, file_path, month, year, 
                   gross_revenue, revenue_ex_vat, revenue_share_percentage, revenue_share_amount,
                   filename, total_rows, uploaded_at, status) 
                  VALUES 
                  ($organisation_id, $category_id, '$nameEsc', '$filePathEsc', '$monthEsc', $year,
                   $gross_revenue, $revenue_ex_vat, $share_percent, $share_amount,
                   '$filename', $totalRows, NOW(), 'pending')";

    if (!$conn->query($uploadSql)) {
        log_action("Failed to create upload record: " . $conn->error);
        throw new Exception("Failed to create upload record.");
    }
    $reportUploadId = $conn->insert_id;


    // Insert each row into `report`

    $inserted = 0;
    $errors = [];
    foreach ($rows as $index => $row) {
        $sp_name = trim($row['SPNAME'] ?? '');
        $singer = trim($row['SINGER'] ?? '');
        $tone_name = trim($row['TONENAME'] ?? '');
        $tone_cd = trim($row['TONE_CD'] ?? '');
        $count = (int) ($row['COUNT'] ?? 0);
        $charge = (float) ($row['CHARGE'] ?? 0);

        if ($sp_name === '' || $tone_cd === '') {
            $errors[] = "Row " . ($index + 2) . " missing SPNAME or TONE_CD.";
            continue;
        }
        if ($count < 0 || $charge < 0) {
            $errors[] = "Row " . ($index + 2) . " has negative COUNT or CHARGE.";
            continue;
        }

        $sp_name = $conn->real_escape_string($sp_name);
        $singer = $conn->real_escape_string($singer);
        $tone_name = $conn->real_escape_string($tone_name);
        $tone_cd = $conn->real_escape_string($tone_cd);

        $sql = "INSERT INTO reports (report_upload_id, sp_name, singer, tone_name, tone_cd, count, charge, created_at)
        VALUES ($reportUploadId, '$sp_name', '$singer', '$tone_name', '$tone_cd', $count, $charge, NOW())";
        if ($conn->query($sql)) {
            $inserted++;
        } else {
            $errors[] = "Row " . ($index + 2) . " DB error: " . $conn->error;
        }
    }

    // Update status
    $status = empty($errors) ? 'processed' : 'failed';
    $conn->query("UPDATE report_uploads SET status = '$status' WHERE id = $reportUploadId");

    if ($inserted === 0) {
        $conn->rollback();
        log_action("Upload rollback: no rows inserted.");
        @unlink($filePath); // remove the stored file
        echo generateResponse(false, "No rows inserted. All rows had errors.", ['errors' => $errors], 400);
        closeConnection($conn);
        exit;
    }

    $conn->commit();

    // Audit log
    try {
        audit_log($conn, $callerId, $callerFullName, "Uploaded report '$name' with $inserted rows (upload_id=$reportUploadId)", 1);
    } catch (\Throwable $e) {
        log_action("Audit log call failed: " . $e->getMessage());
    }

    log_action("Upload successful: upload_id=$reportUploadId, inserted=$inserted, errors=" . count($errors));
    echo generateResponse(true, "File uploaded successfully.", [
        'upload_id' => $reportUploadId,
        'total_rows' => $totalRows,
        'inserted' => $inserted,
        'errors' => $errors
    ], 200);
} catch (\Throwable $e) {
    log_action("Upload exception: " . $e->getMessage());
    if (isset($conn) && $conn->connect_errno === 0) {
        $conn->rollback();
    }
    echo generateResponse(false, "An error occurred: " . $e->getMessage(), null, 500);
} finally {
    if (isset($conn)) closeConnection($conn);
    log_action("=== UPLOAD REPORT ATTEMPT END ===");
}


// Helper functions


function parseCSV(string $filePath): array
{
    $rows = [];
    if (($handle = fopen($filePath, 'r')) !== false) {
        $headers = fgetcsv($handle);
        if ($headers === false) {
            fclose($handle);
            return [];
        }
        $headers = array_map(function ($h) {
            return strtoupper(trim($h));
        }, $headers);
        while (($data = fgetcsv($handle)) !== false) {
            $row = [];
            foreach ($headers as $idx => $header) {
                $row[$header] = isset($data[$idx]) ? trim($data[$idx]) : '';
            }
            $rows[] = $row;
        }
        fclose($handle);
    }
    return $rows;
}

function parseSpreadsheet(string $filePath): array
{
    if (!class_exists('PhpOffice\PhpSpreadsheet\IOFactory')) {
        throw new Exception('PhpSpreadsheet not installed.');
    }
    $spreadsheet = \PhpOffice\PhpSpreadsheet\IOFactory::load($filePath);
    $worksheet = $spreadsheet->getActiveSheet();
    $rows = [];
    $headers = [];
    foreach ($worksheet->getRowIterator() as $rowIndex => $row) {
        $cellIterator = $row->getCellIterator();
        $cellIterator->setIterateOnlyExistingCells(false);
        $rowData = [];
        foreach ($cellIterator as $cell) {
            $rowData[] = trim($cell->getValue());
        }
        if ($rowIndex === 1) {
            $headers = array_map('strtoupper', $rowData);
        } else {
            if (!empty(array_filter($rowData, function ($v) {
                return $v !== '';
            }))) {
                $combined = [];
                foreach ($headers as $idx => $header) {
                    $combined[$header] = isset($rowData[$idx]) ? trim($rowData[$idx]) : '';
                }
                $rows[] = $combined;
            }
        }
    }
    return $rows;
}
