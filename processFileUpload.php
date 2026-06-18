<?php
include_once 'conn.php';

$conn = getConnection();


$sql = "SELECT * FROM uploaded_files WHERE status = 1 and sequence= 1 LIMIT 1";
$result = mysqli_query($conn, $sql);
log_action($sql);

if ($result && mysqli_num_rows($result) > 0) {
   
    // Get the record that's being processed
    $row = mysqli_fetch_assoc($result);
    $updatedAt = $row['updated_at'];
    $fileId = $row['id'];
    
    // Calculate time difference
    $currentTime = date('Y-m-d H:i:s');
    $updatedTimestamp = strtotime($updatedAt);
    $currentTimestamp = strtotime($currentTime);
    $timeDifference = $currentTimestamp - $updatedTimestamp; // difference in seconds
    
    // Check if updated_at is greater than 5 minutes (300 seconds)
    if ($timeDifference > 300) {
        log_action("File ID: $fileId has been processing for more than 5 minutes. Resetting status to 0...\n");
        
        // Update status back to 0
        $resetQuery = "UPDATE uploaded_files SET status = 0 WHERE id = $fileId";
        if (mysqli_query($conn, $resetQuery)) {
            log_action("File ID: $fileId status reset to 0 successfully.\n");
        } else {
            log_action("Failed to reset status for File ID: $fileId. Error: " . mysqli_error($conn) . "\n");
        }
        
        // Continue with processing the next file
        // We don't exit here, we let it fall through to check for files with status 0
    } else {
        log_action("A file is currently being processed. Exiting...\n");
        mysqli_close($conn);
        exit;
    }

} else {
    $sql2 = "SELECT * FROM uploaded_files WHERE status = 0  and sequence= 1 LIMIT 1";
    $result2 = mysqli_query($conn, $sql2);
    log_action($sql2);

    if ($result2 && mysqli_num_rows($result2) > 0) {
        $row = mysqli_fetch_assoc($result2);
        $fileId = $row['id'];
        $filePath = $row['file_path'];
        $msg = $row['message'];
        $batchId = $row['batch_id'];
        $otaConfirmation = $row['ota_confirmation'];
	$endDate = $row['end_date'];
        $campaignName = $row['campaign_name'];
	$srcId = $row['src_id'];
	$replyTo = $row['reply_to'];

	$paramCount  = (int) $row['paramCount'];

	$startDate = $row['start_date'];
        $currentDateTime = date('Y-m-d H:i:00');

        $startTimestamp = strtotime($startDate);
        $currentTimestamp = strtotime($currentDateTime);

        if ($currentTimestamp < $startTimestamp) {
            log_action("Start date ($startDateOnly) is not today ($currentDate). Skipping...\n");
            exit;
        }

        $updateQuery = "UPDATE uploaded_files SET status = 1 WHERE id = $fileId";
        log_action($updateQuery);

        $escapedPath = mysqli_real_escape_string($conn, $filePath);
        log_action($escapedPath);
        if (mysqli_query($conn, $updateQuery)) {
	    $csvHeader = [];
            if (($handle = fopen($filePath, 'r')) !== false) {
                $csvHeader = fgetcsv($handle);
                fclose($handle);
            }

            $fieldVars = [];
            $setParts = [];
            $headerParts = [];

	    $bom = pack('H*','EFBBBF');
	    $csvHeader[0] = preg_replace("/^$bom/", '', $csvHeader[0]);

            foreach ($csvHeader as $column) {
                $columnOriginal = trim($column);
		$column = strtolower($columnOriginal);


                //log_action("Memory address: " . spl_object_hash((object)$column));
                //log_action("Binary safe dump: " . bin2hex($column));

                $fieldVars[] = "@$column";

                if ($column === 'msisdn') {
                    log_action("Comparison passed - adding to setParts");
                    $setParts[] = "msisdn = @$column";
                  //  log_action("Current setParts: " . print_r($setParts, true));
                } else {
                    log_action("Comparison failed for: " . var_export($column, true));
		}

		// Dynamic parameter mapping (params1-5)
                for ($i = 1; $i <= 5; $i++) {
                    $paramKey = "params$i";
                    if (!empty($row[$paramKey])) {
                        // Normalize the configured parameter name for comparison
                        $configParam = strtolower(trim($row[$paramKey]));
                        if ($configParam === $column) {
                            $setParts[] = "$paramKey = @$column";
                            $headerParts[] = $column;
                            log_action("Mapped $column to $paramKey");
                        }
                    }
                }
	/*	$fieldVars[] = "@$column";
		
		 log_action("Raw column value: '" . $column . "'");
    log_action("Trimmed column: '" . trim($column) . "'");
    log_action("Lowercase column: '" . strtolower(trim($column)) . "'");
	 */		

	//	if (strcasecmp($column, 'msisdn') === 0) {
	//	if ($column === 'msisdn') {
	//	    $setParts[] = "msisdn = @$column";
          //      }
               
	    }
    	

            $fieldList = implode(', ', $fieldVars);
            $setClause = implode(', ', $setParts);
            $headerRow = implode(',', $headerParts);
	    log_action("CSV Header: " . print_r($csvHeader, true));
	    log_action("Set Parts: " . print_r($setParts, true));

	    // Product lookup with proper error handling
$productId = $row['product_id'];
$queryProduct = "SELECT * FROM crbt WHERE id = '$productId'";  // Added quotes around value
$resultProduct = $conn->query($queryProduct);

log_action("Product Query: " . $queryProduct);  // Log the actual query

if (!$resultProduct) {  // Check the query result, not the connection
    log_action("DB Error: " . $conn->error);
    echo json_encode(["status" => false, "message" => "Product lookup failed"]);
}

if ($resultProduct->num_rows === 0) {
    http_response_code(404);
    echo json_encode(["status" => false, "message" => "Product not found"]);
}

$product = $resultProduct->fetch_assoc();
$productCode = $product['code'] ?? null;  // Get the coolmn column

if (empty($productCode)) {
    echo json_encode(["status" => false, "message" => "Product configuration incomplete"]);
}

	    //policy string fetch ADD TO LIVE
        $policyId = $row['policy_id'];
        if(!empty($policyId)){
            $queryPolicy = "SELECT * FROM policy_control WHERE id = '$policyId'";  // Added quotes around value
            $resultPolicy = $conn->query($queryPolicy);

            log_action("Policy Query: " . $queryPolicy);  // Log the actual query

            if (!$resultPolicy) {  // Check the query result, not the connection
                log_action("DB Error: " . $conn->error);
                echo json_encode(["status" => false, "message" => "Policy lookup failed"]);
            }

            if ($resultPolicy->num_rows === 0) {
                http_response_code(404);
                echo json_encode(["status" => false, "message" => "Policy not found"]);
            }

            $policy = $resultPolicy->fetch_assoc();
            $policyValue = $policy['value'] ?? null;  // Get the value column

            if (empty($policyValue)) {
                log_action(json_encode(["status" => false, "message" => "Policy configuration incomplete"]));
                // echo json_encode(["status" => false, "message" => "Product configuration incomplete"]);
            }
        }else{
            $policyValue = Null;
        }
		
	    $conn->set_charset("utf8mb4");
            $escapedHeader = mysqli_real_escape_string($conn, $headerRow);
            $escapedMsg = mysqli_real_escape_string($conn, $msg);
            $escapedBatchId = mysqli_real_escape_string($conn, $batchId);
	    $escapedOtaConfirmation= mysqli_real_escape_string($conn, $otaConfirmation);
	    $escapedProductCode= mysqli_real_escape_string($conn, $productCode);
	    $escapedPolicyValue= mysqli_real_escape_string($conn, $policyValue); //ADD TO LIVE
            $escapedStartDate= mysqli_real_escape_string($conn, $startDate); //ADD TO LIVE
            $escapedEndDate= mysqli_real_escape_string($conn, $endDate); //ADD TO LIVE
            $escapedCampaignName= mysqli_real_escape_string($conn, $campaignName); //ADD TO LIVE
	    $escapedSrcId= mysqli_real_escape_string($conn, $srcId);
	    $escapedReplyTo= mysqli_real_escape_string($conn, $replyTo);



            $loadQuery = "
                LOAD DATA INFILE '$escapedPath'
                INTO TABLE queues1
                FIELDS TERMINATED BY ',' 
                ENCLOSED BY '\"'
                LINES TERMINATED BY '\\n'
                IGNORE 1 LINES
                ($fieldList)
                SET $setClause,
                    text = '$escapedMsg',
                    batch_id = '$escapedBatchId',
                    ota_confirmation = '$escapedOtaConfirmation',
                    product_id = '$escapedProductCode',
                    policy_id = '$escapedPolicyValue', 
                    start_date = '$escapedStartDate', 
                    end_date = '$escapedEndDate', 
                    campaign_name = '$escapedCampaignName',
                    reply_to = '$escapedReplyTo',
                            src_id = '$escapedSrcId'  
            ";

            log_action("Load Query: $loadQuery");

            if (mysqli_query($conn, $loadQuery)) {
                log_action("File (ID: $fileId) processed successfully.\n");
                mysqli_query($conn, "UPDATE uploaded_files SET status = 2 WHERE id = $fileId");
            } else {
                $updateQuery = "UPDATE uploaded_files SET status = 3 WHERE id = $fileId";
                log_action($updateQuery);
                mysqli_query($conn,$updateQuery);
                log_action("Failed to load data: " . mysqli_error($conn));
            }
        } else {
            $updateQuery = "UPDATE uploaded_files SET status = 3 WHERE id = $fileId";
	    log_action($updateQuery);
	    mysqli_query($conn,$updateQuery);
            log_action("Failed to update status: " . mysqli_error($conn));
        }
    } else {
        log_action("No unprocessed files found.\n");
        sleep(5);
    }
}

mysqli_close($conn);



function log_action($msg, $logFile = "./process.log")
{
    $fp = @fopen($logFile, 'a+');
    @fputs($fp, "[" . date('Y-m-d H:i:s') . "] - " . $msg . "\n");
    @fclose($fp);
    return true;
}

