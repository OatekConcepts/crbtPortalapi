<?php
require_once __DIR__ . '/response.php';
require_once __DIR__ . '/../log.php';

function getConnection()
{

    // $host = "127.0.0.1";
    // $user = "root";
    // $pass = "root";
    // $db = "crbtPortal";
    // $port = 8889;

    $user = "crbtPortalUser";
    $pass =  "&%crbt!@#$";
    $db   = "crbtportal";
    $host = "10.128.0.29";

    try {
        $conn = new mysqli($host, $user, $pass, $db);

        if ($conn->connect_error) {
            log_action("DB connection failed: " . $conn->connect_error);
            echo generateResponse(false, "An error occured", null, 500);
            exit;
        }

        return $conn;
    } catch (\mysqli_sql_exception $e) {
        log_action("DB connection exception: " . $e->getMessage());
        echo generateResponse(false, "An error occured", null, 500);
        exit;
    }
}

function getConnectionTwo()
{
    /*    $host = "10.128.0.18";
    $user = "comvivaUser";
    $pass = "comviva1@#$";
    $db = "comviva";
 */

    $host = "10.128.0.14";
    $user = "otaCentral";
    $pass = '$ComviBundle1!@#';
    $db = "comviva";

    try {
        $conn = new mysqli($host, $user, $pass, $db);

        if ($conn->connect_error) {
            echo generateResponse(false, "An error occured", null, 500);
            exit;
        }

        return $conn;
    } catch (\mysqli_sql_exception $e) {
        echo generateResponse(false, "An error occured");
        exit;
    }
}
function closeConnection($conn)
{
    if ($conn) {
        $conn->close();
    }
}
