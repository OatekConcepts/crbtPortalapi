<?php
require_once __DIR__ . '/response.php';
require_once __DIR__ . '/../log.php';

function getConnection()
{


    $host = "127.0.0.1";
    $user = "root";
    $pass = "root";
    $db = "crbtPortal";
    $port = 8889;

    try {
        $conn = new mysqli($host, $user, $pass, $db, $port);

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


function closeConnection($conn)
{
    if ($conn) {
        $conn->close();
    }
}
