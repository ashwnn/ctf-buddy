<?php
declare(strict_types=1);

require __DIR__ . '/../lib/common.php';

/** The planted defect lives in this file and nowhere else. */
$file = (string) ($_GET['file'] ?? '');
$path = files_dir() . '/' . $file;

if (!is_file($path)) {
    http_response_code(404);
    header('Content-Type: text/plain');
    echo "not found\n";
    exit;
}

$content = file_get_contents($path);

header('Content-Type: text/plain');
header('Content-Disposition: attachment; filename="' . basename($path) . '"');
header('X-Content-Type-Options: nosniff');
echo $content;
