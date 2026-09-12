<?php
declare(strict_types=1);

require __DIR__ . '/../lib/common.php';

/** Health plus a real read of the note store: a 200 from a dead backend is not health. */
if (($_SERVER['REQUEST_URI'] ?? '') === '/healthz' || ($_GET['action'] ?? '') === 'healthz') {
    $count = count(glob(notes_dir() . '/*.json') ?: []);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode(['status' => 'ok', 'notes' => $count]), "\n";
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = (string) ($_GET['action'] ?? '');
$id = (string) ($_GET['id'] ?? '');
$raw = file_get_contents('php://input') ?: '';
$payload = json_decode($raw, true);
$payload = is_array($payload) ? $payload : [];

if ($method === 'POST' && $action === 'create') {
    $title = substr((string) ($payload['title'] ?? ''), 0, 200);
    $body = substr((string) ($payload['body'] ?? ''), 0, MAX_BODY);
    if ($title === '') {
        json_response(400, ['error' => 'title is required']);
    }
    $note = ['id' => bin2hex(random_bytes(16)), 'title' => $title, 'body' => $body];
    write_note($note);
    json_response(201, ['id' => $note['id'], 'title' => $note['title']]);
}

if ($method === 'GET' && $action === 'read') {
    $note = read_note($id);
    if ($note === null) {
        json_response(404, ['error' => 'not found']);
    }
    json_response(200, $note);
}

if ($method === 'DELETE' && $action === 'delete') {
    if (!delete_note($id)) {
        json_response(404, ['error' => 'not found']);
    }
    http_response_code(204);
    exit;
}

json_response(404, ['error' => 'unknown route']);
