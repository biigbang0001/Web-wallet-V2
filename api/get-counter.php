<?php
declare(strict_types=1);

// CORS & JSON
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}

try {
  // Path to counter file (data dir beside this script)
  $counterFile = __DIR__ . '/../data/counter.txt';
  $dataDir = dirname($counterFile);

  if (!is_dir($dataDir)) {
    if (!mkdir($dataDir, 0755, true) && !is_dir($dataDir)) {
      throw new RuntimeException('Failed to create data directory: ' . $dataDir);
    }
  }

  // Ensure file exists
  if (!file_exists($counterFile)) {
    if (false === file_put_contents($counterFile, "0\n", LOCK_EX)) {
      throw new RuntimeException('Failed to initialize counter file.');
    }
    @chmod($counterFile, 0644);
  }

  // Safely read current value
  $readCount = function() use ($counterFile): int {
    $fh = fopen($counterFile, 'r');
    if ($fh === false) throw new RuntimeException('Cannot open counter for reading.');
    try {
      if (!flock($fh, LOCK_SH)) throw new RuntimeException('Cannot lock counter (shared).');
      $raw = stream_get_contents($fh);
      $val = (int)trim((string)$raw);
      flock($fh, LOCK_UN);
      return $val;
    } finally {
      fclose($fh);
    }
  };

  // Safely increment and return new value
  $incCount = function() use ($counterFile): int {
    $fh = fopen($counterFile, 'c+');
    if ($fh === false) throw new RuntimeException('Cannot open counter for write.');
    try {
      if (!flock($fh, LOCK_EX)) throw new RuntimeException('Cannot lock counter (exclusive).');
      $raw = stream_get_contents($fh);
      $val = (int)trim((string)$raw);
      $val++;
      rewind($fh);
      if (fwrite($fh, (string)$val . "\n") === false) {
        throw new RuntimeException('Failed to write counter.');
      }
      ftruncate($fh, ftell($fh));
      fflush($fh);
      flock($fh, LOCK_UN);
      return $val;
    } finally {
      fclose($fh);
    }
  };

  $method = $_SERVER['REQUEST_METHOD'];

  if ($method === 'POST') {
    $count = $incCount();
    echo json_encode(['ok' => true, 'count' => $count], JSON_UNESCAPED_SLASHES);
    exit;
  }

  if ($method === 'GET') {
    $count = $readCount();
    echo json_encode(['ok' => true, 'count' => $count], JSON_UNESCAPED_SLASHES);
    exit;
  }

  http_response_code(405);
  echo json_encode(['ok' => false, 'error' => 'Method not allowed']);
} catch (Throwable $e) {
  http_response_code(500);
  echo json_encode([
    'ok' => false,
    'error' => 'Server error',
    'message' => $e->getMessage(),
  ]);
  error_log('Counter API Error: ' . $e->getMessage());
}
