<?php
/**
 * config.php
 * ------------------------------------------------------------
 * Database connection (PostgreSQL via PDO) + shared helpers.
 * Every page in this project starts with: require_once 'config.php';
 * ------------------------------------------------------------
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0'); // keep raw errors out of the browser in "production"

// ---------------------------------------------------------------
// Session
// ---------------------------------------------------------------
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax',
    ]);
}

// ---------------------------------------------------------------
// Database connection settings  (PostgreSQL 18 / pgAdmin 4)
// ---------------------------------------------------------------
$host     = 'localhost';
$port     = '5432';
$dbname   = 'bus_ticketing_db';
$dbuser   = 'postgres';
$dbpass   = 'Tusharborn772005@'; // <-- set this to your local PostgreSQL password

try {
    $pdo = new PDO(
        "pgsql:host={$host};port={$port};dbname={$dbname}",
        $dbuser,
        $dbpass,
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    die('Database connection failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}

// ---------------------------------------------------------------
// Output / input helpers
// ---------------------------------------------------------------

/** Escape a string for safe HTML output. */
function e(?string $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

/** Trim and collapse a posted/get value to a plain string. */
function input(string $key, string $default = '', string $source = 'post'): string
{
    $bag = $source === 'get' ? $_GET : $_POST;
    return isset($bag[$key]) ? trim((string)$bag[$key]) : $default;
}

/** Format a numeric amount as currency (BDT). */
function money(float|string $amount): string
{
    return 'BDT ' . number_format((float)$amount, 2);
}

// ---------------------------------------------------------------
// Flash messages (one-time alerts after redirects)
// ---------------------------------------------------------------
function flash(string $type, string $message): void
{
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function get_flash(): ?array
{
    if (!empty($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

function redirect(string $url): never
{
    header("Location: {$url}");
    exit;
}

// ---------------------------------------------------------------
// CSRF protection
// ---------------------------------------------------------------
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_verify(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!is_string($token) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(400);
        die('Invalid or expired form submission (CSRF check failed). Please go back and try again.');
    }
}

// ---------------------------------------------------------------
// Authentication / authorization helpers
// ---------------------------------------------------------------
function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function is_logged_in(): bool
{
    return isset($_SESSION['user']);
}

function require_login(): void
{
    if (!is_logged_in()) {
        flash('warning', 'Please log in to continue.');
        redirect('login.php');
    }
}

/** @param string[] $roles */
function require_role(array $roles): void
{
    require_login();
    $user = current_user();
    if (!in_array($user['role'], $roles, true)) {
        http_response_code(403);
        die('403 - You do not have permission to access this page.');
    }
}

function ticket_code(): string
{
    return 'TKT-' . strtoupper(bin2hex(random_bytes(4)));
}