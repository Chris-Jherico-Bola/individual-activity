<?php
// Simple auth/session helper used across the app.

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/**
 * Ensure session is started (idempotent)
 */
function ensure_session(){
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
}

/**
 * Set the authenticated user into session and regenerate id
 * $user is an associative array coming from DB (may include 'role')
 */
function login_user_in_session(array $user){
    ensure_session();
    // Do not keep password hash in session
    if (isset($user['password_hash'])) unset($user['password_hash']);
    session_regenerate_id(true);
    $_SESSION['user'] = $user;
    $_SESSION['authenticated'] = true;
    $_SESSION['role'] = isset($user['role']) ? $user['role'] : 'customer';
}

/**
 * Clear session safely
 */
function logout_user(){
    ensure_session();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params['path'], $params['domain'],
            $params['secure'], $params['httponly']
        );
    }
    @session_destroy();
}

/**
 * Require authenticated user, otherwise redirect to index with loginRequired flag
 */
function require_auth(){
    ensure_session();
    if (empty($_SESSION['authenticated']) || empty($_SESSION['user'])) {
        header('Location: /index.php?loginRequired=1');
        exit;
    }
}

/**
 * Require specific role(s). $roles may be string or array.
 * Redirects to home if role not satisfied.
 */
function require_role($roles){
    ensure_session();
    if (!is_array($roles)) $roles = [$roles];
    $role = $_SESSION['role'] ?? ($_SESSION['user']['role'] ?? null);
    if (!$role || !in_array($role, $roles, true)) {
        header('Location: /index.php');
        exit;
    }
}

/**
 * Check if current session user has given role
 */
function is_role($role){
    ensure_session();
    $r = $_SESSION['role'] ?? ($_SESSION['user']['role'] ?? null);
    return $r === $role;
}
