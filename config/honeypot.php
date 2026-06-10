<?php

$defaultHost = parse_url((string) env('APP_URL', 'http://localhost'), PHP_URL_HOST) ?: 'localhost';

$allowedHosts = array_values(array_filter(array_map(
    static fn (string $host): string => strtolower(trim($host)),
    explode(',', (string) env('HONEYPOT_ALLOWED_HOSTS', $defaultHost)),
)));

return [
    'enabled' => (bool) env('HONEYPOT_ENABLED', true),

    'enforce_host' => (bool) env('HONEYPOT_ENFORCE_HOST', true),

    'allowed_hosts' => $allowedHosts,

    'health_path' => env('HONEYPOT_HEALTH_PATH', '/up'),

    'retention_days' => (int) env('HONEYPOT_RETENTION_DAYS', 30),

    'capture' => [
        'session_window_minutes' => (int) env('HONEYPOT_SESSION_WINDOW_MINUTES', 30),
        'max_body_bytes' => (int) env('HONEYPOT_MAX_BODY_BYTES', 65535),
        'max_preview_bytes' => (int) env('HONEYPOT_MAX_PREVIEW_BYTES', 8192),
        'max_collection_items' => (int) env('HONEYPOT_MAX_COLLECTION_ITEMS', 50),
        'max_depth' => (int) env('HONEYPOT_MAX_CAPTURE_DEPTH', 5),
        'upload_max_kb' => (int) env('HONEYPOT_UPLOAD_MAX_KB', 2048),
        'quarantine_disk' => env('HONEYPOT_QUARANTINE_DISK', 'honeypot-quarantine'),
    ],

    'deception' => [
        'delay_ms' => [
            'min' => (int) env('HONEYPOT_MIN_DELAY_MS', 0),
            'max' => (int) env('HONEYPOT_MAX_DELAY_MS', 0),
        ],
        'suspicious_path_fragments' => [
            '.env',
            '.git',
            'admin',
            'login',
            'signin',
            'wp-',
            'phpunit',
            'eval-stdin',
            'ignition',
            'backup',
            'dump',
            'sql',
            'config',
            'storage/logs',
            'laravel.log',
            'vendor',
            'phpmyadmin',
            'shell',
            'console',
            'manager',
        ],
        'profiles' => [
            [
                'name' => 'landing-login',
                'patterns' => ['/'],
                'response' => 'login',
                'status' => 200,
                'title' => 'Operations Portal',
                'subtitle' => 'Use your managed credentials to access incident tooling.',
                'techniques' => ['credential_access'],
            ],
            [
                'name' => 'admin-login',
                'patterns' => ['/login', '/signin', '/admin', '/admin/login', '/administrator', '/wp-admin', '/wp-login.php'],
                'response' => 'login',
                'status' => 200,
                'title' => 'Administrative Console',
                'subtitle' => 'Authentication is required before privileged tools are available.',
                'techniques' => ['credential_access'],
            ],
            [
                'name' => 'admin-dashboard',
                'patterns' => ['/dashboard', '/admin/dashboard', '/admin/users', '/admin/logs', '/admin/reports'],
                'response' => 'dashboard',
                'status' => 200,
                'title' => 'Operations Dashboard',
                'techniques' => ['post_auth_enumeration'],
            ],
            [
                'name' => 'env-file',
                'patterns' => ['/.env', '/.env.*'],
                'response' => 'file',
                'status' => 200,
                'content_type' => 'text/plain; charset=UTF-8',
                'file_key' => 'env',
                'techniques' => ['env_harvest'],
            ],
            [
                'name' => 'git-config',
                'patterns' => ['/.git/config'],
                'response' => 'file',
                'status' => 200,
                'content_type' => 'text/plain; charset=UTF-8',
                'file_key' => 'git-config',
                'techniques' => ['source_disclosure'],
            ],
            [
                'name' => 'log-file',
                'patterns' => ['/storage/logs/laravel.log'],
                'response' => 'file',
                'status' => 200,
                'content_type' => 'text/plain; charset=UTF-8',
                'file_key' => 'laravel-log',
                'techniques' => ['log_disclosure'],
            ],
            [
                'name' => 'backup-archive',
                'patterns' => ['/backup.zip', '/backup.tar.gz', '/db.sql', '/dump.sql', '/storage/backups/*'],
                'response' => 'file',
                'status' => 200,
                'content_type' => 'application/octet-stream',
                'file_key' => 'backup',
                'techniques' => ['backup_harvest'],
            ],
            [
                'name' => 'config-php',
                'patterns' => ['/config.php'],
                'response' => 'file',
                'status' => 200,
                'content_type' => 'text/plain; charset=UTF-8',
                'file_key' => 'config-php',
                'techniques' => ['config_disclosure'],
            ],
            [
                'name' => 'phpunit-rce',
                'patterns' => ['/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '/_ignition/execute-solution'],
                'response' => 'exploit',
                'status' => 500,
                'title' => 'Execution pipeline error',
                'techniques' => ['framework_rce'],
            ],
            [
                'name' => 'generic-probe',
                'patterns' => [],
                'response' => 'probe',
                'status' => 403,
                'title' => 'Request blocked by upstream gateway',
                'techniques' => ['reconnaissance'],
            ],
        ],
    ],

    'operator' => [
        'path_prefix' => env('HONEYPOT_OPERATOR_PATH_PREFIX', 'ops'),
        'token' => env('HONEYPOT_OPERATOR_TOKEN'),
    ],
];
