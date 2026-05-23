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

    'retention_days' => (int) env('HONEYPOT_RETENTION_DAYS', 30),

    'operator' => [
        'path_prefix' => env('HONEYPOT_OPERATOR_PATH_PREFIX', 'ops'),
        'token' => env('HONEYPOT_OPERATOR_TOKEN'),
    ],
];
