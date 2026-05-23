<?php

namespace App\Services\Honeypot;

use Illuminate\Http\Request;

class AttackClassifier
{
    /**
     * @param  list<string>  $seedTechniques
     * @return array{primary_technique:?string, techniques:list<string>, suspicious:bool}
     */
    public function classify(Request $request, string $rawBody = '', array $seedTechniques = []): array
    {
        $haystack = strtolower(implode("\n", array_filter([
            $request->getPathInfo(),
            (string) $request->getQueryString(),
            $rawBody,
            json_encode($request->input()) ?: '',
            $request->userAgent(),
        ])));

        $techniques = $seedTechniques;

        if ($this->containsAny($haystack, ['.env', 'app_key=', 'db_password=', 'aws_secret_access_key'])) {
            $techniques[] = 'env_harvest';
        }

        if ($this->containsAny($haystack, ['../', '..\\', '%2e%2e%2f', '%2e%2e\\', '/etc/passwd', 'boot.ini'])) {
            $techniques[] = 'path_traversal';
        }

        if ($this->containsAny($haystack, ['union select', 'select * from', 'sleep(', 'or 1=1', 'drop table', 'information_schema'])) {
            $techniques[] = 'sql_injection';
        }

        if ($this->containsAny($haystack, ['<script', 'javascript:', 'onerror=', 'svg/onload=', 'alert('])) {
            $techniques[] = 'xss_probe';
        }

        if ($this->containsAny($haystack, [';cat ', '|bash', 'wget http', 'curl http', 'base64_decode', 'system(', 'shell_exec', '${jndi:', 'powershell'])) {
            $techniques[] = 'command_injection';
        }

        if ($this->containsAny($haystack, ['wp-login.php', 'administrator', 'password=', 'username=', 'login='])) {
            $techniques[] = 'credential_access';
        }

        if ($this->containsAny($haystack, ['phpunit', 'eval-stdin.php', '_ignition', 'execute-solution'])) {
            $techniques[] = 'framework_rce';
        }

        if ($this->containsAny($haystack, ['backup.zip', 'db.sql', 'dump.sql', '.git/config', 'laravel.log'])) {
            $techniques[] = 'source_disclosure';
        }

        $techniques = array_values(array_unique(array_filter($techniques)));

        $suspicious = $techniques !== []
            || $this->isSuspiciousMethod($request)
            || $this->containsAny($haystack, config('honeypot.deception.suspicious_path_fragments', []));

        if ($suspicious && $techniques === []) {
            $techniques[] = 'reconnaissance';
        }

        return [
            'primary_technique' => $techniques[0] ?? null,
            'techniques' => $techniques,
            'suspicious' => $suspicious,
        ];
    }

    private function isSuspiciousMethod(Request $request): bool
    {
        return in_array(strtoupper($request->method()), ['POST', 'PUT', 'PATCH', 'DELETE'], true)
            || $request->getContentLength() > 0;
    }

    /**
     * @param  list<string>  $needles
     */
    private function containsAny(string $haystack, array $needles): bool
    {
        foreach ($needles as $needle) {
            if ($needle !== '' && str_contains($haystack, strtolower($needle))) {
                return true;
            }
        }

        return false;
    }
}
