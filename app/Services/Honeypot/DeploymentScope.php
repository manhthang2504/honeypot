<?php

namespace App\Services\Honeypot;

use Illuminate\Http\Request;

class DeploymentScope
{
    public function allowsRequest(Request $request): bool
    {
        if ($this->isHealthRequest($request)) {
            return true;
        }

        if (! $this->isEnforced()) {
            return true;
        }

        return $this->allowsHost($request->getHost());
    }

    public function isEnforced(): bool
    {
        return (bool) config('honeypot.enabled', true)
            && (bool) config('honeypot.enforce_host', true)
            && !app()->environment(['local', 'testing']);
    }

    /**
     * @return list<string>
     */
    public function allowedHosts(): array
    {
        $hosts = config('honeypot.allowed_hosts', []);

        return is_array($hosts) ? $hosts : [];
    }

    public function allowsHost(?string $host): bool
    {
        $normalizedHost = $this->normalizeHost($host);

        if ($normalizedHost === '') {
            return false;
        }

        foreach ($this->allowedHosts() as $allowedHost) {
            if ($this->matchesHost($normalizedHost, $allowedHost)) {
                return true;
            }
        }

        return false;
    }

    private function matchesHost(string $host, string $allowedHost): bool
    {
        if ($allowedHost === '*') {
            return true;
        }

        if (str_starts_with($allowedHost, '*.')) {
            $suffix = substr($allowedHost, 1);

            return str_ends_with($host, $suffix);
        }

        return $host === $allowedHost;
    }

    public function healthPath(): string
    {
        return '/'.trim((string) config('honeypot.health_path', '/up'), '/');
    }

    public function isHealthRequest(Request $request): bool
    {
        return $request->getPathInfo() === $this->healthPath();
    }

    private function normalizeHost(?string $host): string
    {
        if (! is_string($host)) {
            return '';
        }

        $normalizedHost = strtolower(trim($host));

        if ($normalizedHost === '') {
            return '';
        }

        if (str_contains($normalizedHost, ':')) {
            [$normalizedHost] = explode(':', $normalizedHost, 2);
        }

        return $normalizedHost;
    }
}
