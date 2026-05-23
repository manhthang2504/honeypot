<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureHoneypotOperatorAccess
{
    public function handle(Request $request, Closure $next): Response
    {
        $configuredToken = trim((string) config('honeypot.operator.token'));

        if ($configuredToken === '') {
            abort(Response::HTTP_NOT_FOUND);
        }

        $providedToken = $this->extractToken($request);

        if ($providedToken === '' || ! hash_equals($configuredToken, $providedToken)) {
            abort(Response::HTTP_NOT_FOUND);
        }

        return $next($request);
    }

    private function extractToken(Request $request): string
    {
        return trim((string) (
            $request->header('X-Honeypot-Token')
            ?? $request->bearerToken()
            ?? $request->query('token', '')
        ));
    }
}
