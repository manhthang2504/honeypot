<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureHoneypotOperatorAccess
{
    private const SESSION_KEY = 'honeypot.operator_authenticated';

    public function handle(Request $request, Closure $next): Response
    {
        $configuredToken = trim((string) config('honeypot.operator.token'));

        if ($configuredToken === '') {
            abort(Response::HTTP_NOT_FOUND);
        }

        if ($this->hasAuthorizedSession($request)) {
            return $next($request);
        }

        $providedToken = $this->extractToken($request);

        if ($providedToken === '' || ! hash_equals($configuredToken, $providedToken)) {
            abort(Response::HTTP_NOT_FOUND);
        }

        $request->session()->put(self::SESSION_KEY, true);
        $request->session()->migrate(true);

        if ($this->shouldStripBootstrapToken($request)) {
            return $this->redirectWithoutBootstrapToken($request);
        }

        return $next($request);
    }

    private function hasAuthorizedSession(Request $request): bool
    {
        return (bool) $request->session()->get(self::SESSION_KEY, false);
    }

    private function extractToken(Request $request): string
    {
        return trim((string) (
            $request->header('X-Honeypot-Token')
            ?? $request->bearerToken()
            ?? $request->query('token', '')
        ));
    }

    private function shouldStripBootstrapToken(Request $request): bool
    {
        return $request->isMethod('GET') && $request->query->has('token');
    }

    private function redirectWithoutBootstrapToken(Request $request): RedirectResponse
    {
        $remainingQuery = $request->query();
        unset($remainingQuery['token']);

        $destination = $request->url();

        if ($remainingQuery !== []) {
            $destination .= '?'.http_build_query($remainingQuery);
        }

        return redirect()->to($destination);
    }
}
