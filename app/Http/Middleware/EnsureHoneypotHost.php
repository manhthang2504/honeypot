<?php

namespace App\Http\Middleware;

use App\Services\Honeypot\DeploymentScope;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureHoneypotHost
{
    public function __construct(
        private readonly DeploymentScope $deploymentScope,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! $this->deploymentScope->allowsRequest($request)) {
            abort(Response::HTTP_NOT_FOUND);
        }

        return $next($request);
    }
}
