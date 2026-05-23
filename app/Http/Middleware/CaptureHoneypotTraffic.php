<?php

namespace App\Http\Middleware;

use App\Services\Honeypot\DeploymentScope;
use App\Services\Honeypot\TrafficRecorder;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class CaptureHoneypotTraffic
{
    public function __construct(
        private readonly DeploymentScope $deploymentScope,
        private readonly TrafficRecorder $trafficRecorder,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $startedAt = microtime(true);

        try {
            $response = $next($request);
        } catch (Throwable $exception) {
            $this->recordSafely($request, null, $startedAt, $exception);

            throw $exception;
        }

        $this->recordSafely($request, $response, $startedAt);

        return $response;
    }

    private function recordSafely(Request $request, ?Response $response, float $startedAt, ?Throwable $exception = null): void
    {
        if (! $this->shouldCapture($request)) {
            return;
        }

        try {
            $this->trafficRecorder->record(
                request: $request,
                response: $response,
                durationMs: (int) round((microtime(true) - $startedAt) * 1000),
                exception: $exception,
            );
        } catch (Throwable $recordingException) {
            Log::warning('Failed to persist honeypot traffic.', [
                'path' => $request->getPathInfo(),
                'host' => $request->getHost(),
                'error' => $recordingException->getMessage(),
            ]);
        }
    }

    private function shouldCapture(Request $request): bool
    {
        if (! (bool) config('honeypot.enabled', true)) {
            return false;
        }

        if ($this->deploymentScope->isHealthRequest($request)) {
            return false;
        }

        $operatorPrefix = trim((string) config('honeypot.operator.path_prefix', 'ops'), '/');

        if ($operatorPrefix !== '' && ($request->is($operatorPrefix) || $request->is($operatorPrefix.'/*'))) {
            return false;
        }

        return true;
    }
}
