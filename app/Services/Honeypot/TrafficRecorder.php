<?php

namespace App\Services\Honeypot;

use App\Models\HoneypotArtifact;
use App\Models\HoneypotEvent;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Arr;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class TrafficRecorder
{
    public function __construct(
        private readonly AttackClassifier $attackClassifier,
        private readonly SessionResolver $sessionResolver,
    ) {}

    public function record(Request $request, ?Response $response, int $durationMs, ?Throwable $exception = null): HoneypotEvent
    {
        [$rawBody, $rawBodySha, $wasTruncated] = $this->captureBody($request);
        $profileTechniques = Arr::wrap($request->attributes->get('honeypot.profile_techniques', []));
        $classification = $this->attackClassifier->classify($request, $rawBody, $profileTechniques);
        $requestFingerprint = hash('sha256', implode('|', [
            strtoupper($request->method()),
            $request->getHost(),
            $request->getPathInfo(),
            (string) $request->getQueryString(),
            $rawBodySha ?? '',
        ]));
        $isDuplicate = HoneypotEvent::query()->where('request_fingerprint', $requestFingerprint)->exists();
        $session = $this->sessionResolver->resolve($request);

        $event = HoneypotEvent::query()->create([
            'honeypot_session_id' => $session->id,
            'occurred_at' => now(),
            'method' => strtoupper($request->method()),
            'scheme' => $request->getScheme(),
            'host' => $request->getHost(),
            'path' => $request->getPathInfo(),
            'normalized_path' => strtolower($request->getPathInfo()),
            'query_string' => $request->getQueryString(),
            'ip_address' => $request->ip(),
            'content_type' => $request->header('Content-Type'),
            'user_agent' => $request->userAgent(),
            'referer' => $request->headers->get('referer'),
            'headers' => $request->headers->all(),
            'cookies' => $request->cookies->all(),
            'query_params' => $request->query(),
            'input' => $request->input(),
            'raw_body' => $rawBody,
            'raw_body_sha256' => $rawBodySha,
            'raw_body_truncated' => $wasTruncated,
            'request_fingerprint' => $requestFingerprint,
            'is_duplicate' => $isDuplicate,
            'primary_technique' => $classification['primary_technique'],
            'techniques' => $classification['techniques'],
            'bait_profile' => $request->attributes->get('honeypot.bait_profile'),
            'suspicious' => $classification['suspicious'],
            'response_status' => $response?->getStatusCode() ?? 500,
            'response_content_type' => $response?->headers->get('content-type'),
            'response_headers' => $response?->headers->all() ?? [],
            'response_excerpt' => $this->responseExcerpt($response, $exception),
            'duration_ms' => max($durationMs, 0),
        ]);

        $this->storeArtifacts($request, $event);

        return $event;
    }

    /**
     * @return array{0:string, 1:?string, 2:bool}
     */
    private function captureBody(Request $request): array
    {
        $rawBody = (string) $request->getContent();
        $maxBytes = max((int) config('honeypot.capture.max_body_bytes', 65535), 1);
        $wasTruncated = strlen($rawBody) > $maxBytes;
        $storedBody = $wasTruncated ? substr($rawBody, 0, $maxBytes) : $rawBody;

        return [
            $storedBody,
            $rawBody !== '' ? hash('sha256', $rawBody) : null,
            $wasTruncated,
        ];
    }

    private function responseExcerpt(?Response $response, ?Throwable $exception): ?string
    {
        if ($exception instanceof Throwable) {
            return $exception::class.': '.$exception->getMessage();
        }

        if (! $response || ! method_exists($response, 'getContent')) {
            return null;
        }

        $content = $response->getContent();

        if (! is_string($content) || $content === '') {
            return null;
        }

        return substr($content, 0, 2000);
    }

    private function storeArtifacts(Request $request, HoneypotEvent $event): void
    {
        $disk = (string) config('honeypot.capture.quarantine_disk', 'honeypot-quarantine');
        $maxBytes = max((int) config('honeypot.capture.upload_max_kb', 2048), 1) * 1024;

        foreach ($this->flattenFiles($request->allFiles()) as $file) {
            $size = $file->getSize();
            $sha256 = is_string($file->getRealPath()) ? hash_file('sha256', $file->getRealPath()) : null;
            $stored = $size !== false && $size !== null && $size <= $maxBytes && $sha256 !== null;
            $storagePath = null;

            if ($stored && $sha256 !== null) {
                $extension = $file->guessExtension() ?: $file->getClientOriginalExtension() ?: 'bin';
                $storagePath = $file->storeAs(now()->format('Y/m/d'), $sha256.'.'.$extension, [
                    'disk' => $disk,
                ]);
            }

            HoneypotArtifact::query()->create([
                'honeypot_event_id' => $event->id,
                'disk' => $disk,
                'storage_path' => $storagePath,
                'original_name' => $file->getClientOriginalName(),
                'client_extension' => $file->getClientOriginalExtension(),
                'mime_type' => $file->getClientMimeType(),
                'size_bytes' => $size,
                'sha256' => $sha256,
                'stored' => $stored,
                'dangerous' => true,
                'metadata' => [
                    'error' => $file->getError(),
                    'stored_reason' => $stored ? 'quarantined' : 'size_limit_or_missing_hash',
                ],
            ]);
        }
    }

    /**
     * @param  array<string, mixed>  $files
     * @return list<UploadedFile>
     */
    private function flattenFiles(array $files): array
    {
        $flattened = [];

        foreach ($files as $file) {
            if ($file instanceof UploadedFile) {
                $flattened[] = $file;

                continue;
            }

            if (is_array($file)) {
                $flattened = array_merge($flattened, $this->flattenFiles($file));
            }
        }

        return $flattened;
    }
}
