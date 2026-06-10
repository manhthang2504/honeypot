<?php

namespace App\Services\Honeypot;

use App\Models\HoneypotArtifact;
use App\Models\HoneypotEvent;
use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
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
        $path = $this->limitString($request->getPathInfo(), 255);
        $queryString = $this->limitText($request->getQueryString());
        $requestFingerprint = hash('sha256', implode('|', [
            strtoupper($request->method()),
            $this->limitString($request->getHost(), 255),
            $path,
            (string) $queryString,
            $rawBodySha ?? '',
        ]));
        $isDuplicate = HoneypotEvent::query()->where('request_fingerprint', $requestFingerprint)->exists();
        $session = $this->sessionResolver->resolve($request);

        $event = HoneypotEvent::query()->create([
            'honeypot_session_id' => $session->id,
            'occurred_at' => now(),
            'method' => $this->limitString(strtoupper($request->method()), 16),
            'scheme' => $this->limitString($request->getScheme(), 16),
            'host' => $this->limitString($request->getHost(), 255),
            'path' => $path,
            'normalized_path' => $this->limitString(strtolower($path), 255),
            'query_string' => $queryString,
            'ip_address' => $this->limitString((string) $request->ip(), 45),
            'content_type' => $this->limitText($request->header('Content-Type'), 255),
            'user_agent' => $this->limitText($request->userAgent()),
            'referer' => $this->limitText($request->headers->get('referer')),
            'headers' => $this->sanitizeArray($request->headers->all()),
            'cookies' => $this->sanitizeArray($request->cookies->all()),
            'query_params' => $this->sanitizeArray($request->query()),
            'input' => $this->sanitizeArray($request->input()),
            'raw_body' => $rawBody,
            'raw_body_sha256' => $rawBodySha,
            'raw_body_truncated' => $wasTruncated,
            'request_fingerprint' => $requestFingerprint,
            'is_duplicate' => $isDuplicate,
            'primary_technique' => $this->limitText($classification['primary_technique'], 255),
            'techniques' => $this->sanitizeList($classification['techniques']),
            'bait_profile' => $this->limitText($request->attributes->get('honeypot.bait_profile'), 255),
            'suspicious' => $classification['suspicious'],
            'response_status' => $response?->getStatusCode() ?? 500,
            'response_content_type' => $this->limitText($response?->headers->get('content-type'), 255),
            'response_headers' => $this->sanitizeArray($response?->headers->all() ?? []),
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
            $this->previewText($storedBody, strlen($rawBody), $wasTruncated),
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

        return $this->limitText($content, 2000);
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

    private function previewText(string $value, int $originalBytes, bool $wasTruncated): string
    {
        $maxPreviewBytes = max((int) config('honeypot.capture.max_preview_bytes', 8192), 1);
        $preview = substr($value, 0, $maxPreviewBytes);

        if ($preview === '') {
            return '';
        }

        if (mb_check_encoding($preview, 'UTF-8')) {
            return $this->limitText($preview, $maxPreviewBytes) ?? '';
        }

        $encoded = base64_encode($preview);
        $suffix = $wasTruncated ? ', truncated=yes' : '';

        return sprintf(
            '[binary body bytes=%d, preview_base64=%s%s]',
            $originalBytes,
            $encoded,
            $suffix,
        );
    }

    /**
     * @param  array<array-key, mixed>  $value
     * @return array<array-key, mixed>
     */
    private function sanitizeArray(array $value, int $depth = 0): array
    {
        $maxDepth = max((int) config('honeypot.capture.max_depth', 5), 1);

        if ($depth >= $maxDepth) {
            return ['_truncated' => 'depth_limit'];
        }

        $maxItems = max((int) config('honeypot.capture.max_collection_items', 50), 1);
        $sanitized = [];
        $index = 0;

        foreach ($value as $key => $item) {
            if ($index >= $maxItems) {
                $sanitized['_truncated'] = 'item_limit';
                break;
            }

            $sanitized[$this->sanitizeKey($key)] = $this->sanitizeValue($item, $depth + 1);
            $index++;
        }

        return $sanitized;
    }

    /**
     * @param  list<string>  $value
     * @return list<string>
     */
    private function sanitizeList(array $value): array
    {
        $sanitized = [];

        foreach ($value as $item) {
            $normalized = $this->limitText(is_string($item) ? $item : null, 255);

            if ($normalized !== null && $normalized !== '') {
                $sanitized[] = $normalized;
            }
        }

        return array_values(array_unique($sanitized));
    }

    private function sanitizeValue(mixed $value, int $depth): mixed
    {
        if (is_array($value)) {
            return $this->sanitizeArray($value, $depth);
        }

        if (is_string($value)) {
            return $this->limitText($value);
        }

        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }

        if ($value instanceof UploadedFile) {
            return [
                'original_name' => $this->limitText($value->getClientOriginalName(), 255),
                'mime_type' => $this->limitText($value->getClientMimeType(), 255),
                'size_bytes' => $value->getSize(),
            ];
        }

        return $this->limitText(get_debug_type($value), 255);
    }

    private function sanitizeKey(mixed $key): string|int
    {
        if (is_int($key)) {
            return $key;
        }

        return $this->limitString((string) $key, 255);
    }

    private function limitString(string $value, int $limit): string
    {
        return Str::limit($value, $limit, '');
    }

    private function limitText(?string $value, int $limit = 8192): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        if (! mb_check_encoding($value, 'UTF-8')) {
            $prefix = substr($value, 0, min(strlen($value), $limit));

            return sprintf(
                '[binary bytes=%d, preview_base64=%s]',
                strlen($value),
                base64_encode($prefix),
            );
        }

        return mb_strcut($value, 0, $limit, 'UTF-8');
    }
}
