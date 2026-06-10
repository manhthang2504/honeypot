<?php

namespace App\Services\Honeypot;

use App\Models\HoneypotSession;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class SessionResolver
{
    public function resolve(Request $request): HoneypotSession
    {
        $now = CarbonImmutable::now();
        $windowMinutes = max((int) config('honeypot.capture.session_window_minutes', 30), 1);
        $windowSeconds = $windowMinutes * 60;
        $bucketTimestamp = intdiv($now->timestamp, $windowSeconds) * $windowSeconds;
        $bucketStart = CarbonImmutable::createFromTimestamp($bucketTimestamp, $now->timezone);
        $sourceIp = (string) $request->ip();
        $userAgent = (string) $request->userAgent();
        $fingerprint = hash('sha256', strtolower($sourceIp.'|'.$userAgent));
        $sessionKey = hash('sha256', $fingerprint.'|'.$bucketStart->toIso8601String());

        /** @var HoneypotSession $session */
        $session = HoneypotSession::query()->firstOrCreate(
            ['session_key' => $sessionKey],
            [
                'fingerprint' => $fingerprint,
                'source_ip' => $sourceIp !== '' ? $sourceIp : null,
                'forwarded_for' => $this->limitText($request->header('X-Forwarded-For')),
                'user_agent' => $userAgent !== '' ? $this->limitText($userAgent) : null,
                'user_agent_hash' => $userAgent !== '' ? hash('sha256', strtolower($userAgent)) : null,
                'first_path' => Str::limit($request->getPathInfo(), 255, ''),
                'started_at' => $bucketStart,
                'last_seen_at' => $now,
                'hit_count' => 0,
                'metadata' => [
                    'host' => Str::limit($request->getHost(), 255, ''),
                ],
            ],
        );

        $session->forceFill([
            'last_seen_at' => $now,
            'hit_count' => (int) $session->hit_count + 1,
            'forwarded_for' => $this->limitText($request->header('X-Forwarded-For')),
        ])->save();

        return $session;
    }

    private function limitText(?string $value, int $limit = 4096): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        return Str::limit($value, $limit, '');
    }
}
