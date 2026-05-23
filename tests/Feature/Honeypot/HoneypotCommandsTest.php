<?php

namespace Tests\Feature\Honeypot;

use App\Models\HoneypotArtifact;
use App\Models\HoneypotDailySummary;
use App\Models\HoneypotEvent;
use App\Models\HoneypotSession;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class HoneypotCommandsTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('honeypot.retention_days', 30);
        Storage::fake('honeypot-quarantine');
    }

    public function test_daily_summary_command_persists_rollups(): void
    {
        $session = HoneypotSession::query()->create([
            'session_key' => 'session-1',
            'fingerprint' => hash('sha256', 'session-1'),
            'source_ip' => '127.0.0.1',
            'forwarded_for' => null,
            'user_agent' => 'scanner',
            'user_agent_hash' => hash('sha256', 'scanner'),
            'first_path' => '/.env',
            'started_at' => now()->subDay(),
            'last_seen_at' => now()->subDay(),
            'hit_count' => 1,
            'metadata' => ['host' => 'honeypot.test'],
        ]);

        HoneypotEvent::query()->create([
            'honeypot_session_id' => $session->id,
            'occurred_at' => now()->subDay(),
            'method' => 'GET',
            'scheme' => 'http',
            'host' => 'honeypot.test',
            'path' => '/.env',
            'normalized_path' => '/.env',
            'query_string' => null,
            'ip_address' => '127.0.0.1',
            'content_type' => null,
            'user_agent' => 'scanner',
            'referer' => null,
            'headers' => [],
            'cookies' => [],
            'query_params' => [],
            'input' => [],
            'raw_body' => null,
            'raw_body_sha256' => null,
            'raw_body_truncated' => false,
            'request_fingerprint' => hash('sha256', 'request-1'),
            'is_duplicate' => false,
            'primary_technique' => 'env_harvest',
            'techniques' => ['env_harvest'],
            'bait_profile' => 'env-file',
            'suspicious' => true,
            'response_status' => 200,
            'response_content_type' => 'text/plain',
            'response_headers' => [],
            'response_excerpt' => 'APP_KEY=',
            'duration_ms' => 10,
        ]);

        $date = now()->subDay()->toDateString();

        $this->artisan('honeypot:daily-summary', ['--date' => $date])
            ->assertSuccessful();

        $summary = HoneypotDailySummary::query()->whereDate('summary_date', $date)->first();

        $this->assertNotNull($summary);
        $this->assertSame(1, $summary->total_events);
        $this->assertSame(1, $summary->unique_ips);
    }

    public function test_purge_command_deletes_stale_events_artifacts_and_files(): void
    {
        $session = HoneypotSession::query()->create([
            'session_key' => 'session-2',
            'fingerprint' => hash('sha256', 'session-2'),
            'source_ip' => '127.0.0.2',
            'forwarded_for' => null,
            'user_agent' => 'scanner',
            'user_agent_hash' => hash('sha256', 'scanner'),
            'first_path' => '/backup.zip',
            'started_at' => now()->subDays(60),
            'last_seen_at' => now()->subDays(60),
            'hit_count' => 1,
            'metadata' => ['host' => 'honeypot.test'],
        ]);

        $event = HoneypotEvent::query()->create([
            'honeypot_session_id' => $session->id,
            'occurred_at' => now()->subDays(60),
            'method' => 'GET',
            'scheme' => 'http',
            'host' => 'honeypot.test',
            'path' => '/backup.zip',
            'normalized_path' => '/backup.zip',
            'query_string' => null,
            'ip_address' => '127.0.0.2',
            'content_type' => null,
            'user_agent' => 'scanner',
            'referer' => null,
            'headers' => [],
            'cookies' => [],
            'query_params' => [],
            'input' => [],
            'raw_body' => null,
            'raw_body_sha256' => null,
            'raw_body_truncated' => false,
            'request_fingerprint' => hash('sha256', 'request-2'),
            'is_duplicate' => false,
            'primary_technique' => 'backup_harvest',
            'techniques' => ['backup_harvest'],
            'bait_profile' => 'backup-archive',
            'suspicious' => true,
            'response_status' => 200,
            'response_content_type' => 'application/octet-stream',
            'response_headers' => [],
            'response_excerpt' => 'dump',
            'duration_ms' => 12,
        ]);

        Storage::disk('honeypot-quarantine')->put('2026/01/01/artifact.txt', 'payload');

        HoneypotArtifact::query()->create([
            'honeypot_event_id' => $event->id,
            'disk' => 'honeypot-quarantine',
            'storage_path' => '2026/01/01/artifact.txt',
            'original_name' => 'artifact.txt',
            'client_extension' => 'txt',
            'mime_type' => 'text/plain',
            'size_bytes' => 7,
            'sha256' => hash('sha256', 'payload'),
            'stored' => true,
            'dangerous' => true,
            'metadata' => [],
        ]);

        HoneypotDailySummary::query()->create([
            'summary_date' => now()->subDays(60)->toDateString(),
            'total_events' => 1,
            'unique_ips' => 1,
            'suspicious_events' => 1,
            'top_paths' => [['label' => '/backup.zip', 'hits' => 1]],
            'top_techniques' => [['label' => 'backup_harvest', 'hits' => 1]],
            'top_ips' => [['label' => '127.0.0.2', 'hits' => 1]],
            'generated_at' => now()->subDays(60),
        ]);

        $this->artisan('honeypot:purge-stale-data', ['--days' => 30])
            ->assertSuccessful();

        $this->assertDatabaseCount('honeypot_events', 0);
        $this->assertDatabaseCount('honeypot_artifacts', 0);
        $this->assertDatabaseCount('honeypot_daily_summaries', 0);
        Storage::disk('honeypot-quarantine')->assertMissing('2026/01/01/artifact.txt');
    }
}
