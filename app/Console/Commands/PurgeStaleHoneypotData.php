<?php

namespace App\Console\Commands;

use App\Models\HoneypotArtifact;
use App\Models\HoneypotDailySummary;
use App\Models\HoneypotEvent;
use App\Models\HoneypotSession;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class PurgeStaleHoneypotData extends Command
{
    protected $signature = 'honeypot:purge-stale-data {--days= : Override retention in days}';

    protected $description = 'Purge honeypot events, artifacts, and summaries older than the retention window.';

    public function handle(): int
    {
        $days = max((int) ($this->option('days') ?: config('honeypot.retention_days', 30)), 1);
        $cutoff = now()->subDays($days);
        $artifactCount = 0;
        $eventCount = 0;

        HoneypotArtifact::query()
            ->whereHas('event', fn ($query) => $query->where('occurred_at', '<', $cutoff))
            ->chunkById(100, function ($artifacts) use (&$artifactCount): void {
                foreach ($artifacts as $artifact) {
                    if ($artifact->stored && $artifact->storage_path) {
                        Storage::disk($artifact->disk)->delete($artifact->storage_path);
                    }

                    $artifact->delete();
                    $artifactCount++;
                }
            });

        HoneypotEvent::query()
            ->where('occurred_at', '<', $cutoff)
            ->chunkById(100, function ($events) use (&$eventCount): void {
                foreach ($events as $event) {
                    $event->delete();
                    $eventCount++;
                }
            });

        HoneypotSession::query()
            ->where('last_seen_at', '<', $cutoff)
            ->doesntHave('events')
            ->delete();

        HoneypotDailySummary::query()
            ->where('summary_date', '<', $cutoff->toDateString())
            ->delete();

        $this->info("Purged {$eventCount} events and {$artifactCount} artifacts older than {$days} days.");

        return self::SUCCESS;
    }
}
