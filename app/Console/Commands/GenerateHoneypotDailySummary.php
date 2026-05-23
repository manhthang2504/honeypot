<?php

namespace App\Console\Commands;

use App\Models\HoneypotDailySummary;
use App\Models\HoneypotEvent;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

class GenerateHoneypotDailySummary extends Command
{
    protected $signature = 'honeypot:daily-summary {--date= : Summary date in YYYY-MM-DD format}';

    protected $description = 'Generate and persist a daily summary of captured honeypot traffic.';

    public function handle(): int
    {
        $date = $this->option('date')
            ? Carbon::parse((string) $this->option('date'))->startOfDay()
            : now()->subDay()->startOfDay();

        $query = HoneypotEvent::query()->whereDate('occurred_at', $date);

        $summary = HoneypotDailySummary::query()->updateOrCreate(
            ['summary_date' => $date->toDateString()],
            [
                'total_events' => (clone $query)->count(),
                'unique_ips' => (clone $query)->distinct('ip_address')->count('ip_address'),
                'suspicious_events' => (clone $query)->where('suspicious', true)->count(),
                'top_paths' => $this->topCounts((clone $query), 'path'),
                'top_techniques' => $this->topCounts((clone $query)->whereNotNull('primary_technique'), 'primary_technique'),
                'top_ips' => $this->topCounts((clone $query)->whereNotNull('ip_address'), 'ip_address'),
                'generated_at' => now(),
            ],
        );

        $this->info('Honeypot summary generated for '.$summary->summary_date->toDateString().'.');
        $this->table(
            ['Metric', 'Value'],
            [
                ['total_events', $summary->total_events],
                ['unique_ips', $summary->unique_ips],
                ['suspicious_events', $summary->suspicious_events],
            ],
        );

        return self::SUCCESS;
    }

    /**
     * @return list<array{label:string,hits:int}>
     */
    private function topCounts($query, string $column): array
    {
        return $query
            ->select($column, DB::raw('count(*) as hits'))
            ->groupBy($column)
            ->orderByDesc('hits')
            ->limit(5)
            ->get()
            ->map(fn ($row): array => [
                'label' => (string) $row->{$column},
                'hits' => (int) $row->hits,
            ])
            ->all();
    }
}
