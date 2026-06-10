@extends('honeypot.ops.layout', ['title' => 'Honeypot dashboard'])

@section('content')
    <div class="stats">
        <div class="card"><strong>Total events</strong><div style="font-size: 2rem; margin-top: 0.4rem;">{{ $stats['events'] }}</div></div>
        <div class="card"><strong>Unique IPs</strong><div style="font-size: 2rem; margin-top: 0.4rem;">{{ $stats['unique_ips'] }}</div></div>
        <div class="card"><strong>Suspicious events</strong><div style="font-size: 2rem; margin-top: 0.4rem;">{{ $stats['suspicious'] }}</div></div>
        <div class="card"><strong>Events with artifacts</strong><div style="font-size: 2rem; margin-top: 0.4rem;">{{ $stats['artifacts'] }}</div></div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Top targeted paths</h3>
            <table>
                <thead><tr><th>Path</th><th>Hits</th></tr></thead>
                <tbody>
                @forelse ($topPaths as $path)
                    <tr><td><code>{{ $path->path }}</code></td><td>{{ $path->hits }}</td></tr>
                @empty
                    <tr><td colspan="2">No events yet.</td></tr>
                @endforelse
                </tbody>
            </table>
        </div>
        <div class="card">
            <h3>Top techniques</h3>
            <table>
                <thead><tr><th>Technique</th><th>Hits</th></tr></thead>
                <tbody>
                @forelse ($topTechniques as $technique)
                    <tr><td>{{ $technique->primary_technique }}</td><td>{{ $technique->hits }}</td></tr>
                @empty
                    <tr><td colspan="2">No classified traffic yet.</td></tr>
                @endforelse
                </tbody>
            </table>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Recent daily summaries</h3>
            <table>
                <thead><tr><th>Date</th><th>Events</th><th>IPs</th></tr></thead>
                <tbody>
                @forelse ($recentSummaries as $summary)
                    <tr>
                        <td>{{ $summary->summary_date->toDateString() }}</td>
                        <td>{{ $summary->total_events }}</td>
                        <td>{{ $summary->unique_ips }}</td>
                    </tr>
                @empty
                    <tr><td colspan="3">Run <code>php artisan honeypot:daily-summary</code> to persist rollups.</td></tr>
                @endforelse
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h3>Recent captured events</h3>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Technique</th>
                    <th>Status</th>
                    <th>Artifacts</th>
                </tr>
            </thead>
            <tbody>
            @forelse ($events as $event)
                <tr>
                    <td>{{ $event->occurred_at?->format('Y-m-d H:i:s') }}</td>
                    <td>{{ $event->method }}</td>
                    <td>
                        <a href="{{ route('honeypot.ops.events.show', ['event' => $event]) }}">
                            <code>{{ $event->path }}</code>
                        </a>
                    </td>
                    <td>{{ $event->primary_technique ?? 'unclassified' }}</td>
                    <td>{{ $event->response_status }}</td>
                    <td>{{ $event->artifacts->count() }}</td>
                </tr>
            @empty
                <tr><td colspan="6">No traffic captured yet.</td></tr>
            @endforelse
            </tbody>
        </table>

        <div style="margin-top: 1rem;">
            {{ $events->links() }}
        </div>
    </div>
@endsection
