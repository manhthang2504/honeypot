<?php

namespace App\Http\Controllers\Honeypot;

use App\Http\Controllers\Controller;
use App\Models\HoneypotDailySummary;
use App\Models\HoneypotEvent;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OperatorDashboardController extends Controller
{
    public function index(Request $request): View
    {
        $accessToken = (string) $request->query('token', '');
        $events = HoneypotEvent::query()
            ->with(['session', 'artifacts'])
            ->latest('occurred_at')
            ->paginate(25)
            ->appends(['token' => $accessToken]);

        $topPaths = HoneypotEvent::query()
            ->select('path', DB::raw('count(*) as hits'))
            ->groupBy('path')
            ->orderByDesc('hits')
            ->limit(10)
            ->get();

        $topTechniques = HoneypotEvent::query()
            ->whereNotNull('primary_technique')
            ->select('primary_technique', DB::raw('count(*) as hits'))
            ->groupBy('primary_technique')
            ->orderByDesc('hits')
            ->limit(10)
            ->get();

        $stats = [
            'events' => HoneypotEvent::query()->count(),
            'unique_ips' => HoneypotEvent::query()->distinct('ip_address')->count('ip_address'),
            'suspicious' => HoneypotEvent::query()->where('suspicious', true)->count(),
            'artifacts' => HoneypotEvent::query()->has('artifacts')->count(),
        ];

        return view('honeypot.ops.dashboard', [
            'accessToken' => $accessToken,
            'events' => $events,
            'recentSummaries' => HoneypotDailySummary::query()->latest('summary_date')->limit(7)->get(),
            'stats' => $stats,
            'topPaths' => $topPaths,
            'topTechniques' => $topTechniques,
        ]);
    }

    public function show(Request $request, HoneypotEvent $event): View
    {
        $event->load(['session', 'artifacts']);

        return view('honeypot.ops.event', [
            'accessToken' => (string) $request->query('token', ''),
            'event' => $event,
        ]);
    }
}
