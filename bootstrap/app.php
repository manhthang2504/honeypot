<?php

use App\Http\Middleware\CaptureHoneypotTraffic;
use App\Http\Middleware\EnsureHoneypotHost;
use App\Http\Middleware\EnsureHoneypotOperatorAccess;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: [
            __DIR__.'/../routes/ops.php',
            __DIR__.'/../routes/web.php',
        ],
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withCommands([
        __DIR__.'/../app/Console/Commands',
    ])
    ->withSchedule(function (Schedule $schedule): void {
        $schedule->command('honeypot:daily-summary')->dailyAt('00:15');
        $schedule->command('honeypot:purge-stale-data')->dailyAt('01:00');
    })
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'honeypot.operator' => EnsureHoneypotOperatorAccess::class,
        ]);

        $middleware->append([
            EnsureHoneypotHost::class,
            CaptureHoneypotTraffic::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
