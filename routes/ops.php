<?php

use App\Http\Controllers\Honeypot\OperatorDashboardController;
use Illuminate\Support\Facades\Route;

Route::middleware('honeypot.operator')
    ->prefix(config('honeypot.operator.path_prefix', 'ops'))
    ->as('honeypot.ops.')
    ->group(function (): void {
        Route::get('/', [OperatorDashboardController::class, 'index'])->name('dashboard');
        Route::get('/events/{event}', [OperatorDashboardController::class, 'show'])->name('events.show');
    });
