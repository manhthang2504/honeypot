<?php

use App\Http\Controllers\Honeypot\HoneypotController;
use Illuminate\Support\Facades\Route;

Route::any('/{path?}', HoneypotController::class)
    ->where('path', '.*')
    ->name('honeypot.catch-all');
