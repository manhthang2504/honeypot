<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use RuntimeException;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        if (app()->isProduction() && blank(config('honeypot.operator.token'))) {
            throw new RuntimeException('HONEYPOT_OPERATOR_TOKEN must be configured in production.');
        }
    }
}
