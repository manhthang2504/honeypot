<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class HoneypotDailySummary extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'summary_date' => 'date',
            'top_paths' => 'array',
            'top_techniques' => 'array',
            'top_ips' => 'array',
            'generated_at' => 'datetime',
        ];
    }
}
