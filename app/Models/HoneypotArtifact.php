<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class HoneypotArtifact extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'stored' => 'boolean',
            'dangerous' => 'boolean',
            'metadata' => 'array',
        ];
    }

    public function event(): BelongsTo
    {
        return $this->belongsTo(HoneypotEvent::class, 'honeypot_event_id');
    }
}
