<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class HoneypotEvent extends Model
{
    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'occurred_at' => 'datetime',
            'headers' => 'array',
            'cookies' => 'array',
            'query_params' => 'array',
            'input' => 'array',
            'techniques' => 'array',
            'response_headers' => 'array',
            'suspicious' => 'boolean',
            'is_duplicate' => 'boolean',
            'raw_body_truncated' => 'boolean',
        ];
    }

    public function session(): BelongsTo
    {
        return $this->belongsTo(HoneypotSession::class, 'honeypot_session_id');
    }

    public function artifacts(): HasMany
    {
        return $this->hasMany(HoneypotArtifact::class);
    }
}
