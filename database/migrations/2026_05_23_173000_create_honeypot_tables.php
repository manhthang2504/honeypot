<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('honeypot_sessions', function (Blueprint $table) {
            $table->id();
            $table->string('session_key')->unique();
            $table->string('fingerprint', 64)->index();
            $table->string('source_ip', 45)->nullable()->index();
            $table->text('forwarded_for')->nullable();
            $table->text('user_agent')->nullable();
            $table->string('user_agent_hash', 64)->nullable()->index();
            $table->string('first_path')->nullable();
            $table->timestamp('started_at')->index();
            $table->timestamp('last_seen_at')->index();
            $table->unsignedInteger('hit_count')->default(0);
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('honeypot_events', function (Blueprint $table) {
            $table->id();
            $table->foreignId('honeypot_session_id')->constrained()->cascadeOnDelete();
            $table->timestamp('occurred_at')->index();
            $table->string('method', 16);
            $table->string('scheme', 16)->nullable();
            $table->string('host')->index();
            $table->string('path')->index();
            $table->string('normalized_path')->index();
            $table->text('query_string')->nullable();
            $table->string('ip_address', 45)->nullable()->index();
            $table->string('content_type')->nullable();
            $table->text('user_agent')->nullable();
            $table->text('referer')->nullable();
            $table->json('headers')->nullable();
            $table->json('cookies')->nullable();
            $table->json('query_params')->nullable();
            $table->json('input')->nullable();
            $table->longText('raw_body')->nullable();
            $table->string('raw_body_sha256', 64)->nullable()->index();
            $table->boolean('raw_body_truncated')->default(false);
            $table->string('request_fingerprint', 64)->index();
            $table->boolean('is_duplicate')->default(false)->index();
            $table->string('primary_technique')->nullable()->index();
            $table->json('techniques')->nullable();
            $table->string('bait_profile')->nullable()->index();
            $table->boolean('suspicious')->default(false)->index();
            $table->unsignedSmallInteger('response_status')->default(500);
            $table->string('response_content_type')->nullable();
            $table->json('response_headers')->nullable();
            $table->text('response_excerpt')->nullable();
            $table->unsignedInteger('duration_ms')->default(0);
            $table->timestamps();
        });

        Schema::create('honeypot_artifacts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('honeypot_event_id')->constrained()->cascadeOnDelete();
            $table->string('disk');
            $table->string('storage_path')->nullable();
            $table->string('original_name')->nullable();
            $table->string('client_extension')->nullable();
            $table->string('mime_type')->nullable();
            $table->unsignedBigInteger('size_bytes')->nullable();
            $table->string('sha256', 64)->nullable()->index();
            $table->boolean('stored')->default(false);
            $table->boolean('dangerous')->default(true);
            $table->json('metadata')->nullable();
            $table->timestamps();
        });

        Schema::create('honeypot_daily_summaries', function (Blueprint $table) {
            $table->id();
            $table->date('summary_date')->unique();
            $table->unsignedInteger('total_events')->default(0);
            $table->unsignedInteger('unique_ips')->default(0);
            $table->unsignedInteger('suspicious_events')->default(0);
            $table->json('top_paths')->nullable();
            $table->json('top_techniques')->nullable();
            $table->json('top_ips')->nullable();
            $table->timestamp('generated_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('honeypot_daily_summaries');
        Schema::dropIfExists('honeypot_artifacts');
        Schema::dropIfExists('honeypot_events');
        Schema::dropIfExists('honeypot_sessions');
    }
};
