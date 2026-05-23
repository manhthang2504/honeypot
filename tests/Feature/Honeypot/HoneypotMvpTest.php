<?php

namespace Tests\Feature\Honeypot;

use App\Models\HoneypotEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

class HoneypotMvpTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', true);
        config()->set('honeypot.allowed_hosts', ['honeypot.test']);
        config()->set('honeypot.operator.token', 'secret-token');
        config()->set('honeypot.operator.path_prefix', 'ops');
        config()->set('honeypot.capture.quarantine_disk', 'honeypot-quarantine');
        Storage::fake('honeypot-quarantine');
    }

    public function test_it_serves_a_fake_env_file_and_records_the_event(): void
    {
        $response = $this->get('http://honeypot.test/.env');

        $response->assertOk();
        $response->assertHeader('content-type', 'text/plain; charset=UTF-8');
        $response->assertSee('APP_KEY=', false);

        $event = HoneypotEvent::query()->latest('id')->firstOrFail();

        $this->assertSame('/.env', $event->path);
        $this->assertSame('env-file', $event->bait_profile);
        $this->assertContains('env_harvest', $event->techniques ?? []);
    }

    public function test_it_returns_a_non_404_for_suspicious_unknown_paths(): void
    {
        $response = $this->get('http://honeypot.test/private/backup.tar?file=../../etc/passwd');

        $response->assertStatus(403);

        $event = HoneypotEvent::query()->latest('id')->firstOrFail();

        $this->assertTrue($event->suspicious);
        $this->assertSame('generic-probe', $event->bait_profile);
    }

    public function test_operator_routes_require_a_token_and_are_not_captured_as_honeypot_events(): void
    {
        $this->get('http://honeypot.test/ops')->assertNotFound();

        $this->get('http://honeypot.test/ops?token=secret-token')
            ->assertOk()
            ->assertSee('Honeypot telemetry');

        $this->assertSame(0, HoneypotEvent::query()->count());
    }

    public function test_it_quarantines_uploaded_files_as_artifacts(): void
    {
        $response = $this->post('http://honeypot.test/admin/upload.php', [
            'payload' => UploadedFile::fake()->create('shell.php', 5, 'application/x-php'),
        ]);

        $response->assertStatus(403);

        $event = HoneypotEvent::query()->with('artifacts')->latest('id')->firstOrFail();
        $artifact = $event->artifacts->first();

        $this->assertNotNull($artifact);
        $this->assertTrue($artifact->stored);
        Storage::disk('honeypot-quarantine')->assertExists($artifact->storage_path);
    }
}
