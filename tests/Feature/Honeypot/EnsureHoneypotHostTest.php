<?php

namespace Tests\Feature\Honeypot;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class EnsureHoneypotHostTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_allows_requests_for_a_configured_honeypot_host(): void
    {
        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', true);
        config()->set('honeypot.allowed_hosts', ['honeypot.test']);

        $response = $this->get('http://honeypot.test/');

        $response->assertOk();
    }

    public function test_it_allows_the_health_path_even_for_unexpected_hosts(): void
    {
        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', true);
        config()->set('honeypot.allowed_hosts', ['honeypot.test']);

        $response = $this->get('http://public-site.test/up');

        $response->assertOk();
    }

    public function test_it_rejects_requests_for_an_unexpected_host(): void
    {
        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', true);
        config()->set('honeypot.allowed_hosts', ['honeypot.test']);

        $response = $this->get('http://public-site.test/');

        $response->assertNotFound();
    }

    public function test_it_rejects_all_requests_when_the_allowed_host_list_is_empty(): void
    {
        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', true);
        config()->set('honeypot.allowed_hosts', []);

        $response = $this->get('http://honeypot.test/');

        $response->assertNotFound();
    }

    public function test_it_can_disable_host_enforcement_for_local_bootstrapping(): void
    {
        config()->set('honeypot.enabled', true);
        config()->set('honeypot.enforce_host', false);
        config()->set('honeypot.allowed_hosts', ['honeypot.test']);

        $response = $this->get('http://public-site.test/');

        $response->assertOk();
    }
}
