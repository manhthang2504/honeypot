<?php

namespace App\Services\Honeypot;

use Illuminate\Contracts\View\Factory as ViewFactory;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Str;

class DeceptionResponder
{
    public function __construct(
        private readonly BaitCatalog $baitCatalog,
        private readonly ViewFactory $viewFactory,
    ) {}

    public function respond(Request $request): Response
    {
        $profile = $this->baitCatalog->match($request);

        if ($profile === null) {
            abort(Response::HTTP_NOT_FOUND);
        }

        $request->attributes->set('honeypot.bait_profile', $profile['name'] ?? null);
        $request->attributes->set('honeypot.profile_techniques', $profile['techniques'] ?? []);

        $this->applyDelay();

        $response = match ($profile['response'] ?? 'probe') {
            'login' => $this->loginResponse($request, $profile),
            'dashboard' => $this->dashboardResponse($request, $profile),
            'file' => $this->fileResponse($request, $profile),
            'exploit' => $this->exploitResponse($request, $profile),
            default => $this->probeResponse($request, $profile),
        };

        return $response->withHeaders([
            'Cache-Control' => 'no-store, private',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    private function loginResponse(Request $request, array $profile): Response
    {
        $content = $this->viewFactory->make('honeypot.auth.login', [
            'title' => $profile['title'] ?? 'Administrative Console',
            'subtitle' => $profile['subtitle'] ?? 'Authentication is required.',
            'path' => $request->getPathInfo(),
            'method' => strtoupper($request->method()),
            'invalidAttempt' => strtoupper($request->method()) !== 'GET',
            'errorMessage' => strtoupper($request->method()) === 'GET'
                ? null
                : 'The supplied credentials were rejected by the upstream identity provider.',
        ])->render();

        return response($content, $profile['status'] ?? 200)
            ->cookie('hp_session', Str::uuid()->toString(), 60, '/', null, false, true, false, 'lax');
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    private function dashboardResponse(Request $request, array $profile): Response
    {
        $content = $this->viewFactory->make('honeypot.auth.dashboard', [
            'title' => $profile['title'] ?? 'Operations Dashboard',
            'path' => $request->getPathInfo(),
            'host' => $request->getHost(),
        ])->render();

        return response($content, $profile['status'] ?? 200)
            ->cookie('hp_session', Str::uuid()->toString(), 60, '/', null, false, true, false, 'lax');
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    private function fileResponse(Request $request, array $profile): Response
    {
        $content = $this->fileContents((string) ($profile['file_key'] ?? 'env'), $request);

        return response($content, $profile['status'] ?? 200)
            ->header('Content-Type', $profile['content_type'] ?? 'text/plain; charset=UTF-8');
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    private function exploitResponse(Request $request, array $profile): Response
    {
        $content = $this->viewFactory->make('honeypot.errors.exploit', [
            'title' => $profile['title'] ?? 'Execution pipeline error',
            'path' => $request->getPathInfo(),
            'requestId' => (string) Str::uuid(),
        ])->render();

        return response($content, $profile['status'] ?? 500);
    }

    /**
     * @param  array<string, mixed>  $profile
     */
    private function probeResponse(Request $request, array $profile): Response
    {
        $content = $this->viewFactory->make('honeypot.errors.probe', [
            'title' => $profile['title'] ?? 'Request blocked by upstream gateway',
            'path' => $request->getPathInfo(),
            'requestId' => (string) Str::uuid(),
        ])->render();

        return response($content, $profile['status'] ?? 403);
    }

    private function fileContents(string $fileKey, Request $request): string
    {
        return match ($fileKey) {
            'git-config' => "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@github.com:internal/ops-portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            'laravel-log' => '['.now()->subMinutes(2)->format('Y-m-d H:i:s')."] production.ERROR: SQLSTATE[HY000] [1045] Access denied for user 'reporting'@'127.0.0.1' (Connection: mysql, SQL: select * from failed_jobs where queue = default) {\"exception\":\"[object] (PDOException(code: 1045): SQLSTATE[HY000] [1045] Access denied at /var/www/html/vendor/laravel/framework/src/Illuminate/Database/Connectors/Connector.php:67)\"}\n",
            'backup' => "-- mysqldump 10.19 Distrib 10.6.17-MariaDB\nCREATE DATABASE IF NOT EXISTS ops_portal;\nUSE ops_portal;\nCREATE TABLE admins (id bigint unsigned, email varchar(255), password varchar(255));\nINSERT INTO admins VALUES (1,'ops-admin@{$request->getHost()}','\$2y\$12\$B4h6V9Vd3I0b6lb0A7LgsuM2fYh0vnF1lz9mA6W3oIfx5WqQK6F8e');\n",
            'config-php' => "<?php\nreturn [\n    'app_env' => 'production',\n    'db_host' => '127.0.0.1',\n    'db_name' => 'ops_portal',\n    'db_user' => 'reporting',\n    'db_pass' => 'S3rvice!2025',\n    'cache_prefix' => 'ops_portal_',\n];\n",
            default => "APP_NAME=OperationsPortal\nAPP_ENV=production\nAPP_KEY=base64:6SW+qH1WcFQqM1bE0R8Q2vD2P9Q6t0m1Yk8rL5Vh7sI=\nAPP_DEBUG=false\nAPP_URL=https://{$request->getHost()}\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=ops_portal\nDB_USERNAME=reporting\nDB_PASSWORD=S3rvice!2025\nCACHE_DRIVER=redis\nQUEUE_CONNECTION=database\nMAIL_HOST=10.0.10.15\nMAIL_PORT=2525\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
        };
    }

    private function applyDelay(): void
    {
        $min = max((int) config('honeypot.deception.delay_ms.min', 0), 0);
        $max = max((int) config('honeypot.deception.delay_ms.max', 0), $min);

        if ($max === 0) {
            return;
        }

        usleep(random_int($min, $max) * 1000);
    }
}
