<?php

namespace App\Services\Honeypot;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

class BaitCatalog
{
    public function __construct(
        private readonly AttackClassifier $attackClassifier,
    ) {}

    /**
     * @return array<string, mixed>|null
     */
    public function match(Request $request): ?array
    {
        $path = $this->normalizedPath($request);

        foreach (config('honeypot.deception.profiles', []) as $profile) {
            foreach ($profile['patterns'] ?? [] as $pattern) {
                if (Str::is($pattern, $path)) {
                    return $profile;
                }
            }
        }

        $classification = $this->attackClassifier->classify($request, $request->getContent());

        if ($classification['suspicious']) {
            /** @var array<string, mixed>|null $fallback */
            $fallback = collect(config('honeypot.deception.profiles', []))
                ->first(fn (array $profile): bool => ($profile['name'] ?? null) === 'generic-probe');

            return $fallback;
        }

        return null;
    }

    public function normalizedPath(Request $request): string
    {
        $path = $request->getPathInfo();

        return $path === '' ? '/' : $path;
    }
}
