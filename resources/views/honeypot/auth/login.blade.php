<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title }}</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }
        .shell { max-width: 480px; margin: 6rem auto; padding: 2rem; background: rgba(15, 23, 42, 0.92); border: 1px solid #334155; border-radius: 16px; box-shadow: 0 20px 60px rgba(15, 23, 42, 0.45); }
        .badge { display: inline-block; padding: 0.35rem 0.7rem; border-radius: 999px; background: #1d4ed8; color: white; font-size: 0.8rem; margin-bottom: 1rem; }
        h1 { margin: 0 0 0.5rem; font-size: 1.8rem; }
        p { color: #94a3b8; }
        label { display: block; margin-top: 1rem; font-size: 0.9rem; }
        input { width: 100%; box-sizing: border-box; margin-top: 0.4rem; padding: 0.8rem 0.9rem; border-radius: 10px; border: 1px solid #475569; background: #020617; color: #e2e8f0; }
        button { width: 100%; margin-top: 1.2rem; padding: 0.9rem; border: 0; border-radius: 10px; background: #2563eb; color: white; font-weight: bold; cursor: pointer; }
        .error { margin-top: 1rem; padding: 0.8rem 0.9rem; border-radius: 10px; background: rgba(153, 27, 27, 0.35); border: 1px solid #7f1d1d; color: #fecaca; }
        .hint { margin-top: 1rem; font-size: 0.85rem; color: #64748b; }
    </style>
</head>
<body>
    <div class="shell">
        <span class="badge">restricted</span>
        <h1>{{ $title }}</h1>
        <p>{{ $subtitle }}</p>
        <form method="post" action="{{ $path }}">
            <label for="email">Username or email</label>
            <input id="email" type="text" name="email" autocomplete="username">

            <label for="password">Password</label>
            <input id="password" type="password" name="password" autocomplete="current-password">

            <button type="submit">Continue</button>
        </form>

        @if ($invalidAttempt && $errorMessage)
            <div class="error">{{ $errorMessage }}</div>
        @endif

        <div class="hint">Request method: {{ $method }} &middot; Endpoint: {{ $path }}</div>
    </div>
</body>
</html>
