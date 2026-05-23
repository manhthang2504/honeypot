<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>{{ $title }}</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
        .panel { max-width: 720px; margin: 3rem auto; background: rgba(15, 23, 42, 0.92); border: 1px solid #334155; border-radius: 16px; padding: 1.5rem; }
        small { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="panel">
        <h1>{{ $title }}</h1>
        <p>The requested upstream resource is temporarily unavailable. Retry after credential validation or contact the service owner.</p>
        <small>Path: {{ $path }} &middot; Request ID: {{ $requestId }}</small>
    </div>
</body>
</html>
