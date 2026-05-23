<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title ?? 'Honeypot Ops' }}</title>
    <style>
        body { margin: 0; font-family: Arial, sans-serif; background: #f8fafc; color: #0f172a; }
        header { background: #0f172a; color: white; padding: 1rem 1.5rem; }
        main { max-width: 1280px; margin: 0 auto; padding: 1.5rem; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
        .card { background: white; border-radius: 14px; padding: 1rem 1.2rem; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 14px; overflow: hidden; box-shadow: 0 10px 30px rgba(15, 23, 42, 0.08); }
        th, td { padding: 0.85rem 1rem; border-bottom: 1px solid #e2e8f0; text-align: left; vertical-align: top; }
        th { background: #e2e8f0; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
        a { color: #2563eb; text-decoration: none; }
        code, pre { background: #e2e8f0; border-radius: 8px; padding: 0.1rem 0.25rem; }
        pre { padding: 1rem; overflow: auto; }
        .grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); margin-bottom: 1.5rem; }
        .pill { display: inline-block; padding: 0.2rem 0.55rem; background: #dbeafe; border-radius: 999px; margin: 0.15rem 0.25rem 0 0; font-size: 0.8rem; }
        .muted { color: #64748b; }
    </style>
</head>
<body>
    <header>
        <strong>Honeypot telemetry</strong>
        <div class="muted">Protected operator surface</div>
    </header>
    <main>
        @yield('content')
    </main>
</body>
</html>
