<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ $title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f8fafc; color: #0f172a; }
        header { background: #0f172a; color: white; padding: 1.4rem 2rem; }
        main { padding: 2rem; max-width: 1100px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
        .card { background: white; border-radius: 14px; padding: 1.2rem; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.08); }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: white; border-radius: 14px; overflow: hidden; }
        th, td { padding: 0.85rem 1rem; border-bottom: 1px solid #e2e8f0; text-align: left; }
        th { background: #e2e8f0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.04em; }
    </style>
</head>
<body>
    <header>
        <strong>{{ $title }}</strong><br>
        <small>Cluster node: {{ $host }} &middot; Current path: {{ $path }}</small>
    </header>
    <main>
        <div class="grid">
            <div class="card">
                <strong>Open incidents</strong>
                <div style="font-size: 2rem; margin-top: 0.5rem;">14</div>
            </div>
            <div class="card">
                <strong>Pending patches</strong>
                <div style="font-size: 2rem; margin-top: 0.5rem;">3</div>
            </div>
            <div class="card">
                <strong>Failed jobs</strong>
                <div style="font-size: 2rem; margin-top: 0.5rem;">27</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>System</th>
                    <th>Status</th>
                    <th>Last sync</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>identity-provider</td>
                    <td>degraded</td>
                    <td>{{ now()->subMinutes(5)->format('Y-m-d H:i:s') }}</td>
                </tr>
                <tr>
                    <td>reporting-db</td>
                    <td>online</td>
                    <td>{{ now()->subMinutes(2)->format('Y-m-d H:i:s') }}</td>
                </tr>
                <tr>
                    <td>mailer</td>
                    <td>delayed</td>
                    <td>{{ now()->subMinute()->format('Y-m-d H:i:s') }}</td>
                </tr>
            </tbody>
        </table>
    </main>
</body>
</html>
