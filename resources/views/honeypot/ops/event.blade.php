@extends('honeypot.ops.layout', ['title' => 'Captured event'])

@section('content')
    <p><a href="{{ route('honeypot.ops.dashboard') }}">&larr; Back to dashboard</a></p>

    <div class="grid">
        <div class="card">
            <h3>Request</h3>
            <p><strong>Time:</strong> {{ $event->occurred_at?->format('Y-m-d H:i:s') }}</p>
            <p><strong>Method:</strong> {{ $event->method }}</p>
            <p><strong>Host:</strong> {{ $event->host }}</p>
            <p><strong>Path:</strong> <code>{{ $event->path }}</code></p>
            <p><strong>IP:</strong> {{ $event->ip_address }}</p>
            <p><strong>Profile:</strong> {{ $event->bait_profile ?? 'none' }}</p>
            <p><strong>Techniques:</strong>
                @foreach ($event->techniques ?? [] as $technique)
                    <span class="pill">{{ $technique }}</span>
                @endforeach
            </p>
        </div>
        <div class="card">
            <h3>Response</h3>
            <p><strong>Status:</strong> {{ $event->response_status }}</p>
            <p><strong>Content-Type:</strong> {{ $event->response_content_type }}</p>
            <p><strong>Duration:</strong> {{ $event->duration_ms }} ms</p>
            <p><strong>Duplicate:</strong> {{ $event->is_duplicate ? 'yes' : 'no' }}</p>
            <p><strong>Session key:</strong> <code>{{ $event->session->session_key }}</code></p>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Payload</h3>
            <pre>{{ $event->raw_body ?: '(empty body)' }}</pre>
        </div>
        <div class="card">
            <h3>Response excerpt</h3>
            <pre>{{ $event->response_excerpt ?: '(no excerpt)' }}</pre>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Headers</h3>
            <pre>{{ json_encode($event->headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
        </div>
        <div class="card">
            <h3>Input</h3>
            <pre>{{ json_encode($event->input, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
        </div>
    </div>

    <div class="card">
        <h3>Artifacts</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>MIME</th>
                    <th>Size</th>
                    <th>Stored</th>
                    <th>Path</th>
                </tr>
            </thead>
            <tbody>
            @forelse ($event->artifacts as $artifact)
                <tr>
                    <td>{{ $artifact->original_name }}</td>
                    <td>{{ $artifact->mime_type }}</td>
                    <td>{{ $artifact->size_bytes }}</td>
                    <td>{{ $artifact->stored ? 'yes' : 'no' }}</td>
                    <td><code>{{ $artifact->storage_path }}</code></td>
                </tr>
            @empty
                <tr><td colspan="5">No artifacts captured.</td></tr>
            @endforelse
            </tbody>
        </table>
    </div>
@endsection
