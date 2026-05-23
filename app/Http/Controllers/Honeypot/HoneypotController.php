<?php

namespace App\Http\Controllers\Honeypot;

use App\Http\Controllers\Controller;
use App\Services\Honeypot\DeceptionResponder;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class HoneypotController extends Controller
{
    public function __construct(
        private readonly DeceptionResponder $deceptionResponder,
    ) {}

    public function __invoke(Request $request): Response
    {
        return $this->deceptionResponder->respond($request);
    }
}
