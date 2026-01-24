<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;


class RoleMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
public function handle(Request $request, Closure $next, ...$roles)
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['message' => 'Unauthenticated'], 401);
    }

    if (!in_array($user->role, $roles, true)) {
        return response()->json([
            'message' => 'Forbidden. You do not have permission.',
            'your_role' => $user->role,
            'allowed_roles' => $roles
        ], 403);
    }

    return $next($request);
}

}
