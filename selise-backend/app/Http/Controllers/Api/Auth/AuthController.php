<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\UserLoginRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use App\Services\AccessTokenService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * @param UserLoginRequest $request
     * @return JsonResponse
     */
    public function login(UserLoginRequest $request): JsonResponse
    {
        if (!Auth::attempt($request->only(['email', 'password'])))
            return response()->json(['message' => 'Unauthorized failed! Email and Password not match.', 'status' => 401]);

        return AccessTokenService::getAccessToken($request->user());
    }

    /**
     * @param UserLoginRequest $request
     * @return JsonResponse
     */
    public function registration(UserLoginRequest $request): JsonResponse
    {
        $user = User::create($request->only(['name', 'email', 'password']));
        return AccessTokenService::getAccessToken($user);
    }

    /**
     * user logout
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Successfully logged out', 'status' => 200]);
    }

    /**
     * @return JsonResponse|void
     */
    public function checkToken(Request $request): JsonResponse
    {
        return $request->user() ? response()->json(['user' => UserResource::make($request->user()), 'status' => 200]) : abort(401);
    }

}
