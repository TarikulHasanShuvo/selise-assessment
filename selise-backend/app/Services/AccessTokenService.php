<?php

namespace App\Services;

use App\Http\Resources\UserResource;
use App\Models\RefreshToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;


class AccessTokenService
{
    /**
     * @param $user
     * @return JsonResponse
     */
    public static function getAccessToken($user)
    {
        $tokenInfo = $user->createToken("API TOKEN", ['*'], now()->addMinute(5));
        $refreshToken = Str::random(30);

        self::makeRefreshToken($user->id, $tokenInfo->accessToken->id, $refreshToken);
        return response()->json([
            'user' => UserResource::make($user),
            'access_token' => $user->createToken("API TOKEN")->plainTextToken,
            'refresh_token' => $refreshToken,
            'status' => 200,
            'token_type' => 'Bearer',
            'expires_at' => $tokenInfo->accessToken->expires_at,

        ]);
    }

    public static function makeRefreshToken($userId, $tokenId, $refreshToken)
    {
        RefreshToken::create([
            'user_id' => $userId,
            'personal_access_token_id' => $tokenId,
            'refresh_token' => $refreshToken
        ]);
    }
}
