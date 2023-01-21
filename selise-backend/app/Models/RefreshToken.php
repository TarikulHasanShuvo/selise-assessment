<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\PersonalAccessToken;

class RefreshToken extends Model
{
    use HasFactory;

    protected $fillable = ['user_id','personal_access_token_id', 'refresh_token'];


    public function user()
    {
        return $this->belongsToMany(User::class);
    }

    public function personalAccessTokens()
    {
        return $this->belongsToMany(PersonalAccessToken::class);
    }
}
