<?php

use App\Http\Controllers\Api\BookController;
use App\Http\Controllers\Api\Auth\AuthController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

Route::controller(AuthController::class)->group(function () {
    Route::post('login', 'login');
    Route::post('registration', 'registration');
});

Route::middleware('refresh.token')->group(function () {

//Authenticate Routes
    Route::middleware('auth:sanctum')->group(function () {
        Route::controller(AuthController::class)->group(function () {
            Route::post('logout', 'logout');
            Route::get('check-token', 'checkToken');
        });
        Route::get('books', [BookController::class, 'index']);
    });
});
