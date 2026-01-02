<?php

use App\Http\Controllers\Api\ApiController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\DioceseController;
use App\Http\Controllers\Api\LearnerController;
use App\Http\Controllers\Api\SchoolController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('/test', [App\Http\Controllers\Api\ApiController::class, 'test']);

Route::prefix('v1')->group(function () {

    // Public routes
    Route::post('register', [ApiController::class, 'register']);
    Route::post('login', [ApiController::class, 'login']);
    Route::get('verify/{userId}/{token}', [ApiController::class, 'verify']);
    Route::post('/forgot-password', [ApiController::class, 'forgotPassword']);
    Route::post('/resend', [ApiController::class, 'resend']);

    // Protected routes
    Route::middleware(['auth:api', 'throttle:60,1'])->group(function () {

        // Super Admin
        Route::middleware(['role:super_admin'])->group(function () {
            Route::post('/create/dioceses', [ApiController::class, 'createDioceses']);
            Route::get('/dioceses', [ApiController::class, 'index']);
        });

        // Diocesan Admin
        Route::middleware(['role:diocesan_admin'])->group(function () {
            Route::post('/dioceses/update', [ApiController::class, 'updateDioceses']);
            Route::post('/create/schools', [ApiController::class, 'createSchools']);
            Route::get('/schools', [ApiController::class, 'index']);
        });

        // School Admin
        Route::middleware(['role:school_admin'])->group(function () {
             Route::post('/schools/update', [ApiController::class, 'updateSchool']);
            Route::post('/create/learners', [ApiController::class, 'createLearners']);
            Route::get('/learners', [ApiController::class, 'index']);
        });

    });
});

