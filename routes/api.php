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
    Route::post('/learner/login', [ApiController::class, 'learnerLogin']);

    // Protected routes
    Route::middleware(['auth:api', 'throttle:60,1'])->group(function () {

        Route::post('/change-password', [ApiController::class, 'changePassword']);
        Route::post('/reset-password-default', [ApiController::class, 'resetPasswordToDefault']);
        Route::get('/analytics/learners-enrolment-per-month', [ApiController::class, 'learnersEnrolmentPerMonth']);
        Route::get('/sessions', [ApiController::class, 'getAllSessions']);
        Route::get('/sessions/{id}', [ApiController::class, 'getSessionById']);

        // Super Admin
        Route::middleware(['role:super_admin'])->group(function () {
            Route::get('/dioceses/total', [ApiController::class, 'getTotalDioceses']);
            Route::get('/dioceses/filter', [ApiController::class, 'filterDiocesesByStateAndLga']);
            Route::get('/super-admin/schools/filter', [ApiController::class, 'filterSchoolsByDiocese']);
            Route::get('/super-admin/schools/search', [ApiController::class, 'searchSchoolsByName']);
            Route::get('/super-admin/dioceses/filter-by-date', [ApiController::class, 'filterDiocesesByDate']);
            Route::get('/super-admin/schools/filter-by-date', [ApiController::class, 'filterSchoolsByDate']);
            Route::get('/super-admin/all/schools', [ApiController::class, 'getAllSchoolsSuper']);
            Route::post('/super-admin/create/sessions', [ApiController::class, 'createSession']);

            Route::get('/super-admin/students', [ApiController::class, 'getAllStudents']);
            Route::get('/super-admin/search', [ApiController::class, 'globalSearch']);
            Route::get('/schools/total', [ApiController::class, 'getTotalSchools']);
            Route::get('/learners/total', [ApiController::class, 'getTotalLearners']);
            Route::get('/get/all/dioceses', [ApiController::class, 'getAllDiocesesSuper']);
            Route::get('/get/all/provinces', [ApiController::class, 'getAllProvincesSuper']);
            Route::post('/create/dioceses', [ApiController::class, 'createDioceses']);
            Route::post('/create/province', [ApiController::class, 'createProvince']);
            Route::get('/dioceses', [ApiController::class, 'allDioceses']);
            Route::get('/super-admin/provinces', [ApiController::class, 'getAllProvinces']);
            Route::get('/dioceses/{id}/schools', [ApiController::class, 'getSchoolsByDiocese']);
            Route::delete('/delete/schools/{id}', [ApiController::class, 'deleteSchool']);
            Route::put('/dioceses/{id}', [ApiController::class, 'updateDiocese']);
            Route::delete('/dioceses/{id}', [ApiController::class, 'deleteDiocese']);
            Route::get('/dioceses/{id}/schools/count', [ApiController::class, 'getTotalSchoolsDiocese']);
            Route::get('/dioceses/{id}/details', [ApiController::class, 'getDioceseDetails']);
            Route::get('/get/learners/{id}', [ApiController::class, 'getSingleLearnerSuperAdmin']);
            Route::get('/get/schools/{id}', [ApiController::class, 'getSingleSchoolSuperAdmin']);
            Route::get('/get/provinces/{id}', [ApiController::class, 'getSingleProvinceSuperAdmin']);
            Route::put('/update/dioceses/{id}', [ApiController::class, 'updateDioceseSuperAdmin']);
            Route::put('/diocesan-admins/{dioceseId}/reset-password', [ApiController::class, 'resetDiocesanAdminPassword']);
            Route::put('/update/session/{id}', [ApiController::class, 'updateSession']);
             Route::put('/update/province/{id}', [ApiController::class, 'updateProvince']);
        });

        // Diocesan Admin
        Route::middleware(['role:diocesan_admin'])->group(function () {
            Route::post('/dioceses/update', [ApiController::class, 'updateDioceses']);
            Route::post('/create/schools', [ApiController::class, 'createSchools']);
            Route::get('/user/diocese-id', [ApiController::class, 'getAuthenticatedUserDioceseId']);
            Route::post('/create/education-secretary', [ApiController::class, 'createEducationSecretary']);
            Route::get('/diocese/schools/total', [ApiController::class, 'getTotalSchoolsForDiocesanAdmin']);
            Route::get('/diocese/schools/learners', [ApiController::class, 'getSchoolsAndLearnersForDiocese']);
            Route::get('/diocesan-admin/schools/search', [ApiController::class, 'searchSchoolsForDiocesanAdmin']);
            Route::get('/diocesan-admin/schools/filter', [ApiController::class, 'filterSchoolsByStateAndLga']);
            Route::get('/diocesan-admin/schools/filter-by-date', [ApiController::class, 'filterSchoolsByDateForDiocesanAdmin']);
            Route::get('/diocesan-admin/students', [ApiController::class, 'getStudentsUnderDiocese']);
            Route::get('/diocesan-admin/schools', [ApiController::class, 'getSchoolsUnderDiocese']);
            Route::get('/diocese/schools/{schoolId}', [ApiController::class, 'getSchoolInMyDiocese']);
            Route::post('/schools/{schoolId}/update', [ApiController::class, 'updateSchoolByDiocese']);
            Route::delete('/schools/{schoolId}/delete', [ApiController::class, 'deleteSchoolByDiocese']);
            Route::get('/schools', [ApiController::class, 'index']);
            Route::get('/dioceses/{id}', [ApiController::class, 'getSingleDiocese']);
            Route::put('/schools/{schoolId}/reset-password', [ApiController::class, 'resetSchoolAdminPassword']);
            Route::put('/education-secretary/{id}/update', [ApiController::class, 'updateEducationSecretary']);

            Route::get('/education-secretary/{id}', [ApiController::class, 'getEducationSecretaryById']);

        });

        // School Admin.
        Route::middleware(['role:school_admin'])->group(function () {
            Route::get('/user/school-admin', [ApiController::class, 'getAuthenticatedSchoolAdmin']);
            Route::post('/schools/update', [ApiController::class, 'updateSchool']);
            Route::get('/school-admin/dashboard', [ApiController::class, 'getSchoolAdminDashboard']);
            Route::post('/create/learners', [ApiController::class, 'createLearners']);
            Route::post('/create/terms', [ApiController::class, 'createTerm']);
            Route::get('/school/learners', [ApiController::class, 'getLearnersForSchool']);
            Route::get('/school/terms', [ApiController::class, 'getTermsForSchool']);
            Route::get('/school-admin/students', [ApiController::class, 'filterStudentsForSchool']);
            Route::get('/school-admin/students/lga-filter', [ApiController::class, 'filterStudentsForSchoolLga']);
            Route::get('/school-admin/students/date-filter', [ApiController::class, 'filterStudentsForSchoolDate']);
            Route::get('/learners/class-filter', [ApiController::class, 'filterLearnersByClass']);
            Route::get('/school/learners/{learnerId}', [ApiController::class, 'showLearner']);
            Route::post('/school/learners/{learnerId}/update', [ApiController::class, 'updateLearner']);
            Route::delete('/school/learners/{learnerId}/delete', [ApiController::class, 'deleteLearner']);
            Route::post('/school/learners/{learnerId}/reset-password', [ApiController::class, 'resetLearnerPassword']);
            Route::get('/learners/{id}', [ApiController::class, 'getSingleLearner']);
            Route::put('/update/term/{id}', [ApiController::class, 'updateTerm']);
            Route::get('/terms/{id}', [ApiController::class, 'getTermById']);

        });

        // Learners
        Route::middleware(['role:learner'])->group(function () {
            Route::get('/user/learner-id', [ApiController::class, 'getAuthenticatedLearnerId']);
            Route::get('/learner/profile', [ApiController::class, 'getAuthenticatedLearnerProfile']);
            Route::get('/learner/profile/dashboard', [ApiController::class, 'getLearnerProfile']);
            Route::post('/learner/logout', [ApiController::class, 'learnerLogout']);
        });

    });
});

