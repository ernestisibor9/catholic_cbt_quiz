<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\SchoolAccountMail;
use App\Models\Diocese;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use App\Mail\DioceseAccountMail;
use App\Mail\DioceseVerifyMail;
use App\Models\School;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Validation\Rule;

/**
 * @OA\Info(
 *     version="1.0.0",
 *     title="CATHOLIC QUIZ API | Stable Shield Solutions",
 *     description="Backend for the Catholic Quiz project. Powered by Stable Shield Solutions"
 * )
 *
 * @OA\SecurityScheme(
 *     securityScheme="bearerAuth",
 *     type="http",
 *     scheme="bearer",
 *     bearerFormat="JWT",
 *     description="Enter token as: Bearer {JWT token}"
 * )
 */




class ApiController extends Controller
{
    //
    /**
     * @OA\Get(
     *     path="/api/test",
     *     summary="Testing Swagger",
     *     @OA\Response(response=200, description="Success")
     * )
     */
    public function test()
    {
        return "Swagger works!";
    }



    /**
     * @OA\Post(
     *     path="/api/v1/login",
     *     summary="User login",
     *     description="Authenticate user and return JWT token",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email","password"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com"),
     *             @OA\Property(property="password", type="string", format="password", example="secret123")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Login successful"),
     *             @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600),
     *             @OA\Property(
     *                 property="user",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="user@example.com"),
     *                 @OA\Property(property="role", type="string", example="admin")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid email or password")
     *         )
     *     )
     * )
     */
    public function login(Request $request)
    {
        // 1. Validate input
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        // 2. Attempt login
        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid email or password'
            ], 401);
        }

        // 3. Get user details
        $user = auth('api')->user();

        // 4. Response
        return response()->json([
            'status' => 'success',
            'message' => 'Login successful',
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60, // in seconds
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
            ]
        ]);
    }




    /**
     * @OA\Post(
     *     path="/api/v1/create/dioceses",
     *     summary="Create a new Diocese",
     *     description="Create a diocese and assign a diocesan admin. Requires JWT authentication.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={
     *                 "name",
     *                 "province",
     *                 "state",
     *                 "lga",
     *                 "address",
     *                 "contact_number",
     *                 "email"
     *             },
     *             @OA\Property(property="name", type="string", example="Catholic Diocese of Abuja"),
     *             @OA\Property(property="province", type="string", example="Abuja Province"),
     *             @OA\Property(property="state", type="string", example="FCT"),
     *             @OA\Property(property="lga", type="string", example="Abuja Municipal"),
     *             @OA\Property(property="address", type="string", example="123 Catholic Road, Abuja"),
     *             @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *             @OA\Property(property="email", type="string", format="email", example="diocese@church.org")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Diocese created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Diocese created and email sent to Diocese Admin"),
     *             @OA\Property(
     *                 property="diocese",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="CATHOLIC DIOCESE OF ABUJA"),
     *                 @OA\Property(property="province", type="string", example="Abuja Province"),
     *                 @OA\Property(property="state", type="string", example="FCT"),
     *                 @OA\Property(property="lga", type="string", example="Abuja Municipal"),
     *                 @OA\Property(property="address", type="string", example="123 Catholic Road, Abuja"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678")
     *             ),
     *             @OA\Property(
     *                 property="diocesan_admin",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=5),
     *                 @OA\Property(property="email", type="string", example="diocese@church.org"),
     *                 @OA\Property(property="role", type="string", example="diocesan_admin")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized (missing or invalid token)"
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */

    public function createDioceses(Request $request)
    {
        // 1. Validate input
        $validated = $request->validate([
            'name' => 'required|string',
            'province' => 'required|string',
            'state' => 'required|string',
            'lga' => 'required|string',
            'address' => 'required|string',
            'contact_number' => 'required|string',
            'email' => 'required|email|unique:users,email'
        ]);

        // 2. Create Diocese
        $diocese = Diocese::create([
            'name' => strtoupper($validated['name']),
            'province' => $validated['province'],
            'state' => $validated['state'],
            'lga' => $validated['lga'],
            'address' => $validated['address'],
            'contact_number' => $validated['contact_number'],
        ]);

        // 3. Default password
        $defaultPassword = '123456';

        // 4. Create Diocesan Admin User
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($defaultPassword),
            'role' => 'diocesan_admin',
            'diocese_id' => $diocese->id,
        ]);

        // 5. Email verification
        $token = Str::random(8);
        Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

        $verificationLink = rtrim(config('app.frontend_url'), '/') .
            "/verify/{$user->id}/{$token}";

        // 6. Prepare mail data
        $mailData = [
            'name' => $user->name,
            'email' => $user->email,
            'password' => $defaultPassword,
            'link' => $verificationLink,
        ];

        // 7. Send mail
        try {
            Log::info('Sending diocese account mail to: ' . $user->email);
            Mail::to($user->email)->send(new DioceseAccountMail($mailData));
            Log::info('Mail sent successfully');
        } catch (\Exception $e) {
            Log::error('Diocese email failed: ' . $e->getMessage());
        }

        // 8. Response
        return response()->json([
            'status' => 'success',
            'message' => 'Diocese created and email sent to Diocese Admin',
            'diocese' => $diocese,
            'diocesan_admin' => [
                'id' => $user->id,
                'email' => $user->email,
                'role' => $user->role
            ]
        ], 201);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/verify/{userId}/{token}",
     *     summary="Verify user email",
     *     description="Verify a user's email by clicking the link sent to their email",
     *     tags={"Authentication"},
     *
     *     @OA\Parameter(
     *         name="userId",
     *         in="path",
     *         description="ID of the user to verify",
     *         required=true,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         description="Email verification token sent to the user",
     *         required=true,
     *         @OA\Schema(type="string", example="A1B2C3D4")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Email verified successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Email verified successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=400,
     *         description="Invalid or expired verification token",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid or expired verification token")
     *         )
     *     )
     * )
     */

    public function verify($userId, $token)
    {
        $cacheKey = "email_verification_{$userId}";
        $cachedToken = Cache::get($cacheKey);

        if (!$cachedToken || $cachedToken !== $token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid or expired verification token'
            ], 400);
        }

        $user = User::findOrFail($userId);

        if ($user->email_verified_at) {
            return response()->json([
                'status' => 'success',
                'message' => 'Email already verified'
            ]);
        }

        $user->update(['email_verified_at' => now()]);

        Cache::forget($cacheKey);

        return response()->json([
            'status' => 'success',
            'message' => 'Email verified successfully'
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/resend",
     *     summary="Resend email verification token",
     *     description="Resend the verification email to a user who has not yet verified their email.",
     *     tags={"Authentication"},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email", example="user@example.com")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Verification email resent successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Verification email resent")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=400,
     *         description="Email already verified",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Email already verified")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The email field is required."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={"email": {"The selected email is invalid."}}
     *             )
     *         )
     *     )
     * )
     */

    public function resend(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $user = User::where('email', $request->email)->first();

        if ($user->email_verified_at) {
            return response()->json([
                'status' => 'error',
                'message' => 'Email already verified'
            ], 400);
        }

        $token = Str::random(8);
        Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

        $verificationLink = rtrim(config('app.frontend_url'), '/') .
            "/verify/{$user->id}/{$token}";

        Mail::to($user->email)->send(
            new DioceseVerifyMail($user, $token, $verificationLink)
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Verification email resent'
        ]);
    }

    /**
     * @OA\Post(
     *     path="/api/v1/dioceses/update",
     *     operationId="updateDioceseProfile",
     *     summary="Update Diocese Profile",
     *     description="Partially update the profile of the diocese linked to the authenticated user. Fields are optional. Requires JWT authentication.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 type="object",
     *                 @OA\Property(
     *                     property="province",
     *                     type="string",
     *                     example="Lagos Province 2"
     *                 ),
     *                 @OA\Property(
     *                     property="state",
     *                     type="string",
     *                     example="Lagos"
     *                 ),
     *                 @OA\Property(
     *                     property="lga",
     *                     type="string",
     *                     example="Alimosho"
     *                 ),
     *                 @OA\Property(
     *                     property="address",
     *                     type="string",
     *                     example="12 Ipaja road, Lagos"
     *                 ),
     *                 @OA\Property(
     *                     property="contact_number",
     *                     type="string",
     *                     example="+2348012345678"
     *                 ),
     *                 @OA\Property(
     *                     property="education_secretary",
     *                     type="string",
     *                     example="John Doe"
     *                 ),
     *                 @OA\Property(
     *                     property="latest_news",
     *                     type="string",
     *                     example="Diocese event update"
     *                 ),
     *                 @OA\Property(
     *                     property="logo",
     *                     type="string",
     *                     format="binary",
     *                     description="Diocese logo image (png, jpg, jpeg)"
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Diocese profile updated successfully"
     *             ),
     *             @OA\Property(
     *                 property="diocese",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Alimosho"),
     *                 @OA\Property(property="address", type="string", example="12 Ipaja road, Lagos"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(property="education_secretary", type="string", example="John Doe"),
     *                 @OA\Property(property="latest_news", type="string", example="Diocese event update"),
     *                 @OA\Property(
     *                     property="logo",
     *                     type="string",
     *                     example="uploads/dioceses/170000123_abcd1234.png"
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="No diocese linked to this account",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="No diocese linked to this account"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="The logo must be an image."
     *             ),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 @OA\Property(
     *                     property="logo",
     *                     type="array",
     *                     @OA\Items(type="string", example="The logo must be a file of type: png, jpg, jpeg.")
     *                 )
     *             )
     *         )
     *     )
     * )
     */


    public function updateDioceses(Request $request)
    {
        $diocese = auth()->user()->diocese;

        if (!$diocese) {
            return response()->json([
                'message' => 'No diocese linked to this account'
            ], 403);
        }

        $validated = $request->validate([
            'province' => 'sometimes|string',
            'state' => 'sometimes|string',
            'lga' => 'sometimes|string',
            'address' => 'sometimes|string',
            'contact_number' => 'sometimes|string',
            'education_secretary' => 'nullable|string',
            'latest_news' => 'nullable|string',
            'logo' => 'nullable|image|mimes:png,jpg,jpeg|max:2048',
        ]);

        // Handle logo upload
        if ($request->hasFile('logo')) {

            // Delete old logo if exists
            if ($diocese->logo && File::exists(public_path($diocese->logo))) {
                File::delete(public_path($diocese->logo));
            }

            $logo = $request->file('logo');

            // Generate unique filename
            $fileName = time() . '_' . Str::random(8) . '.' . $logo->getClientOriginalExtension();

            // Move file to public/uploads/dioceses
            $logo->move(public_path('uploads/dioceses'), $fileName);

            // Save path in DB (relative to public/)
            $validated['logo'] = 'uploads/dioceses/' . $fileName;
        }

        $diocese->update($validated);

        return response()->json([
            'message' => 'Diocese profile updated successfully',
            'diocese' => $diocese
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/create/schools",
     *     summary="Create a School",
     *     description="Create a new school under the logged-in diocesan admin's diocese and assign a school admin. Requires JWT authentication.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","province","state","lga"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="St. Joseph Catholic School"
     *             ),
     *             @OA\Property(
     *                 property="email",
     *                 type="string",
     *                 format="email",
     *                 example="stjoseph@school.com"
     *             ),
     *             @OA\Property(
     *                 property="province",
     *                 type="string",
     *                 example="Lagos Province"
     *             ),
     *             @OA\Property(
     *                 property="state",
     *                 type="string",
     *                 example="Lagos"
     *             ),
     *             @OA\Property(
     *                 property="lga",
     *                 type="string",
     *                 example="Ikeja"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="School created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="School created and email sent to School Admin"
     *             ),
     *             @OA\Property(
     *                 property="school",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                 @OA\Property(property="email", type="string", example="stjoseph@school.com"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Ikeja")
     *             ),
     *             @OA\Property(
     *                 property="school_admin",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=10),
     *                 @OA\Property(property="email", type="string", example="stjoseph@school.com"),
     *                 @OA\Property(property="role", type="string", example="school_admin")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="User does not belong to any diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Logged-in user does not belong to any diocese")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The name has already been taken."),
     *             @OA\Property(property="errors", type="object",
     *                 @OA\Property(property="name", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="email", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="province", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="state", type="array", @OA\Items(type="string")),
     *                 @OA\Property(property="lga", type="array", @OA\Items(type="string"))
     *             )
     *         )
     *     )
     * )
     */

    public function createSchools(Request $request)
    {
        // 1. Validate input
        $validated = $request->validate([
            'name' => 'required|string|unique:schools',
            'email' => 'required|email|unique:users,email',
            'province' => 'required|string',
            'state' => 'required|string',
            'lga' => 'required|string',
        ]);

        // 2. Get the Diocese of the logged-in diocesan admin
        $diocese = auth()->user()->diocese;
        if (!$diocese) {
            return response()->json([
                'status' => 'error',
                'message' => 'Logged-in user does not belong to any diocese'
            ], 403);
        }

        // 3. Create School
        $school = School::create([
            'diocese_id' => $diocese->id,
            'name' => strtoupper($validated['name']),
            'email' => $validated['email'],
            'province' => $validated['province'],
            'state' => $validated['state'],
            'lga' => $validated['lga'],
        ]);

        // 4. Default password
        $defaultPassword = '123456';

        // 5. Create School User Account
        $user = User::create([
            'name' => $school->name,
            'email' => $school->email,
            'password' => Hash::make($defaultPassword),
            'role' => 'school_admin',
            'school_id' => $school->id,
        ]);

        // 6. Generate email verification token
        $token = Str::random(8);
        Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

        $verificationLink = rtrim(config('app.frontend_url'), '/') . "/verify/{$user->id}/{$token}";

        // 7. Send school account mail
        try {
            Mail::to($user->email)->send(new SchoolAccountMail([
                'name' => $user->name,
                'email' => $user->email,
                'password' => $defaultPassword,
                'link' => $verificationLink
            ]));
            Log::info('School account mail sent to ' . $user->email);
        } catch (\Exception $e) {
            Log::error('School email failed: ' . $e->getMessage());
        }

        // 8. Return response
        return response()->json([
            'status' => 'success',
            'message' => 'School created and email sent to School Admin',
            'school' => $school,
            'school_admin' => [
                'id' => $user->id,
                'email' => $user->email,
                'role' => $user->role
            ]
        ], 201);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/schools/update",
     *     operationId="updateSchoolProfile",
     *     summary="Update School Profile",
     *     description="Partially update the school profile linked to the authenticated school admin. All fields are optional. Requires JWT authentication.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 type="object",
     *
     *                 @OA\Property(property="name", type="string", example="ST MARYS SECONDARY SCHOOL"),
     *                 @OA\Property(property="email", type="string", format="email", example="stmaryschool@gmail.com"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Alimosho"),
     *
     *                 @OA\Property(property="latitude", type="number", format="float", example=6.5244),
     *                 @OA\Property(property="longitude", type="number", format="float", example=3.3792),
     *
     *                 @OA\Property(property="address", type="string", example="12 Ipaja road, Lagos"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *
     *                 @OA\Property(
     *                     property="class_categories[]",
     *                     type="array",
     *                     @OA\Items(type="string"),
     *                     example={"Primary","Junior Secondary","Senior Secondary"}
     *                 ),
     *
     *                 @OA\Property(
     *                     property="subjects_offered[]",
     *                     type="array",
     *                     @OA\Items(type="string"),
     *                     example={"Mathematics","English","Physics","Chemistry"}
     *                 ),
     *
     *                 @OA\Property(property="latest_news", type="string", example="School resumes fully on Monday"),
     *
     *                 @OA\Property(
     *                     property="logo",
     *                     type="string",
     *                     format="binary",
     *                     description="School logo image (png, jpg, jpeg)"
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="School profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School profile updated successfully"),
     *             @OA\Property(property="school", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="No school linked to this account",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="No school linked to this account")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The email has already been taken."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */


    public function updateSchool(Request $request)
    {
        $school = auth()->user()->school;

        if (!$school) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        // Validate arrays properly
        $validated = $request->validate([
            'name' => ['sometimes', 'string', Rule::unique('schools', 'name')->ignore($school->id)],
            'email' => ['sometimes', 'email', Rule::unique('schools', 'email')->ignore($school->id)],
            'province' => 'sometimes|string',
            'state' => 'sometimes|string',
            'lga' => 'sometimes|string',
            'latitude' => 'nullable|numeric',
            'longitude' => 'nullable|numeric',
            'address' => 'nullable|string',
            'contact_number' => 'nullable|string',
            'class_categories' => 'nullable|array',
            'class_categories.*' => 'string',
            'subjects_offered' => 'nullable|array',
            'subjects_offered.*' => 'string',
            'latest_news' => 'nullable|string',
            'logo' => 'nullable|image|mimes:png,jpg,jpeg|max:2048',
        ]);

        // Handle logo
        if ($request->hasFile('logo')) {
            if ($school->logo && File::exists(public_path($school->logo))) {
                File::delete(public_path($school->logo));
            }
            $logo = $request->file('logo');
            $fileName = time() . '_' . Str::random(8) . '.' . $logo->getClientOriginalExtension();
            $logo->move(public_path('uploads/school'), $fileName);
            $validated['logo'] = 'uploads/school/' . $fileName;
        }

        $school->update($validated);
        $school->refresh(); // ensures casted arrays show correctly

        return response()->json([
            'message' => 'School profile updated successfully',
            'school' => $school
        ]);
    }


    /**
     * Create a new learner and user account
     *
     * @OA\Post(
     *     path="/api/v1/create/learners",
     *     operationId="createLearners",
     *     summary="Register a new learner",
     *     description="Allows a school admin to create a learner and automatically generates a learner user account using the provided email.",
     *     tags={"Learner"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"surname","first_name","dob","present_class","email"},
     *
     *                 @OA\Property(property="surname", type="string", example="Isibor"),
     *                 @OA\Property(property="first_name", type="string", example="Ernest"),
     *                 @OA\Property(property="middle_name", type="string", example=""),
     *                 @OA\Property(property="dob", type="string", format="date", example="2012-05-14"),
     *                 @OA\Property(property="religion", type="string", example="Christianity"),
     *                 @OA\Property(property="residential_address", type="string", example="12 Ipaja Road, Lagos"),
     *                 @OA\Property(property="state_of_origin", type="string", example="Edo"),
     *                 @OA\Property(property="lga_of_origin", type="string", example="Oredo"),
     *                 @OA\Property(property="previous_class", type="string", example="Primary 5"),
     *                 @OA\Property(property="present_class", type="string", example="Primary 6"),
     *
     *                 @OA\Property(
     *                     property="email",
     *                     type="string",
     *                     format="email",
     *                     example="ernestisibor@gmail.com",
     *                     description="Learner email provided by the school"
     *                 ),
     *
     *                 @OA\Property(
     *                     property="nin",
     *                     type="string",
     *                     example="12345678901",
     *                     description="Optional National Identification Number"
     *                 ),
     *
     *                 @OA\Property(property="parent_name", type="string", example="Mr Isibor"),
     *                 @OA\Property(property="parent_relationship", type="string", example="Father"),
     *                 @OA\Property(property="parent_phone", type="string", example="08012345678"),
     *
     *                 @OA\Property(
     *                     property="photo",
     *                     type="string",
     *                     format="binary",
     *                     description="Learner passport photograph"
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Learner created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner created successfully"),
     *             @OA\Property(property="learner", type="object"),
     *             @OA\Property(property="user", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="School not linked to account"
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error"
     *     )
     * )
     */


    public function createLearners(Request $request)
    {
        $school = auth()->user()->school;

        if (!$school) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        $validated = $request->validate([
            'surname' => 'required|string|max:255',
            'first_name' => 'required|string|max:255',
            'middle_name' => 'nullable|string|max:255',
            'dob' => 'required|date',
            'religion' => 'nullable|string|max:100',
            'residential_address' => 'nullable|string|max:255',
            'state_of_origin' => 'nullable|string|max:100',
            'lga_of_origin' => 'nullable|string|max:100',
            'previous_class' => 'nullable|string|max:50',
            'present_class' => 'required|string|max:50',

            // ✅ Email entered by school
            'email' => 'required|email|unique:users,email',

            // Optional NIN (no longer used for email)
            'nin' => 'nullable|string|max:20|unique:learners,nin',

            'parent_name' => 'nullable|string|max:255',
            'parent_relationship' => 'nullable|string|max:100',
            'parent_phone' => 'nullable|string|max:20',
            'photo' => 'nullable|image|mimes:jpg,jpeg,png|max:2048',
        ]);

        // Handle photo upload
        if ($request->hasFile('photo')) {
            $photo = $request->file('photo');
            $fileName = time() . '_' . Str::random(8) . '.' . $photo->getClientOriginalExtension();
            $photo->move(public_path('uploads/learners'), $fileName);
            $validated['photo'] = 'uploads/learners/' . $fileName;
        }

        // Create learner record
        $learner = $school->learners()->create($validated);

        // Create learner login account
        $user = User::create([
            'name' => trim(
                $validated['first_name'] . ' ' .
                ($validated['middle_name'] ?? '') . ' ' .
                $validated['surname']
            ),
            'email' => $validated['email'], // ✅ use entered email
            'password' => Hash::make('123456'), // default password
            'role' => 'learner',
            'school_id' => $school->id,
            'learner_id' => $learner->id,
        ]);

        return response()->json([
            'message' => 'Learner created successfully',
            'learner' => $learner,
            'user' => $user
        ], 201);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/dioceses",
     *     operationId="AllDioceses",
     *     summary="Get all dioceses",
     *     description="Retrieve all dioceses nationwide with their associated schools. Accessible only to Super Admin users.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="Lagos Archdiocese"),
     *                     @OA\Property(property="created_at", type="string", format="date-time", example="2024-01-10T08:30:00Z"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time", example="2024-01-10T08:30:00Z"),
     *
     *                     @OA\Property(
     *                         property="schools",
     *                         type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=15),
     *                             @OA\Property(property="name", type="string", example="St. Mary's Secondary School"),
     *                             @OA\Property(property="email", type="string", format="email", example="stmary@gmail.com"),
     *                             @OA\Property(property="state", type="string", example="Lagos"),
     *                             @OA\Property(property="lga", type="string", example="Ikeja"),
     *                             @OA\Property(property="created_at", type="string", format="date-time", example="2024-02-01T10:00:00Z"),
     *                             @OA\Property(property="updated_at", type="string", format="date-time", example="2024-02-01T10:00:00Z")
     *                         )
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthenticated.")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Unauthorized access",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="You are not authorized to perform this action.")
     *         )
     *     )
     * )
     */

    public function allDioceses()
    {
        // Super admin sees ALL dioceses nationwide
        $dioceses = Diocese::with('schools')->get();

        return response()->json([
            'status' => true,
            'data' => $dioceses
        ]);
    }



    /**
     * @OA\Put(
     *     path="/api/v1/dioceses/{id}",
     *     operationId="updateDiocese",
     *     summary="Update a Diocese",
     *     description="Partially update a diocese by its ID. All fields are optional. Requires JWT authentication.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID of the diocese to update",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 type="object",
     *                 @OA\Property(property="name", type="string", example="Lagos Archdiocese"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Ikeja"),
     *                 @OA\Property(property="address", type="string", example="12 Church Street, Lagos"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(property="education_secretary", type="string", example="Mr. John Doe")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Diocese updated successfully"),
     *             @OA\Property(
     *                 property="diocese",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="Lagos Archdiocese"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Ikeja"),
     *                 @OA\Property(property="address", type="string", example="12 Church Street, Lagos"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(property="education_secretary", type="string", example="Mr. John Doe"),
     *                 @OA\Property(property="created_at", type="string", format="date-time", example="2024-01-10T08:30:00Z"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time", example="2024-01-10T09:30:00Z")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Diocese not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Diocese not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The name has already been taken."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */

    public function updateDiocese(Request $request, $id)
    {
        $diocese = Diocese::find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        $validated = $request->validate([
            'name' => 'sometimes|string|unique:dioceses,name,' . $diocese->id,
            'province' => 'sometimes|string',
            'state' => 'sometimes|string',
            'lga' => 'sometimes|string',
            'address' => 'nullable|string',
            'contact_number' => 'nullable|string',
            'education_secretary' => 'sometimes|string',
        ]);

        $diocese->update($validated);

        return response()->json([
            'message' => 'Diocese updated successfully',
            'diocese' => $diocese
        ]);
    }


    /**
     * @OA\Delete(
     *     path="/api/v1/dioceses/{id}",
     *     operationId="deleteDiocese",
     *     summary="Delete a Diocese",
     *     description="Deletes a diocese by its ID. Requires JWT authentication.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID of the diocese to delete",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Diocese deleted successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Diocese not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Diocese not found")
     *         )
     *     )
     * )
     */

    public function deleteDiocese($id)
    {
        $diocese = Diocese::find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        DB::transaction(function () use ($diocese) {

            // 1️⃣ Delete all users attached directly to this diocese
            User::where('diocese_id', $diocese->id)->delete();

            // 2️⃣ Delete schools and their users (if applicable)
            foreach ($diocese->schools as $school) {
                User::where('school_id', $school->id)->delete();
                $school->delete();
            }

            // 3️⃣ Finally delete the diocese
            $diocese->delete();
        });

        return response()->json([
            'message' => 'Diocese and related users deleted successfully'
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/get/all/dioceses",
     *     operationId="getAllDioceses",
     *     summary="Get all dioceses with schools and learners",
     *     description="Fetches all dioceses nationwide including their schools and learners. Accessible by Super Admin.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="List of dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Ikeja"),
     *
     *                     @OA\Property(
     *                         property="schools",
     *                         type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=10),
     *                             @OA\Property(property="name", type="string", example="St. Mary's Secondary School"),
     *
     *                             @OA\Property(
     *                                 property="learners",
     *                                 type="array",
     *                                 @OA\Items(
     *                                     type="object",
     *                                     @OA\Property(property="id", type="integer", example=100),
     *                                     @OA\Property(property="first_name", type="string", example="John"),
     *                                     @OA\Property(property="last_name", type="string", example="Doe")
     *                                 )
     *                             )
     *                         )
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */

    public function getAllDioceses()
    {
        $dioceses = Diocese::with('schools.learners')->get();

        return response()->json([
            'data' => $dioceses
        ]);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/{dioceseId}/schools",
     *     operationId="getSchoolsByDiocese",
     *     summary="Get schools by diocese",
     *     description="Fetches all schools belonging to a specific diocese, including their learners.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="dioceseId",
     *         in="path",
     *         required=true,
     *         description="ID of the diocese",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=10),
     *                     @OA\Property(property="name", type="string", example="St Mary's Secondary School"),
     *                     @OA\Property(property="email", type="string", example="stmaryschool@gmail.com"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *
     *                     @OA\Property(
     *                         property="learners",
     *                         type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=101),
     *                             @OA\Property(property="first_name", type="string", example="John"),
     *                             @OA\Property(property="last_name", type="string", example="Doe"),
     *                             @OA\Property(property="class", type="string", example="SS 2")
     *                         )
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Diocese not found"
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     )
     * )
     */


    public function getSchoolsByDiocese($dioceseId)
    {
        $schools = School::where('diocese_id', $dioceseId)
            ->with('learners')
            ->get();

        return response()->json([
            'data' => $schools
        ]);
    }


    /**
 * @OA\Delete(
 *     path="/api/v1/delete/schools/{id}",
 *     operationId="deleteSchoolAdmin",
 *     summary="Delete a school",
 *     description="Deletes a school and all related learners and user accounts. This action is irreversible.",
 *     tags={"Api"},
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Parameter(
 *         name="id",
 *         in="path",
 *         required=true,
 *         description="ID of the school to delete",
 *         @OA\Schema(type="integer", example=5)
 *     ),
 *
 *     @OA\Response(
 *         response=200,
 *         description="School and learners deleted successfully",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="School and learners deleted successfully"
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=404,
 *         description="School not found",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(
 *                 property="message",
 *                 type="string",
 *                 example="School not found"
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized"
 *     ),
 *
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden"
 *     )
 * )
 */

    public function deleteSchool($id)
{
    $school = School::find($id);

    if (!$school) {
        return response()->json(['message' => 'School not found'], 404);
    }

    DB::transaction(function () use ($school) {

        // Delete learners' users
        User::whereIn(
            'learner_id',
            $school->learners->pluck('id')
        )->delete();

        // Delete learners
        $school->learners()->delete();

        // Delete school admin user
        User::where('school_id', $school->id)->delete();

        // Delete school
        $school->delete();
    });

    return response()->json([
        'message' => 'School and learners deleted successfully'
    ]);
}



}
