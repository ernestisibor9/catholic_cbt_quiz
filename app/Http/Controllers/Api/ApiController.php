<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Mail\EducationSecretaryMail;
use App\Mail\SchoolAccountMail;
use App\Models\Diocese;
use App\Models\Province;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use App\Mail\DioceseAccountMail;
use App\Mail\DioceseVerifyMail;
use App\Models\EducationSecretary;
use App\Models\Learner;
use App\Models\School;
use App\Models\Session;
use App\Models\Term;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;




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
     *             @OA\Property(property="email", type="string", format="email", example="info@catheducsn.org.ng"),
     *             @OA\Property(property="password", type="string", format="password", example="PassWord123!")
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
     *     tags={"Api"},
     *     summary="Create a new diocese",
     *     description="Creates a diocese along with its diocesan admin. Sends verification email to admin.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","province_id","state","lga","address","contact_number","email"},
     *             @OA\Property(property="name", type="string", example="Ikeja Diocese", description="Unique diocese name"),
     *             @OA\Property(property="province_id", type="integer", example=1, description="ID of the province this diocese belongs to"),
     *             @OA\Property(property="state", type="string", example="Lagos", description="State where the diocese is located"),
     *             @OA\Property(property="lga", type="string", example="Ikeja", description="Local government area"),
     *             @OA\Property(property="address", type="string", example="123 Church St", description="Physical address of the diocese"),
     *             @OA\Property(property="contact_number", type="string", example="+2348012345678", description="Unique contact number for the diocese"),
     *             @OA\Property(property="email", type="string", format="email", example="admin@ikejadiocese.com", description="Email for diocesan admin account")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Diocese created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Diocese created successfully"),
     *             @OA\Property(
     *                 property="diocese",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="IKEJA DIOCESE"),
     *                 @OA\Property(property="province_id", type="integer", example=1),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Ikeja"),
     *                 @OA\Property(property="address", type="string", example="123 Church St"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             ),
     *             @OA\Property(
     *                 property="diocesan_admin",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=10),
     *                 @OA\Property(property="email", type="string", example="admin@ikejadiocese.com"),
     *                 @OA\Property(property="role", type="string", example="diocesan_admin")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error or duplicate diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "name": {"A diocese with this name already exists"},
     *                     "email": {"The email has already been taken."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */

    // public function createDioceses(Request $request)
    // {
    //     // 1. Validate input
    //     $validated = $request->validate([
    //         'name' => 'required|string',
    //         'province' => 'required|string',
    //         'state' => 'required|string',
    //         'lga' => 'required|string',
    //         'address' => 'required|string',
    //         'contact_number' => 'required|string',
    //         'email' => 'required|email|unique:users,email'
    //     ]);

    //     // 2. Create Diocese
    //     $diocese = Diocese::create([
    //         'name' => strtoupper($validated['name']),
    //         'province' => $validated['province'],
    //         'state' => $validated['state'],
    //         'lga' => $validated['lga'],
    //         'address' => $validated['address'],
    //         'contact_number' => $validated['contact_number'],
    //     ]);

    //     // 3. Default password
    //     $defaultPassword = '123456';

    //     // 4. Create Diocesan Admin User
    //     $user = User::create([
    //         'name' => $validated['name'],
    //         'email' => $validated['email'],
    //         'password' => Hash::make($defaultPassword),
    //         'role' => 'diocesan_admin',
    //         'diocese_id' => $diocese->id,
    //     ]);

    //     // 5. Email verification
    //     $token = Str::random(8);
    //     Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

    //     $verificationLink = rtrim(config('app.frontend_url'), '/') .
    //         "/verify/{$user->id}/{$token}";

    //     // 6. Prepare mail data
    //     $mailData = [
    //         'name' => $user->name,
    //         'email' => $user->email,
    //         'password' => $defaultPassword,
    //         'link' => $verificationLink,
    //     ];

    //     // 7. Send mail
    //     try {
    //         Log::info('Sending diocese account mail to: ' . $user->email);
    //         Mail::to($user->email)->send(new DioceseAccountMail($mailData));
    //         Log::info('Mail sent successfully');
    //     } catch (\Exception $e) {
    //         Log::error('Diocese email failed: ' . $e->getMessage());
    //     }

    //     // 8. Response
    //     return response()->json([
    //         'status' => 'success',
    //         'message' => 'Diocese created and email sent to Diocese Admin',
    //         'diocese' => $diocese,
    //         'diocesan_admin' => [
    //             'id' => $user->id,
    //             'email' => $user->email,
    //             'role' => $user->role
    //         ]
    //     ], 201);
    // }

    // public function createDioceses(Request $request)
    // {
    //     $validated = $request->validate([
    //         'name' => 'required|string|unique:dioceses,name',
    //         'province' => 'required|string',
    //         'state' => 'required|string',
    //         'lga' => 'required|string',
    //         'address' => 'required|string',
    //         'contact_number' => 'required|string|unique:dioceses,contact_number',
    //         'email' => 'required|email|unique:users,email',
    //     ]);

    //     // Normalize name (VERY important for uniqueness)
    //     $dioceseName = strtoupper(trim($validated['name']));

    //     // Extra safety check (optional but professional)
    //     if (Diocese::where('name', $dioceseName)->exists()) {
    //         return response()->json([
    //             'message' => 'A diocese with this name already exists'
    //         ], 422);
    //     }

    //     // Create Diocese
    //     $diocese = Diocese::create([
    //         'name' => $dioceseName,
    //         'province' => $validated['province'],
    //         'state' => $validated['state'],
    //         'lga' => $validated['lga'],
    //         'address' => $validated['address'],
    //         'contact_number' => $validated['contact_number'],
    //     ]);

    //     // Default password
    //     $defaultPassword = '123456';

    //     // Create Diocesan Admin
    //     $user = User::create([
    //         'name' => $validated['name'],
    //         'email' => $validated['email'],
    //         'password' => Hash::make($defaultPassword),
    //         'role' => 'diocesan_admin',
    //         'diocese_id' => $diocese->id,
    //     ]);

    //     // Email verification
    //     $token = Str::random(8);
    //     Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

    //     $verificationLink = rtrim(config('app.frontend_url'), '/') .
    //         "/verify/{$user->id}/{$token}";

    //     $mailData = [
    //         'name' => $user->name,
    //         'email' => $user->email,
    //         'password' => $defaultPassword,
    //         'link' => $verificationLink,
    //     ];

    //     try {
    //         Mail::to($user->email)->send(new DioceseAccountMail($mailData));
    //     } catch (\Exception $e) {
    //         Log::error('Diocese email failed: ' . $e->getMessage());
    //     }

    //     return response()->json([
    //         'status' => 'success',
    //         'message' => 'Diocese created successfully',
    //         'diocese' => $diocese,
    //         'diocesan_admin' => [
    //             'id' => $user->id,
    //             'email' => $user->email,
    //             'role' => $user->role
    //         ]
    //     ], 201);
    // }

    public function createDioceses(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|unique:dioceses,name',
            'province_id' => 'required|exists:provinces,id', // <-- updated
            'state' => 'required|string',
            'lga' => 'required|string',
            'address' => 'required|string',
            'contact_number' => 'required|string|unique:dioceses,contact_number',
            'email' => 'required|email|unique:users,email',
        ]);

        // Normalize name (VERY important for uniqueness)
        $dioceseName = strtoupper(trim($validated['name']));

        // Extra safety check
        if (Diocese::where('name', $dioceseName)->exists()) {
            return response()->json([
                'message' => 'A diocese with this name already exists'
            ], 422);
        }

        // Create Diocese with province_id
        $diocese = Diocese::create([
            'name' => $dioceseName,
            'province_id' => $validated['province_id'], // <-- link to province
            'state' => $validated['state'],
            'lga' => $validated['lga'],
            'address' => $validated['address'],
            'contact_number' => $validated['contact_number'],
        ]);

        // Default password for diocesan admin
        $defaultPassword = '123456';

        // Create Diocesan Admin
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($defaultPassword),
            'role' => 'diocesan_admin',
            'diocese_id' => $diocese->id,
        ]);

        // Email verification
        $token = Str::random(8);
        Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));

        $verificationLink = rtrim(config('app.frontend_url'), '/') .
            "/verify/{$user->id}/{$token}";

        $mailData = [
            'name' => $user->name,
            'email' => $user->email,
            'password' => $defaultPassword,
            'link' => $verificationLink,
        ];

        try {
            Mail::to($user->email)->send(new DioceseAccountMail($mailData));
        } catch (\Exception $e) {
            Log::error('Diocese email failed: ' . $e->getMessage());
        }

        return response()->json([
            'status' => 'success',
            'message' => 'Diocese created successfully',
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
     *     description="Create a new school under the logged-in diocesan admin's diocese. The province is automatically derived from the diocese. Requires JWT authentication.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","email","state","lga"},
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
     *                 @OA\Property(property="diocese_id", type="integer", example=2),
     *                 @OA\Property(property="province_id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                 @OA\Property(property="email", type="string", example="stjoseph@school.com"),
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
     *         description="No province linked to diocese or validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="No province linked to this diocese")
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

        // 3. Get province from diocese
        if (!$diocese->province_id) {
            return response()->json([
                'status' => 'error',
                'message' => 'No province linked to this diocese'
            ], 422);
        }

        // 4. Create School
        $school = School::create([
            'diocese_id' => $diocese->id,
            'name' => strtoupper($validated['name']),
            'email' => $validated['email'],
            'province_id' => $diocese->province_id,
            'state' => $validated['state'],
            'lga' => $validated['lga'],
        ]);

        // 5. Default password
        $defaultPassword = '123456';

        // 6. Create School User Account
        $user = User::create([
            'name' => $school->name,
            'email' => $school->email,
            'password' => Hash::make($defaultPassword),
            'role' => 'school_admin',
            'school_id' => $school->id,
        ]);

        // 7. Generate email verification token
        $token = Str::random(8);
        Cache::put("email_verification_{$user->id}", $token, now()->addMinutes(60));
        $verificationLink = rtrim(config('app.frontend_url'), '/') . "/verify/{$user->id}/{$token}";

        // 8. Send school account mail
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

        // 9. Return response
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
 * @OA\Post(
 *     path="/api/v1/create/learners",
 *     summary="Create a new learner",
 *     description="Registers a new learner without email. The system generates a unique Learner ID automatically. Default password is 123456.",
 *     tags={"School"},
 *     security={{"bearerAuth":{}}},
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\MediaType(
 *             mediaType="multipart/form-data",
 *             @OA\Schema(
 *                 required={"surname","first_name","dob","present_class","gender"},
 *                 @OA\Property(property="surname", type="string", example="Doe", description="Learner's surname"),
 *                 @OA\Property(property="first_name", type="string", example="John", description="Learner's first name"),
 *                 @OA\Property(property="middle_name", type="string", example="Michael", description="Learner's middle name (optional)"),
 *                 @OA\Property(property="dob", type="string", format="date", example="2010-05-12", description="Date of birth"),
 *                 @OA\Property(property="gender", type="string", enum={"male","female"}, example="male", description="Learner's gender"),
 *                 @OA\Property(property="religion", type="string", example="Christianity", description="Learner's religion"),
 *                 @OA\Property(property="residential_address", type="string", example="123 Main Street", description="Residential address"),
 *                 @OA\Property(property="state_of_origin", type="string", example="Lagos", description="State of origin"),
 *                 @OA\Property(property="lga_of_origin", type="string", example="Ikeja", description="Local government area of origin"),
 *                 @OA\Property(property="previous_class", type="string", example="Primary 2", description="Previous class (if any)"),
 *                 @OA\Property(property="present_class", type="string", example="Primary 3", description="Current class"),
 *                 @OA\Property(property="session", type="string", example="2025/2026", description="Academic session"),
 *                 @OA\Property(property="nin", type="string", example="12345678901", description="National Identification Number (optional, unique)"),
 *                 @OA\Property(property="parent_name", type="string", example="Jane Doe", description="Parent/guardian name"),
 *                 @OA\Property(property="parent_relationship", type="string", example="Mother", description="Relationship to learner"),
 *                 @OA\Property(property="parent_phone", type="string", example="+2348012345678", description="Parent/guardian phone number"),
 *                 @OA\Property(property="photo", type="string", format="binary", description="Optional photo file (jpg, jpeg, png)")
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=201,
 *         description="Learner created successfully",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Learner created successfully"),
 *             @OA\Property(
 *                 property="learner",
 *                 type="object",
 *                 description="Learner details",
 *                 @OA\Property(property="id", type="integer", example=1),
 *                 @OA\Property(property="learner_id", type="string", example="CSN/LAG/HOL/0001"),
 *                 @OA\Property(property="surname", type="string", example="Doe"),
 *                 @OA\Property(property="first_name", type="string", example="John"),
 *                 @OA\Property(property="middle_name", type="string", example="Michael"),
 *                 @OA\Property(property="dob", type="string", format="date", example="2010-05-12"),
 *                 @OA\Property(property="gender", type="string", example="male"),
 *                 @OA\Property(property="present_class", type="string", example="Primary 3")
 *             ),
 *             @OA\Property(
 *                 property="user",
 *                 type="object",
 *                 description="Learner user account",
 *                 @OA\Property(property="id", type="integer", example=1),
 *                 @OA\Property(property="name", type="string", example="John Michael Doe"),
 *                 @OA\Property(property="role", type="string", example="learner"),
 *                 @OA\Property(property="school_id", type="integer", example=1),
 *                 @OA\Property(property="learner_id", type="integer", example=1)
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=403,
 *         description="No school linked to this account",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="No school linked to this account")
 *         )
 *     ),
 *     @OA\Response(
 *         response=422,
 *         description="Validation error",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="The given data was invalid."),
 *             @OA\Property(property="errors", type="object")
 *         )
 *     )
 * )
 */



    // public function createLearners(Request $request)
    // {
    //     $school = auth()->user()->school;

    //     if (!$school) {
    //         return response()->json([
    //             'message' => 'No school linked to this account'
    //         ], 403);
    //     }

    //     $validated = $request->validate([
    //         'surname' => 'required|string|max:255',
    //         'first_name' => 'required|string|max:255',
    //         'middle_name' => 'nullable|string|max:255',
    //         'dob' => 'required|date',
    //         'religion' => 'nullable|string|max:100',
    //         'residential_address' => 'nullable|string|max:255',
    //         'state_of_origin' => 'nullable|string|max:100',
    //         'lga_of_origin' => 'nullable|string|max:100',
    //         'previous_class' => 'nullable|string|max:50',
    //         'present_class' => 'required|string|max:50',
    //         'session' => 'nullable|string|max:50',

    //         // ✅ Email entered by school
    //         'email' => 'required|email|unique:users,email',

    //         // Optional NIN (no longer used for email)
    //         'nin' => 'nullable|string|max:20|unique:learners,nin',

    //         'parent_name' => 'nullable|string|max:255',
    //         'parent_relationship' => 'nullable|string|max:100',
    //         'parent_phone' => 'nullable|string|max:20',
    //         'photo' => 'nullable|image|mimes:jpg,jpeg,png|max:2048',
    //     ]);

    //     // Handle photo upload
    //     if ($request->hasFile('photo')) {
    //         $photo = $request->file('photo');
    //         $fileName = time() . '_' . Str::random(8) . '.' . $photo->getClientOriginalExtension();
    //         $photo->move(public_path('uploads/learners'), $fileName);
    //         $validated['photo'] = 'uploads/learners/' . $fileName;
    //     }

    //     // Create learner record
    //     $learner = $school->learners()->create($validated);

    //     // Create learner login account
    //     $user = User::create([
    //         'name' => trim(
    //             $validated['first_name'] . ' ' .
    //             ($validated['middle_name'] ?? '') . ' ' .
    //             $validated['surname']
    //         ),
    //         'email' => $validated['email'], // ✅ use entered email
    //         'password' => Hash::make('123456'), // default password
    //         'role' => 'learner',
    //         'school_id' => $school->id,
    //         'learner_id' => $learner->id,
    //     ]);

    //     return response()->json([
    //         'message' => 'Learner created successfully',
    //         'learner' => $learner,
    //         'user' => $user
    //     ], 201);
    // }


    public function createLearners(Request $request)
    {
        $school = auth()->user()->school;

        if (!$school) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        /* ===========================
         * 1. Validate Request
         * =========================== */
        $validated = $request->validate([
            'surname' => 'required|string|max:255',
            'first_name' => 'required|string|max:255',
            'middle_name' => 'nullable|string|max:255',
            'dob' => 'required|date',
            'religion' => 'nullable|string|max:100',
            'gender' => 'required|string|max:100',
            'residential_address' => 'nullable|string|max:255',
            'state_of_origin' => 'nullable|string|max:100',
            'lga_of_origin' => 'nullable|string|max:100',
            'previous_class' => 'nullable|string|max:50',
            'present_class' => 'required|string|max:50',
            'nin' => 'nullable|string|max:20|unique:learners,nin',
            'parent_name' => 'nullable|string|max:255',
            'parent_relationship' => 'nullable|string|max:100',
            'parent_phone' => 'nullable|string|max:20',
            'photo' => 'nullable|image|mimes:jpg,jpeg,png|max:2048',
        ]);

        /* ===========================
         * 2. Upload Photo (if any)
         * =========================== */
        if ($request->hasFile('photo')) {
            $photo = $request->file('photo');
            $fileName = time() . '_' . Str::random(8) . '.' . $photo->getClientOriginalExtension();
            $photo->move(public_path('uploads/learners'), $fileName);
            $validated['photo'] = 'uploads/learners/' . $fileName;
        }

        /* ===========================
         * 3. Get Active Session & Term
         * =========================== */
        $activeSession = Session::where('status', 'active')->first();
        $activeTerm = Term::where('school_id', $school->id)
            ->where('status', 'active')
            ->first();

        $validated['session_id'] = $activeSession?->id; // null if no active session
        $validated['term_id'] = $activeTerm?->id;       // null if no active term

        /* ===========================
         * 4. Generate Learner Login ID
         * =========================== */
        $dioceseCode = strtoupper(substr($school->diocese->name, 0, 3));
        $schoolCode = strtoupper(substr($school->name, 0, 3));

        $lastUser = User::where('school_id', $school->id)
            ->where('role', 'learner')
            ->orderByDesc('id')
            ->first();

        $serial = $lastUser && $lastUser->login_id
            ? intval(substr($lastUser->login_id, -4)) + 1
            : 1;

        $loginId = 'CSN/' . $dioceseCode . '/' . $schoolCode . '/' . str_pad($serial, 4, '0', STR_PAD_LEFT);

        /* ===========================
         * 5. Create Learner Record
         * =========================== */
        $learner = $school->learners()->create($validated);

        /* ===========================
         * 6. Create User Account
         * =========================== */
        $user = User::create([
            'name' => trim(
                $validated['first_name'] . ' ' .
                ($validated['middle_name'] ?? '') . ' ' .
                $validated['surname']
            ),
            'login_id' => $loginId,
            'email' => null,
            'password' => Hash::make('123456'),
            'role' => 'learner',
            'school_id' => $school->id,
            'learner_id' => $learner->id,
        ]);

        /* ===========================
         * 7. Response
         * =========================== */
        return response()->json([
            'message' => 'Learner created successfully',
            'login_id' => $loginId,
            'learner' => $learner,
            'user' => $user,
            'session' => $activeSession,
            'term' => $activeTerm
        ], 201);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/dioceses",
     *     operationId="AllDioceses",
     *     summary="Get all dioceses (optional filters)",
     *     description="Retrieve all dioceses nationwide with their associated schools. Super Admin can optionally filter by state and local government.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         required=false,
     *         description="Filter dioceses by state",
     *         @OA\Schema(type="string", example="Lagos")
     *     ),
     *
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         required=false,
     *         description="Filter dioceses by local government area (LGA)",
     *         @OA\Schema(type="string", example="Alimosho")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="total", type="integer", example=1),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *                     @OA\Property(property="address", type="string", example="12 Ipaja Road, Lagos"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="education_secretary", type="string", example="Rev. John Doe"),
     *                     @OA\Property(property="created_at", type="string", format="date-time", example="2026-01-01T07:12:46Z"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time", example="2026-01-16T21:37:45Z"),
     *
     *                     @OA\Property(
     *                         property="schools",
     *                         type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=15),
     *                             @OA\Property(property="name", type="string", example="St. Mary's Primary School"),
     *                             @OA\Property(property="email", type="string", format="email", example="stmary@gmail.com"),
     *                             @OA\Property(property="state", type="string", example="Lagos"),
     *                             @OA\Property(property="lga", type="string", example="Ikeja"),
     *                             @OA\Property(property="created_at", type="string", format="date-time", example="2026-01-05T10:00:00Z"),
     *                             @OA\Property(property="updated_at", type="string", format="date-time", example="2026-01-05T10:00:00Z")
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
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     )
     * )
     */


public function allDioceses(Request $request)
{
    $query = Diocese::with([
        'province',
        'schools',
        'educationSecretaries',
        'learners'
    ]);

    if ($request->filled('state')) {
        $query->where('state', $request->state);
    }

    if ($request->filled('lga')) {
        $query->where('lga', $request->lga);
    }

    if ($request->filled('province_id')) {
        $query->where('province_id', $request->province_id);
    }

    $dioceses = $query->get();

    return response()->json([
        'status' => true,
        'total'  => $dioceses->count(),
        'data'   => $dioceses
    ], 200);
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
     *     summary="Get all dioceses with schools and learners (paginated)",
     *     description="Retrieve a paginated list of all dioceses nationwide, including each diocese's schools and learners. Optional `per_page` query parameter for pagination.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         required=false,
     *         description="Number of dioceses per page (default: 10)",
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Paginated list of dioceses with schools and learners",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="data", type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="Lagos Diocese"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *                     @OA\Property(property="address", type="string", example="12 Ipaja road"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="schools", type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=5),
     *                             @OA\Property(property="name", type="string", example="ST MARYS SECONDARY SCHOOL"),
     *                             @OA\Property(property="learners", type="array",
     *                                 @OA\Items(
     *                                     type="object",
     *                                     @OA\Property(property="id", type="integer", example=12),
     *                                     @OA\Property(property="name", type="string", example="John Doe"),
     *                                     @OA\Property(property="class", type="string", example="Primary 1")
     *                                 )
     *                             )
     *                         )
     *                     )
     *                 )
     *             ),
     *             @OA\Property(property="current_page", type="integer", example=1),
     *             @OA\Property(property="last_page", type="integer", example=5),
     *             @OA\Property(property="per_page", type="integer", example=10),
     *             @OA\Property(property="total", type="integer", example=50)
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


    // public function getAllDioceses(Request $request)
    // {
    //     // Get the 'per_page' parameter from request, default to 10
    //     $perPage = $request->get('per_page', 10);

    //     // Paginate dioceses with their schools and learners
    //     $dioceses = Diocese::with('schools.learners')->paginate($perPage);

    //     return response()->json([
    //         'data' => $dioceses->items(),      // current page items
    //         'current_page' => $dioceses->currentPage(),
    //         'last_page' => $dioceses->lastPage(),
    //         'per_page' => $dioceses->perPage(),
    //         'total' => $dioceses->total(),
    //     ]);
    // }



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



    /**
     * @OA\Get(
     *     path="/api/v1/diocese/schools/learners",
     *     operationId="getSchoolsAndLearnersForDiocese",
     *     summary="Get schools and learners for the authenticated diocesan admin",
     *     description="Retrieves all schools under the diocesan admin's diocese, with paginated learners for each school. Requires JWT authentication and 'diocesan_admin' role.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="per_page_schools",
     *         in="query",
     *         required=false,
     *         description="Number of schools per page (default: 10)",
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *     @OA\Parameter(
     *         name="per_page_learners",
     *         in="query",
     *         required=false,
     *         description="Number of learners per school (default: 10)",
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Schools and learners retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="diocese_id", type="integer", example=1),
     *             @OA\Property(property="schools", type="object",
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="last_page", type="integer", example=5),
     *                 @OA\Property(property="per_page", type="integer", example=10),
     *                 @OA\Property(property="total", type="integer", example=50),
     *                 @OA\Property(property="data", type="array",
     *                     @OA\Items(
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=5),
     *                         @OA\Property(property="name", type="string", example="ST MARYS SECONDARY SCHOOL"),
     *                         @OA\Property(property="learners", type="object",
     *                             @OA\Property(property="current_page", type="integer", example=1),
     *                             @OA\Property(property="last_page", type="integer", example=2),
     *                             @OA\Property(property="per_page", type="integer", example=10),
     *                             @OA\Property(property="total", type="integer", example=15),
     *                             @OA\Property(property="data", type="array",
     *                                 @OA\Items(
     *                                     type="object",
     *                                     @OA\Property(property="id", type="integer", example=12),
     *                                     @OA\Property(property="name", type="string", example="John Doe"),
     *                                     @OA\Property(property="class", type="string", example="Primary 1")
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
     *         response=403,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated"
     *     )
     * )
     */

    public function getSchoolsAndLearnersForDiocese(Request $request)
    {
        $user = auth()->user();

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Unauthorized'
            ], 403);
        }

        $perPageSchools = $request->get('per_page_schools', 10); // default 10 schools per page
        $perPageLearners = $request->get('per_page_learners', 10); // default 10 learners per school

        // Get the diocesan schools with paginated learners
        $schools = School::with([
            'learners' => function ($query) use ($perPageLearners) {
                $query->paginate($perPageLearners);
            }
        ])
            ->where('diocese_id', $user->diocese_id)
            ->paginate($perPageSchools);

        return response()->json([
            'diocese_id' => $user->diocese_id,
            'schools' => $schools
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/schools/{schoolId}/update",
     *     operationId="updateSchoolByDiocese",
     *     summary="Update a School within a Diocese",
     *     description="Allows a diocesan admin to update a school within their diocese. All fields are optional. Requires JWT authentication.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="schoolId",
     *         in="path",
     *         description="ID of the school to update",
     *         required=true,
     *         @OA\Schema(type="integer", example=5)
     *     ),
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
     *                     property="class_categories",
     *                     type="array",
     *                     @OA\Items(type="string"),
     *                     description="Array of class categories",
     *                     example={"Primary","Junior Secondary","Senior Secondary"}
     *                 ),
     *
     *                 @OA\Property(
     *                     property="subjects_offered",
     *                     type="array",
     *                     @OA\Items(type="string"),
     *                     description="Array of subjects offered",
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
     *         description="School updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School updated successfully"),
     *             @OA\Property(property="school", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School not found in your diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School not found in your diocese")
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

    public function updateSchoolByDiocese(Request $request, $schoolId)
    {
        $user = auth()->user();

        if ($user->role !== 'diocesan_admin') {
            return response()->json(['message' => 'Unauthorized'], 403);
        }

        $school = School::where('id', $schoolId)
            ->where('diocese_id', $user->diocese_id)
            ->first();

        if (!$school) {
            return response()->json(['message' => 'School not found in your diocese'], 404);
        }

        $validated = $request->validate([
            'name' => 'sometimes|string|unique:schools,name,' . $school->id,
            'email' => 'sometimes|email|unique:schools,email,' . $school->id,
            'province' => 'sometimes|string',
            'state' => 'sometimes|string',
            'lga' => 'sometimes|string',
            'address' => 'nullable|string',
            'contact_number' => 'nullable|string',
            'class_categories' => 'nullable|array',
            'subjects_offered' => 'nullable|array',
            'latest_news' => 'nullable|string',
            'logo' => 'nullable|image|mimes:png,jpg,jpeg|max:2048',
        ]);

        // Handle logo upload
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

        return response()->json([
            'message' => 'School updated successfully',
            'school' => $school->refresh()
        ]);
    }


    /**
     * @OA\Delete(
     *     path="/api/v1/schools/{schoolId}/delete",
     *     operationId="deleteSchoolByDiocese",
     *     summary="Delete a school within the authenticated diocese",
     *     description="Allows a diocesan admin to delete a school that belongs to their diocese. This will also delete learners, associated user accounts, and the school logo if it exists.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="schoolId",
     *         in="path",
     *         required=true,
     *         description="ID of the school to delete",
     *         @OA\Schema(type="integer", example=12)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="School deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School deleted successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School not found in your diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School not found in your diocese")
     *         )
     *     )
     * )
     */

    public function deleteSchoolByDiocese($schoolId)
    {
        $user = auth()->user();

        if ($user->role !== 'diocesan_admin') {
            return response()->json(['message' => 'Unauthorized'], 403);
        }

        $school = School::where('id', $schoolId)
            ->where('diocese_id', $user->diocese_id)
            ->first();

        if (!$school) {
            return response()->json(['message' => 'School not found in your diocese'], 404);
        }

        // Delete all learners first (optional)
        foreach ($school->learners as $learner) {
            // Delete associated user accounts
            if ($learner->user) {
                $learner->user->delete();
            }
            $learner->delete();
        }

        // Delete all school admin users
        foreach ($school->users as $schoolUser) {
            $schoolUser->delete();
        }

        // Delete school logo if exists
        if ($school->logo && File::exists(public_path($school->logo))) {
            File::delete(public_path($school->logo));
        }

        $school->delete();

        return response()->json(['message' => 'School deleted successfully']);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/school/learners",
     *     tags={"School"},
     *     summary="Retrieve all learners for the authenticated school",
     *     description="Returns a list of learners for the school of the authenticated school admin. Supports optional filters like student name, email, parent name, state, LGA, class, and date of registration. Includes login_id for each learner.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="student_name",
     *         in="query",
     *         description="Filter learners by full or partial student name",
     *         @OA\Schema(type="string", example="John Doe")
     *     ),
     *     @OA\Parameter(
     *         name="student_email",
     *         in="query",
     *         description="Filter learners by email",
     *         @OA\Schema(type="string", example="johndoe@example.com")
     *     ),
     *     @OA\Parameter(
     *         name="parent_name",
     *         in="query",
     *         description="Filter learners by parent name",
     *         @OA\Schema(type="string", example="Jane Doe")
     *     ),
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="Filter learners by state of origin",
     *         @OA\Schema(type="string", example="Lagos")
     *     ),
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Filter learners by local government area (LGA)",
     *         @OA\Schema(type="string", example="Ikeja")
     *     ),
     *     @OA\Parameter(
     *         name="class",
     *         in="query",
     *         description="Filter learners by class (previous or present)",
     *         @OA\Schema(type="string", example="NUR 1")
     *     ),
     *     @OA\Parameter(
     *         name="date",
     *         in="query",
     *         description="Filter learners by registration date (YYYY-MM-DD)",
     *         @OA\Schema(type="string", format="date", example="2026-02-10")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="List of learners retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="school_id", type="integer", example=12),
     *             @OA\Property(property="total", type="integer", example=10),
     *             @OA\Property(
     *                 property="learners",
     *                 type="array",
     *                 @OA\Items(
     *                     @OA\Property(property="id", type="integer", example=5),
     *                     @OA\Property(property="surname", type="string", example="Doe"),
     *                     @OA\Property(property="first_name", type="string", example="John"),
     *                     @OA\Property(property="middle_name", type="string", example="Michael"),
     *                     @OA\Property(property="dob", type="string", format="date", example="2015-01-15"),
     *                     @OA\Property(property="previous_class", type="string", example="NUR 1"),
     *                     @OA\Property(property="present_class", type="string", example="NUR 2"),
     *                     @OA\Property(property="session", type="string", example="2024/2025 Academic Session"),
     *                     @OA\Property(property="term", type="string", example="First Term"),
     *                     @OA\Property(property="login_id", type="string", example="LNCSN/LAG/HOL/0001"),
     *                     @OA\Property(property="parent_name", type="string", example="Jane Doe"),
     *                     @OA\Property(property="parent_phone", type="string", example="08012345678"),
     *                     @OA\Property(property="photo", type="string", example="https://example.com/photos/learner5.jpg")
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Unauthorized"))
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - School admin access only",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Forbidden. School admin access only."))
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="No school assigned to this admin",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="No school assigned to this admin."))
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="No learners found under this school",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="No learners found under this school."))
     *     )
     * )
     */



    public function getLearnersForSchool(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden. School admin access only.'], 403);
        }

        if (!$user->school_id) {
            return response()->json(['message' => 'No school assigned to this admin.'], 422);
        }

        // Base query with eager loading session, term, and user (for login_id)
        $query = Learner::with(['session', 'term', 'user'])
            ->where('school_id', $user->school_id);

        // Filters
        if ($request->filled('student_name')) {
            $name = $request->student_name;
            $query->whereRaw("CONCAT_WS(' ', surname, first_name, middle_name) LIKE ?", ["%{$name}%"]);
        }

        if ($request->filled('student_email')) {
            $email = $request->student_email;
            $query->whereHas('user', function ($q) use ($email) {
                $q->where('email', 'LIKE', "%{$email}%");
            });
        }

        if ($request->filled('parent_name')) {
            $query->where('parent_name', 'LIKE', '%' . $request->parent_name . '%');
        }

        if ($request->filled('state')) {
            $query->where('state_of_origin', 'LIKE', '%' . $request->state . '%');
        }

        if ($request->filled('lga')) {
            $query->where('lga_of_origin', 'LIKE', '%' . $request->lga . '%');
        }

        if ($request->filled('class')) {
            $query->where(function ($q) use ($request) {
                $q->where('previous_class', $request->class)
                    ->orWhere('present_class', $request->class);
            });
        }

        if ($request->filled('date')) {
            $query->whereDate('created_at', $request->date);
        }

        $learners = $query->orderBy('created_at', 'desc')->get();

        if ($learners->isEmpty()) {
            return response()->json(['message' => 'No learners found under this school.'], 404);
        }

        // Append login_id from related user to each learner without removing any other data
        $learners = $learners->map(function ($learner) {
            $learnerArray = $learner->toArray(); // keep all learner fields
            $learnerArray['login_id'] = $learner->user ? $learner->user->login_id : null;
            return $learnerArray;
        });

        return response()->json([
            'school_id' => $user->school_id,
            'total' => $learners->count(),
            'learners' => $learners
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/school/learners/{learnerId}",
     *     tags={"School"},
     *     summary="Retrieve a single learner",
     *     description="Retrieve a learner belonging to the authenticated school admin's school. Includes all learner fields, session, term, and login_id.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="learnerId",
     *         in="path",
     *         required=true,
     *         description="ID of the learner to retrieve",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="learner",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="surname", type="string", example="Doe"),
     *                 @OA\Property(property="first_name", type="string", example="John"),
     *                 @OA\Property(property="middle_name", type="string", example="Michael"),
     *                 @OA\Property(property="dob", type="string", format="date", example="2015-01-15"),
     *                 @OA\Property(property="previous_class", type="string", example="NUR 1"),
     *                 @OA\Property(property="present_class", type="string", example="NUR 2"),
     *                 @OA\Property(property="state_of_origin", type="string", example="Lagos"),
     *                 @OA\Property(property="lga_of_origin", type="string", example="Ikeja"),
     *                 @OA\Property(property="parent_name", type="string", example="Jane Doe"),
     *                 @OA\Property(property="parent_relationship", type="string", example="Mother"),
     *                 @OA\Property(property="parent_phone", type="string", example="08012345678"),
     *                 @OA\Property(property="photo", type="string", example="https://example.com/photos/learner1.jpg"),
     *                 @OA\Property(property="login_id", type="string", nullable=true, example="LNCSN/LAG/HOL/0001"),
     *                 @OA\Property(
     *                     property="session",
     *                     type="object",
     *                     nullable=true,
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="2024/2025 Academic Session")
     *                 ),
     *                 @OA\Property(
     *                     property="term",
     *                     type="object",
     *                     nullable=true,
     *                     @OA\Property(property="id", type="integer", example=3),
     *                     @OA\Property(property="name", type="string", example="First Term")
     *                 ),
     *                 @OA\Property(property="created_at", type="string", format="date-time", example="2026-02-10T12:00:00Z"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time", example="2026-02-10T12:30:00Z")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
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
     *         response=404,
     *         description="Learner not found or access denied",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner not found or access denied")
     *         )
     *     )
     * )
     */


    public function showLearner($learnerId)
    {
        $user = auth()->user();

        if (!$user->school_id) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        // Eager load session, term, and user (for login_id)
        $learner = Learner::with(['session', 'term', 'user'])
            ->where('id', $learnerId)
            ->where('school_id', $user->school_id)
            ->first();

        if (!$learner) {
            return response()->json([
                'message' => 'Learner not found or access denied'
            ], 404);
        }

        // Convert learner to array to include all fields
        $learnerArray = $learner->toArray();

        // Add login_id from related user
        $learnerArray['login_id'] = $learner->user ? $learner->user->login_id : null;

        return response()->json([
            'learner' => $learnerArray
        ], 200);
    }




    /**
     * @OA\Post(
     *     path="/api/v1/school/learners/{learnerId}/update",
     *     operationId="updateLearner",
     *     summary="Update a learner",
     *     description="Allows the authenticated school admin to update a learner's details. All fields are optional. Supports image upload.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="learnerId",
     *         in="path",
     *         required=true,
     *         description="ID of the learner to update",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 type="object",
     *
     *                 @OA\Property(property="surname", type="string", example="Doe"),
     *                 @OA\Property(property="first_name", type="string", example="John"),
     *                 @OA\Property(property="middle_name", type="string", example="Michael"),
     *
     *                 @OA\Property(property="dob", type="string", format="date", example="2010-05-15"),
     *                 @OA\Property(property="religion", type="string", example="Christianity"),
     *
     *                 @OA\Property(property="residential_address", type="string", example="12, Apapa road, Lagos"),
     *                 @OA\Property(property="state_of_origin", type="string", example="Lagos"),
     *                 @OA\Property(property="lga_of_origin", type="string", example="Apapa"),
     *
     *                 @OA\Property(property="previous_class", type="string", example="Primary 3"),
     *                 @OA\Property(property="present_class", type="string", example="Primary 4"),
     *
     *                 @OA\Property(property="nin", type="string", example="12345678901"),
     *
     *                 @OA\Property(property="parent_name", type="string", example="Jane Doe"),
     *                 @OA\Property(property="parent_relationship", type="string", example="Mother"),
     *                 @OA\Property(property="parent_phone", type="string", example="+2348012345678"),
     *
     *                 @OA\Property(
     *                     property="photo",
     *                     type="string",
     *                     format="binary",
     *                     description="Learner photo (jpg, jpeg, png)"
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner updated successfully"),
     *             @OA\Property(property="learner", type="object")
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
     *         response=404,
     *         description="Learner not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The photo must be an image."),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */

    public function updateLearner(Request $request, $id)
    {
        $schoolId = auth()->user()->school_id;

        if (!$schoolId) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        $learner = Learner::where('id', $id)
            ->where('school_id', $schoolId)
            ->first();

        if (!$learner) {
            return response()->json([
                'message' => 'Learner not found'
            ], 404);
        }

        $validated = $request->validate([
            'surname' => 'sometimes|string|max:100',
            'first_name' => 'sometimes|string|max:100',
            'middle_name' => 'nullable|string|max:100',

            'dob' => 'nullable|date',
            'religion' => 'nullable|string|max:50',

            'residential_address' => 'nullable|string',
            'state_of_origin' => 'nullable|string|max:50',
            'lga_of_origin' => 'nullable|string|max:50',

            'previous_class' => 'nullable|string|max:50',
            'present_class' => 'sometimes|string|max:50',

            'nin' => 'nullable|string|max:20',

            'parent_name' => 'nullable|string|max:100',
            'parent_relationship' => 'nullable|string|max:50',
            'parent_phone' => 'nullable|string|max:20',

            'photo' => 'nullable|image|mimes:jpg,jpeg,png|max:2048',
        ]);

        // Handle learner photo upload
        if ($request->hasFile('photo')) {

            // Delete old photo if exists
            if ($learner->photo && File::exists(public_path($learner->photo))) {
                File::delete(public_path($learner->photo));
            }

            $photo = $request->file('photo');
            $fileName = time() . '_' . Str::random(8) . '.' . $photo->getClientOriginalExtension();

            $photo->move(public_path('uploads/learners'), $fileName);

            $validated['photo'] = 'uploads/learners/' . $fileName;
        }

        $learner->update($validated);

        return response()->json([
            'message' => 'Learner updated successfully',
            'learner' => $learner
        ]);
    }



    /**
     * @OA\Delete(
     *     path="/api/v1/school/learners/{learnerId}/delete",
     *     operationId="deleteLearner",
     *     summary="Delete a learner",
     *     description="Deletes a learner linked to the authenticated school. Also removes the learner's user account if it exists.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="learnerId",
     *         in="path",
     *         required=true,
     *         description="ID of the learner to delete",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner deleted successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Learner not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="No school linked to this account",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="No school linked to this account")
     *         )
     *     )
     * )
     */

    public function deleteLearner($id)
    {
        $schoolId = auth()->user()->school_id;

        $learner = Learner::where('id', $id)
            ->where('school_id', $schoolId)
            ->first();

        if (!$learner) {
            return response()->json([
                'message' => 'Learner not found'
            ], 404);
        }

        // Remove learner login account if exists
        User::where('learner_id', $learner->id)->delete();

        $learner->delete();

        return response()->json([
            'message' => 'Learner deleted successfully'
        ]);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/learner/profile",
     *     summary="Get Authenticated Learner Profile",
     *     tags={"Learner"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Authenticated learner profile",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(
     *                 property="learner",
     *                 type="object",
     *                 description="Learner details",
     *                 example={
     *                     "id":5,
     *                     "surname":"Doe",
     *                     "first_name":"John",
     *                     "middle_name":"Michael",
     *                     "dob":"2010-05-12",
     *                     "present_class":"Primary 3",
     *                     "school_id":2
     *                 }
     *             ),
     *             @OA\Property(
     *                 property="user",
     *                 type="object",
     *                 example={
     *                     "id":9,
     *                     "name":"John Michael Doe",
     *                     "login_id":"LNCSN/CAT/GOV/0001",
     *                     "role":"learner"
     *                 }
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */
    public function getAuthenticatedLearnerProfile()
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'learner') {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized',
            ], 401);
        }

        $learner = $user->learner; // Relation from User -> Learner

        return response()->json([
            'status' => true,
            'learner' => $learner,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'login_id' => $user->login_id,
                'role' => $user->role,
            ],
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/school/learners/{learnerId}/reset-password",
     *     operationId="resetLearnerPassword",
     *     summary="Reset a learner's password",
     *     description="Resets the password of a learner to a default value ('123456'). Only accessible by the authenticated school admin.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="learnerId",
     *         in="path",
     *         required=true,
     *         description="ID of the learner whose password is to be reset",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner password reset successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner password reset successfully"),
     *             @OA\Property(property="default_password", type="string", example="123456")
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
     *         response=404,
     *         description="Learner not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner not found")
     *         )
     *     )
     * )
     */
    public function resetLearnerPassword($learnerId)
    {
        $schoolId = auth()->user()->school_id;

        if (!$schoolId) {
            return response()->json([
                'message' => 'No school linked to this account'
            ], 403);
        }

        // Make sure learner belongs to this school
        $learner = Learner::where('id', $learnerId)
            ->where('school_id', $schoolId)
            ->first();

        if (!$learner) {
            return response()->json([
                'message' => 'Learner not found'
            ], 404);
        }

        // Get learner's user account
        $user = User::where('learner_id', $learner->id)
            ->where('role', 'learner')
            ->first();

        if (!$user) {
            return response()->json([
                'message' => 'Learner user account not found'
            ], 404);
        }

        // Reset password
        $user->update([
            'password' => Hash::make('123456')
        ]);

        return response()->json([
            'message' => 'Learner password reset successfully',
            'default_password' => '123456'
        ]);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/diocese/schools/{schoolId}",
     *     operationId="getSchoolInMyDiocese",
     *     summary="Get a specific school within the authenticated diocesan admin's diocese",
     *     description="Retrieves a specific school by its ID, ensuring it belongs to the diocesan admin's diocese. Requires JWT authentication and 'diocesan_admin' role.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="schoolId",
     *         in="path",
     *         required=true,
     *         description="ID of the school to retrieve",
     *         @OA\Schema(type="integer", example=5)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="School retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="school", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="No diocese linked to this account",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="No diocese linked to this account")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School not found in your diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School not found in your diocese")
     *         )
     *     )
     * )
     */

    public function getSchoolInMyDiocese($schoolId)
    {
        $user = auth()->user();

        // Ensure diocesan admin is linked to a diocese
        if (!$user->diocese_id) {
            return response()->json([
                'message' => 'No diocese linked to this account'
            ], 403);
        }

        // Fetch school only within this diocese
        $school = School::with(['learners', 'users'])
            ->where('id', $schoolId)
            ->where('diocese_id', $user->diocese_id)
            ->first();

        if (!$school) {
            return response()->json([
                'message' => 'School not found in your diocese'
            ], 404);
        }

        return response()->json([
            'school' => $school
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/user/change-password",
     *     operationId="changePassword",
     *     summary="Change authenticated user's password",
     *     description="Allows the authenticated user to change their password by providing the current password and a new password. Requires JWT authentication.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="current_password", type="string", example="oldpassword123"),
     *             @OA\Property(property="new_password", type="string", example="newpassword456"),
     *             @OA\Property(property="new_password_confirmation", type="string", example="newpassword456")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Password changed successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Password changed successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error or incorrect current password",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Current password is incorrect"),
     *             @OA\Property(property="errors", type="object")
     *         )
     *     )
     * )
     */

    public function changePassword(Request $request)
    {
        $user = auth()->user();

        $validated = $request->validate([
            'current_password' => 'required|string',
            'new_password' => 'required|string|min:6|confirmed',
        ]);

        // Check current password
        if (!Hash::check($validated['current_password'], $user->password)) {
            return response()->json([
                'message' => 'Current password is incorrect'
            ], 422);
        }

        // Update password
        $user->password = Hash::make($validated['new_password']);
        $user->save();

        return response()->json([
            'message' => 'Password changed successfully'
        ]);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/{id}",
     *     operationId="getSingleDiocese",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *     description="Retrieve a single diocese by its ID, including its associated schools and learners.",
     *     summary="Get a single diocese by ID",
     *     description="Returns a single diocese with its schools and learners",
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Diocese ID",
     *         @OA\Schema(
     *             type="integer",
     *             example=2
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=2),
     *                 @OA\Property(property="name", type="string", example="CATHOLIC DIOCESE OF LAGOS"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Alimosho"),
     *                 @OA\Property(property="address", type="string", example="12 Ipaja road, Lagos"),
     *                 @OA\Property(
     *                     property="schools",
     *                     type="array",
     *                     @OA\Items(
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=1),
     *                         @OA\Property(property="name", type="string", example="St. Mary's School"),
     *                         @OA\Property(
     *                             property="learners",
     *                             type="array",
     *                             @OA\Items(
     *                                 type="object",
     *                                 @OA\Property(property="id", type="integer", example=10),
     *                                 @OA\Property(property="name", type="string", example="John Doe")
     *                             )
     *                         )
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Diocese not found",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Diocese not found"
     *             )
     *         )
     *     )
     * )
     */
    public function getSingleDiocese($id)
    {
        $diocese = Diocese::with([
            'educationSecretaries',
            'schools.learners'
        ])->find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        return response()->json([
            'data' => $diocese
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/learners/{id}",
     *     operationId="getSingleLearner",
     *     tags={"School"},
     *     summary="Get a single learner by ID",
     *     description="Returns a learner belonging to the authenticated user's school",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Learner ID",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="data", type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="school_id", type="integer", example=2),
     *                 @OA\Property(property="surname", type="string", example="Isibor"),
     *                 @OA\Property(property="first_name", type="string", example="Ernest"),
     *                 @OA\Property(property="middle_name", type="string", example="Peter"),
     *                 @OA\Property(property="dob", type="string", format="date", example="2010-05-15"),
     *                 @OA\Property(property="religion", type="string", example="Christianity"),
     *                 @OA\Property(property="residential_address", type="string", example="12, Apapa road, Lagos"),
     *                 @OA\Property(property="state_of_origin", type="string", example="Lagos"),
     *                 @OA\Property(property="lga_of_origin", type="string", example="Apapa"),
     *                 @OA\Property(property="previous_class", type="string", example="Primary 3"),
     *                 @OA\Property(property="present_class", type="string", example="Primary 4"),
     *                 @OA\Property(property="nin", type="string", example="12345678901"),
     *                 @OA\Property(property="parent_name", type="string", example="Jane Doe"),
     *                 @OA\Property(property="parent_relationship", type="string", example="Mother"),
     *                 @OA\Property(property="parent_phone", type="string", example="+2348012345678"),
     *                 @OA\Property(property="photo", type="string", example="uploads/learners/photo.jpg"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
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
     *         response=404,
     *         description="Learner not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner not found")
     *         )
     *     )
     * )
     */


    public function getSingleLearner($id)
    {
        $schoolId = auth()->user()->school_id;

        if (!$schoolId) {
            return response()->json(['message' => 'No school linked to this account'], 403);
        }

        $learner = Learner::where([
            'id' => $id,
            'school_id' => $schoolId
        ])->first();

        if (!$learner) {
            return response()->json(['message' => 'Learner not found'], 404);
        }

        return response()->json(['data' => $learner], 200);
    }

    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/{id}/schools/count",
     *     operationId="getTotalSchoolsDiocese",
     *     tags={"Api"},
     *     summary="Get total schools and learners in a particular diocese",
     *     description="Returns the total number of schools and total learners for the specified diocese by ID",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Diocese ID",
     *         @OA\Schema(
     *             type="integer",
     *             example=2
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Totals retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="diocese_id", type="integer", example=2),
     *             @OA\Property(property="diocese_name", type="string", example="CATHOLIC DIOCESE OF LAGOS"),
     *             @OA\Property(property="total_schools", type="integer", example=5),
     *             @OA\Property(property="total_learners", type="integer", example=1200)
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

    public function getTotalSchoolsDiocese($id)
    {
        $diocese = Diocese::withCount(['schools', 'learners'])->find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        return response()->json([
            'diocese_id' => $diocese->id,
            'diocese_name' => $diocese->name,
            'total_schools' => $diocese->schools_count,
            'total_learners' => $diocese->learners_count,
        ], 200);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/create/education-secretary",
     *     summary="Create a new Education Secretary for the logged-in diocesan admin",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *     description="Creates a new Education Secretary associated with the diocese of the logged-in diocesan admin.",
     *     operationId="createEducationSecretary",
     *     @OA\RequestBody(
     *         required=true,
     *         description="Education Secretary data",
     *         @OA\JsonContent(
     *             required={"name","email"},
     *             @OA\Property(property="name", type="string", example="John Doe", description="Full name of the Education Secretary"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com", description="Email address of the Education Secretary"),
     *             @OA\Property(property="phone", type="string", example="+2348012345678", description="Phone number"),
     *             @OA\Property(property="years_of_service", type="integer", example=5, description="Number of years served in education"),
     *             @OA\Property(property="office_location", type="string", example="Diocesan Education Office, Lagos", description="Office location"),
     *             @OA\Property(property="biography", type="string", example="Experienced education officer...", description="Short biography"),
     *             @OA\Property(property="education_background", type="string", example="B.Ed, M.Ed", description="Education qualifications")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Education Secretary created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Education Secretary created successfully"),
     *             @OA\Property(
     *                 property="education_secretary",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="diocese_id", type="integer", example=2),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="email", type="string", example="john.doe@example.com"),
     *                 @OA\Property(property="phone", type="string", example="+2348012345678"),
     *                 @OA\Property(property="years_of_service", type="integer", example=5),
     *                 @OA\Property(property="office_location", type="string", example="Diocesan Education Office, Lagos"),
     *                 @OA\Property(property="biography", type="string", example="Experienced education officer..."),
     *                 @OA\Property(property="education_background", type="string", example="B.Ed, M.Ed"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Logged-in user does not belong to any diocese",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Logged-in user does not belong to any diocese")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 additionalProperties=@OA\Property(type="array", @OA\Items(type="string"))
     *             )
     *         )
     *     )
     * )
     */


    public function createEducationSecretary(Request $request)
    {
        // 1. Validate input
        $validated = $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:education_secretaries,email',
            'phone' => 'nullable|string',
            'years_of_service' => 'nullable|integer|min:0',
            'office_location' => 'nullable|string',
            'biography' => 'nullable|string',
            'education_background' => 'nullable|string',
        ]);

        // 2. Get the Diocese of the logged-in diocesan admin
        $diocese = auth()->user()->diocese;
        if (!$diocese) {
            return response()->json([
                'status' => 'error',
                'message' => 'Logged-in user does not belong to any diocese'
            ], 403);
        }

        // 3. Create Education Secretary
        $secretary = EducationSecretary::create([
            'diocese_id' => $diocese->id,
            'name' => $validated['name'],
            'email' => $validated['email'],
            'phone' => $validated['phone'] ?? null,
            'years_of_service' => $validated['years_of_service'] ?? null,
            'office_location' => $validated['office_location'] ?? null,
            'biography' => $validated['biography'] ?? null,
            'education_background' => $validated['education_background'] ?? null,
        ]);

        // 4. Optional: Send welcome email
        try {
            Mail::to($secretary->email)->send(new EducationSecretaryMail([
                'name' => $secretary->name,
                'diocese' => $diocese->name,
                'email' => $secretary->email,
            ]));
            Log::info('Education Secretary mail sent to ' . $secretary->email);
        } catch (\Exception $e) {
            Log::error('Education Secretary email failed: ' . $e->getMessage());
        }

        // 5. Return response
        return response()->json([
            'status' => 'success',
            'message' => 'Education Secretary created successfully',
            'education_secretary' => $secretary,
        ], 201);
    }


    /**
     * @OA\Put(
     *     path="/api/v1/education-secretary/{id}/update",
     *     summary="Update an Education Secretary by ID (Diocesan Admin only)",
     *     description="Allows a diocesan admin to update an Education Secretary that belongs to their diocese.",
     *     tags={"Diocese"},
     *    security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Education Secretary ID",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         description="Fields to update (send only the fields you want to change)",
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Rev. John Doe"),
     *             @OA\Property(property="email", type="string", format="email", example="john.doe@example.com"),
     *             @OA\Property(property="phone", type="string", example="+2348012345678"),
     *             @OA\Property(property="years_of_service", type="integer", example=10),
     *             @OA\Property(property="office_location", type="string", example="Catholic Secretariat, Lagos"),
     *             @OA\Property(property="biography", type="string", example="Over 15 years of experience in educational administration."),
     *             @OA\Property(property="education_background", type="string", example="B.Ed, M.Ed, PhD")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Education Secretary updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Education Secretary updated successfully"),
     *             @OA\Property(
     *                 property="education_secretary",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="diocese_id", type="integer", example=2),
     *                 @OA\Property(property="name", type="string", example="Rev. John Doe"),
     *                 @OA\Property(property="email", type="string", example="john.doe@example.com"),
     *                 @OA\Property(property="phone", type="string", example="+2348012345678"),
     *                 @OA\Property(property="years_of_service", type="integer", example=10),
     *                 @OA\Property(property="office_location", type="string", example="Catholic Secretariat, Lagos"),
     *                 @OA\Property(property="biography", type="string"),
     *                 @OA\Property(property="education_background", type="string"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
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
     *         response=404,
     *         description="Education Secretary not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Education Secretary not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 additionalProperties=@OA\Property(
     *                     type="array",
     *                     @OA\Items(type="string")
     *                 )
     *             )
     *         )
     *     )
     * )
     */

    public function updateEducationSecretary(Request $request, $id)
    {
        // 1. Get the Diocese of the logged-in diocesan admin
        $diocese = auth()->user()->diocese;

        if (!$diocese) {
            return response()->json([
                'status' => 'error',
                'message' => 'Logged-in user does not belong to any diocese'
            ], 403);
        }

        // 2. Find Education Secretary and ensure it belongs to this diocese
        $secretary = EducationSecretary::where('id', $id)
            ->where('diocese_id', $diocese->id) // 🔐 ownership check
            ->first();

        if (!$secretary) {
            return response()->json([
                'message' => 'Education Secretary not found'
            ], 404);
        }

        // 3. Validate input (email must be unique EXCEPT current record)
        $validated = $request->validate([
            'name' => 'sometimes|required|string',
            'email' => 'sometimes|required|email|unique:education_secretaries,email,' . $secretary->id,
            'phone' => 'nullable|string',
            'years_of_service' => 'nullable|integer|min:0',
            'office_location' => 'nullable|string',
            'biography' => 'nullable|string',
            'education_background' => 'nullable|string',
        ]);

        // 4. Update record
        $secretary->update($validated);

        // 5. Return response
        return response()->json([
            'status' => 'success',
            'message' => 'Education Secretary updated successfully',
            'education_secretary' => $secretary
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/{id}/details",
     *     summary="Get Diocese details by ID (Admin)",
     *     description="Fetch a single diocese with its schools, learners, and diocesan users.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Diocese ID",
     *         @OA\Schema(type="integer", example=2)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=2),
     *                 @OA\Property(property="name", type="string", example="CATHOLIC DIOCESE OF LAGOS"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province 2"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Alimosho"),
     *                 @OA\Property(property="address", type="string", example="12 Ipaja road, Lagos"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(property="logo", type="string", example="uploads/dioceses/logo.png"),
     *                 @OA\Property(property="education_secretary", type="string", example="John Doe"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time"),
     *
     *                 @OA\Property(
     *                     property="schools",
     *                     type="array",
     *                     @OA\Items(
     *                         @OA\Property(property="id", type="integer", example=1),
     *                         @OA\Property(property="diocese_id", type="integer", example=2),
     *                         @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                         @OA\Property(property="email", type="string", example="stjoseph@school.com"),
     *                         @OA\Property(property="state", type="string", example="Lagos"),
     *                         @OA\Property(property="lga", type="string", example="Apapa"),
     *                         @OA\Property(property="created_at", type="string", format="date-time"),
     *
     *                         @OA\Property(
     *                             property="learners",
     *                             type="array",
     *                             @OA\Items(
     *                                 @OA\Property(property="id", type="integer", example=1),
     *                                 @OA\Property(property="school_id", type="integer", example=2),
     *                                 @OA\Property(property="surname", type="string", example="Isibor"),
     *                                 @OA\Property(property="first_name", type="string", example="Ernest"),
     *                                 @OA\Property(property="present_class", type="string", example="Primary 4"),
     *                                 @OA\Property(property="created_at", type="string", format="date-time")
     *                             )
     *                         )
     *                     )
     *                 ),
     *
     *                 @OA\Property(
     *                     property="users",
     *                     type="array",
     *                     @OA\Items(
     *                         @OA\Property(property="id", type="integer", example=10),
     *                         @OA\Property(property="name", type="string", example="Diocesan Admin"),
     *                         @OA\Property(property="email", type="string", example="admin@diocese.com"),
     *                         @OA\Property(property="role", type="string", example="diocese_admin")
     *                     )
     *                 )
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
     *         response=403,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */

    public function getDioceseDetails($id)
    {
        $diocese = Diocese::with([
            'province',
            'schools.learners',
            'users',
        ])
            ->find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        return response()->json([
            'data' => $diocese
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/total",
     *     summary="Get total number of dioceses",
     *     description="Returns the total count of all dioceses. Accessible only by Super Admin.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Total dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total_dioceses",
     *                 type="integer",
     *                 example=25
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     )
     * )
     */
    public function getTotalDioceses()
    {
        // Ensure the user is authenticated via JWT
        $user = auth()->user();
        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized. Please provide a valid token.'
            ], 401);
        }

        // Ensure the user is a super admin
        if ($user->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. You do not have permission to access this resource.'
            ], 403);
        }

        // Count all dioceses
        $total = Diocese::count();

        return response()->json([
            'total_dioceses' => $total
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/schools/total",
     *     summary="Get total number of schools",
     *     description="Returns the total count of all schools. Accessible only by Super Admin.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Total schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total_schools",
     *                 type="integer",
     *                 example=120
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

    public function getTotalSchools()
    {
        $total = School::count();

        return response()->json([
            'total_schools' => $total
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/learners/total",
     *     summary="Get total number of learners",
     *     description="Returns the total count of all learners. Accessible only by Super Admin.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Total learners retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total_learners",
     *                 type="integer",
     *                 example=1200
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
    public function getTotalLearners()
    {
        $total = Learner::count();

        return response()->json([
            'total_learners' => $total
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/get/all/dioceses",
     *     operationId="getAllDiocesesSuper",
     *     tags={"Api"},
     *     summary="Get all dioceses with schools, learners, and education secretary",
     *     description="Allows a super admin to retrieve all dioceses. Optional filters can be applied using state and LGA. Requires JWT authentication.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Number of records per page",
     *         required=false,
     *         @OA\Schema(
     *             type="integer",
     *             example=10
     *         )
     *     ),
     *
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="Filter dioceses by state (optional)",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             example="Lagos"
     *         )
     *     ),
     *
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Filter dioceses by Local Government Area (optional)",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             example="Alimosho"
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Successful response",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="CATHOLIC DIOCESE OF LAGOS"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *
     *                     @OA\Property(
     *                         property="educationsecretary",
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=1),
     *                         @OA\Property(property="name", type="string", example="Rev. John Doe"),
     *                         @OA\Property(property="email", type="string", example="john.doe@example.com"),
     *                         @OA\Property(property="phone", type="string", example="+2348012345678")
     *                     ),
     *
     *                     @OA\Property(
     *                         property="schools",
     *                         type="array",
     *                         @OA\Items(
     *                             type="object",
     *                             @OA\Property(property="id", type="integer", example=1),
     *                             @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                             @OA\Property(
     *                                 property="learners",
     *                                 type="array",
     *                                 @OA\Items(
     *                                     type="object",
     *                                     @OA\Property(property="id", type="integer", example=1),
     *                                     @OA\Property(property="first_name", type="string", example="Ernest"),
     *                                     @OA\Property(property="surname", type="string", example="Isibor")
     *                                 )
     *                             )
     *                         )
     *                     )
     *                 )
     *             ),
     *
     *             @OA\Property(
     *                 property="meta",
     *                 type="object",
     *                 @OA\Property(property="current_page", type="integer", example=1),
     *                 @OA\Property(property="last_page", type="integer", example=1),
     *                 @OA\Property(property="per_page", type="integer", example=10),
     *                 @OA\Property(property="total", type="integer", example=25)
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized - Invalid or missing JWT token"
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - User is not a super admin"
     *     )
     * )
     */


public function getAllDiocesesSuper(Request $request)
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    if ($user->role !== 'super_admin') {
        return response()->json([
            'message' => 'Forbidden. Super admin access only.'
        ], 403);
    }

    $perPage = $request->query('per_page', 10);

    $dioceses = Diocese::with([
            'province',
            'educationSecretaries', // ✅ FIXED
            'schools.learners'
        ])
        ->when($request->filled('state'), fn ($q) =>
            $q->where('state', $request->state)
        )
        ->when($request->filled('lga'), fn ($q) =>
            $q->where('lga', $request->lga)
        )
        ->paginate($perPage);

    return response()->json([
        'data' => $dioceses->items(),
        'meta' => [
            'current_page' => $dioceses->currentPage(),
            'last_page'    => $dioceses->lastPage(),
            'per_page'     => $dioceses->perPage(),
            'total'        => $dioceses->total(),
        ]
    ], 200);
}





    /**
     * @OA\Get(
     *     path="/api/v1/get/learners/{id}",
     *     operationId="getSingleLearnerSuperAdmin",
     *     tags={"Api"},
     *     summary="Get a single learner by ID",
     *     description="Allows a Super Admin to retrieve an individual learner along with the associated school and diocese.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of the learner",
     *         required=true,
     *         @OA\Schema(
     *             type="integer",
     *             example=1
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="object"
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
     *         description="Forbidden. Super admin access only."
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Learner not found"
     *     )
     * )
     */

    public function getSingleLearnerSuperAdmin($id)
    {
        // JWT authentication
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        // Role check
        if ($user->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. Super admin access only.'
            ], 403);
        }

        // Fetch learner with related school and diocese
        $learner = Learner::with([
            'school.diocese'
        ])->find($id);

        if (!$learner) {
            return response()->json([
                'message' => 'Learner not found'
            ], 404);
        }

        return response()->json([
            'data' => $learner
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/get/schools/{id}",
     *     operationId="getSingleSchoolSuperAdmin",
     *     tags={"Api"},
     *     summary="Get a single school by ID",
     *     description="Allows a Super Admin to retrieve a school along with its associated diocese and learners.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="ID of the school",
     *         required=true,
     *         @OA\Schema(
     *             type="integer",
     *             example=1
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="School retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                 @OA\Property(property="email", type="string", example="stjoseph@school.com"),
     *                 @OA\Property(property="province", type="string", example="Lagos Province"),
     *                 @OA\Property(property="state", type="string", example="Lagos"),
     *                 @OA\Property(property="lga", type="string", example="Apapa"),
     *                 @OA\Property(property="address", type="string", example="40, Whafs road, Apapa"),
     *                 @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                 @OA\Property(
     *                     property="diocese",
     *                     type="object",
     *                     description="The diocese this school belongs to",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="CATHOLIC DIOCESE OF LAGOS")
     *                 ),
     *                 @OA\Property(
     *                     property="learners",
     *                     type="array",
     *                     description="List of learners in this school",
     *                     @OA\Items(
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=1),
     *                         @OA\Property(property="surname", type="string", example="Isibor"),
     *                         @OA\Property(property="first_name", type="string", example="Ernest"),
     *                         @OA\Property(property="present_class", type="string", example="Primary 4")
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized. JWT token missing or invalid."
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Super admin access only."
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School not found"
     *     )
     * )
     */

    public function getSingleSchoolSuperAdmin($id)
    {
        // JWT authentication
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        // Role check
        if ($user->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. Super admin access only.'
            ], 403);
        }

        // Fetch school with related diocese and learners
        $school = School::with([
            'diocese',
            'learners'
        ])->find($id);

        if (!$school) {
            return response()->json([
                'message' => 'School not found'
            ], 404);
        }

        return response()->json([
            'data' => $school
        ], 200);
    }



    /**
     * @OA\Put(
     *     path="/api/v1/update/dioceses/{id}",
     *     operationId="superAdminUpdateDioceseById",
     *     tags={"Api"},
     *     summary="Update diocese (Super Admin)",
     *     description="Allows a super admin to update a diocese by ID",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Diocese ID",
     *         @OA\Schema(type="integer", example=2)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *             @OA\Property(property="province", type="string", example="Lagos Province"),
     *             @OA\Property(property="state", type="string", example="Lagos"),
     *             @OA\Property(property="lga", type="string", example="Alimosho"),
     *             @OA\Property(property="address", type="string", example="12 Ipaja Road, Lagos"),
     *             @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *             @OA\Property(property="education_secretary", type="string", example="Rev. John Doe"),
     *             @OA\Property(property="latest_news", type="string", example="New schools opening soon")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Diocese updated successfully"),
     *             @OA\Property(property="data", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden"),
     *     @OA\Response(response=404, description="Diocese not found")
     * )
     */


    public function updateDioceseSuperAdmin(Request $request, $id)
    {
        // JWT authentication
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        // Role check
        if ($user->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. Super admin access only.'
            ], 403);
        }

        // Validate request
        $validated = $request->validate([
            'name' => 'sometimes|string|max:255',
            'province' => 'sometimes|string|max:255',
            'state' => 'sometimes|string|max:255',
            'lga' => 'sometimes|string|max:255',
            'address' => 'sometimes|string|max:500',
            'contact_number' => 'sometimes|string|max:20',
            'education_secretary' => 'sometimes|string|max:255',
            'latest_news' => 'sometimes|string|nullable',
        ]);

        // Find diocese
        $diocese = Diocese::find($id);

        if (!$diocese) {
            return response()->json([
                'message' => 'Diocese not found'
            ], 404);
        }

        // Update diocese
        $diocese->update($validated);

        return response()->json([
            'message' => 'Diocese updated successfully',
            'data' => $diocese
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/user/diocese-id",
     *     summary="Get authenticated user's diocese ID",
     *     description="Returns the diocese ID assigned to the currently authenticated user",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Diocese ID retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="diocese_id",
     *                 type="integer",
     *                 example=5
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="User is not assigned to any diocese",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="User is not assigned to any diocese"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthenticated",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Unauthenticated."
     *             )
     *         )
     *     )
     * )
     */
    public function getAuthenticatedUserDioceseId()
    {
        $user = auth()->user();

        if (!$user->diocese_id) {
            return response()->json([
                'message' => 'User is not assigned to any diocese'
            ], 404);
        }

        return response()->json([
            'diocese_id' => $user->diocese_id
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/education-secretary/{id}",
     *     summary="Get Education Secretary by ID (Diocesan Admin only)",
     *     description="Retrieve an Education Secretary by ID. Access is restricted to diocesan admins and limited to secretaries within the admin's diocese.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         description="Education Secretary ID",
     *         required=true,
     *         @OA\Schema(
     *             type="integer",
     *             example=10
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Education Secretary retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=10),
     *                 @OA\Property(property="diocese_id", type="integer", example=4),
     *                 @OA\Property(property="name", type="string", example="Mrs. Jane Smith"),
     *                 @OA\Property(property="email", type="string", example="jane@example.com"),
     *                 @OA\Property(property="phone", type="string", example="+2348098765432"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Unauthorized"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden – diocesan admin access only",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Forbidden. Diocesan admin access only."
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Education Secretary not found or access denied",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Education Secretary not found or access denied"
     *             )
     *         )
     *     )
     * )
     */
    public function getEducationSecretaryById($id)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        $secretary = EducationSecretary::where('id', $id)
            ->where('diocese_id', $user->diocese_id)
            ->first();

        if (!$secretary) {
            return response()->json([
                'message' => 'Education Secretary not found or access denied'
            ], 404);
        }

        return response()->json([
            'data' => $secretary
        ], 200);
    }




    /**
     * @OA\Get(
     *     path="/api/v1/diocese/schools/total",
     *     summary="Get total number of schools for diocesan admin",
     *     description="Returns the total number of schools associated with the authenticated diocesan admin’s diocese.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Total schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="diocese_id", type="integer", example=2),
     *             @OA\Property(property="total_schools", type="integer", example=45)
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Unauthorized"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden – diocesan admin access only or no diocese linked",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Forbidden. Diocesan admin access only."
     *             )
     *         )
     *     )
     * )
     */
    public function getTotalSchoolsForDiocesanAdmin()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        if (!$user->diocese_id) {
            return response()->json([
                'message' => 'No diocese linked to this account'
            ], 403);
        }

        $totalSchools = School::where('diocese_id', $user->diocese_id)->count();

        return response()->json([
            'diocese_id' => $user->diocese_id,
            'total_schools' => $totalSchools
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/user/school-admin",
     *     summary="Get authenticated school admin details",
     *     description="Returns the authenticated school admin ID and the school they are assigned to. Access is restricted to school admins only.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="School admin details retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="school_admin_id", type="integer", example=15),
     *             @OA\Property(property="school_id", type="integer", example=8)
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Unauthorized"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden – school admin access only",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Forbidden. School admin access only."
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School admin is not assigned to any school",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="School admin is not assigned to any school"
     *             )
     *         )
     *     )
     * )
     */
    public function getAuthenticatedSchoolAdmin()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'school_admin') {
            return response()->json([
                'message' => 'Forbidden. School admin access only.'
            ], 403);
        }

        if (!$user->school_id) {
            return response()->json([
                'message' => 'School admin is not assigned to any school'
            ], 404);
        }

        return response()->json([
            'user_id' => $user->id,
            'school_id' => $user->school_id
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/user/learner-id",
     *     summary="Get authenticated learner ID",
     *     description="Returns the authenticated user's learner ID. Access is restricted to users with the learner role.",
     *     tags={"Learner"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner ID retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="user_id", type="integer", example=21),
     *             @OA\Property(property="learner_id", type="integer", example=1045)
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Unauthorized"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden – learner access only",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Forbidden. Learner access only."
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Learner profile not linked to this account",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="message",
     *                 type="string",
     *                 example="Learner profile not linked to this account"
     *             )
     *         )
     *     )
     * )
     */
    public function getAuthenticatedLearnerId()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'learner') {
            return response()->json([
                'message' => 'Forbidden. Learner access only.'
            ], 403);
        }

        if (!$user->learner_id) {
            return response()->json([
                'message' => 'Learner profile not linked to this account'
            ], 404);
        }

        return response()->json([
            'user_id' => $user->id,
            'learner_id' => $user->learner_id
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/school-admin/dashboard",
     *     operationId="getSchoolAdminDashboard",
     *     tags={"School"},
     *     summary="Get School Admin Dashboard",
     *     description="Returns dashboard data for an authenticated school admin including school details and statistics.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Dashboard data retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="school_admin_id",
     *                 type="integer",
     *                 example=12
     *             ),
     *             @OA\Property(
     *                 property="school",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=5),
     *                 @OA\Property(property="name", type="string", example="St. Peter's College"),
     *                 @OA\Property(
     *                     property="diocese",
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="Lagos Diocese")
     *                 ),
     *                 @OA\Property(
     *                     property="learners",
     *                     type="array",
     *                     @OA\Items(type="object")
     *                 )
     *             ),
     *             @OA\Property(
     *                 property="statistics",
     *                 type="object",
     *                 @OA\Property(property="total_learners", type="integer", example=350)
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - School admin access only",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden. School admin access only.")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="School not found or not assigned",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="School not found")
     *         )
     *     )
     * )
     */

    public function getSchoolAdminDashboard()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'school_admin') {
            return response()->json([
                'message' => 'Forbidden. School admin access only.'
            ], 403);
        }

        if (!$user->school_id) {
            return response()->json([
                'message' => 'No school assigned to this account'
            ], 404);
        }

        $school = School::with([
            'diocese',
            'learners'
        ])->find($user->school_id);

        if (!$school) {
            return response()->json([
                'message' => 'School not found'
            ], 404);
        }

        return response()->json([
            'school_admin_id' => $user->id,
            'school' => $school,
            'statistics' => [
                'total_learners' => $school->learners->count()
            ]
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/learner/profile/dashboard",
     *     operationId="getLearnerProfile",
     *     tags={"Learner"},
     *     summary="Get Learner Profile",
     *     description="Returns the authenticated learner's profile including school and diocese information.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learner profile retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="learner",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=45),
     *                 @OA\Property(property="first_name", type="string", example="John"),
     *                 @OA\Property(property="last_name", type="string", example="Doe"),
     *                 @OA\Property(property="email", type="string", example="john.doe@example.com"),
     *                 @OA\Property(
     *                     property="school",
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=8),
     *                     @OA\Property(property="name", type="string", example="St. Joseph Secondary School")
     *                 ),
     *                 @OA\Property(
     *                     property="diocese",
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=3),
     *                     @OA\Property(property="name", type="string", example="Abuja Diocese")
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Learner access only",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden. Learner access only.")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Learner profile not found or not linked",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Learner record not found")
     *         )
     *     )
     * )
     */


    public function getLearnerProfile()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'learner') {
            return response()->json([
                'message' => 'Forbidden. Learner access only.'
            ], 403);
        }

        if (!$user->learner_id) {
            return response()->json([
                'message' => 'No learner profile linked to this account'
            ], 404);
        }

        $learner = Learner::with([
            'school',
            'diocese'
        ])->find($user->learner_id);

        if (!$learner) {
            return response()->json([
                'message' => 'Learner record not found'
            ], 404);
        }

        return response()->json([
            'learner' => $learner
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/dioceses/filter",
     *     operationId="filterDiocesesByStateAndLga",
     *     tags={"Api"},
     *     summary="Filter dioceses by state and LGA (Super Admin only)",
     *     description="Allows a super admin to filter dioceses using optional state and LGA query parameters.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="State name to filter dioceses",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             example="Lagos"
     *         )
     *     ),
     *
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Local Government Area to filter dioceses",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             example="Alimosho"
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Filtered dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total",
     *                 type="integer",
     *                 example=2
     *             ),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *                     @OA\Property(property="address", type="string", example="12 Ipaja Road, Lagos"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="logo", type="string", example="uploads/dioceses/logo.png"),
     *                     @OA\Property(property="created_at", type="string", example="2026-01-01 07:12:46"),
     *                     @OA\Property(property="updated_at", type="string", example="2026-01-16 21:37:45")
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - Super admin access only",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     )
     * )
     */

    public function filterDiocesesByStateAndLga(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. Super admin access only.'
            ], 403);
        }

        $query = Diocese::query();

        if ($request->filled('state')) {
            $query->where('state', $request->state);
        }

        if ($request->filled('lga')) {
            $query->where('lga', $request->lga);
        }

        $dioceses = $query->get();

        return response()->json([
            'total' => $dioceses->count(),
            'data' => $dioceses
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/search",
     *     summary="Global search for Super Admin",
     *     description="Search dioceses and schools by name, province, state. Returns matching dioceses and schools.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="q",
     *         in="query",
     *         description="Keyword to search for (diocese name, school name, province, state, LGA)",
     *         required=true,
     *         @OA\Schema(
     *             type="string",
     *             example="lagos"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Search results found",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="query", type="string", example="lagos"),
     *             @OA\Property(
     *                 property="dioceses",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos")
     *                 )
     *             ),
     *             @OA\Property(
     *                 property="schools",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="St Joseph Catholic School"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(
     *                         property="diocese",
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=2),
     *                         @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                         @OA\Property(property="province", type="string", example="Lagos Province")
     *                     )
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden (not super admin)",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=422,
     *         description="Validation error (keyword missing)",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Search keyword is required")
     *         )
     *     )
     * )
     */
    public function globalSearch(Request $request)
    {
        $keyword = $request->query('q');

        if (!$keyword) {
            return response()->json([
                'message' => 'Search keyword is required'
            ], 422);
        }

        /** ---------------- DIOCESES ---------------- */
        $dioceses = Diocese::where('name', 'LIKE', "%{$keyword}%")
            ->orWhere('province', 'LIKE', "%{$keyword}%")
            ->orWhere('state', 'LIKE', "%{$keyword}%")
            ->get();

        /** ---------------- SCHOOLS ---------------- */
        $schools = School::where('name', 'LIKE', "%{$keyword}%")
            ->orWhere('province', 'LIKE', "%{$keyword}%")
            ->orWhere('state', 'LIKE', "%{$keyword}%")
            ->with('diocese:id,name,province')
            ->get();

        return response()->json([
            'query' => $keyword,
            'dioceses' => $dioceses,
            'schools' => $schools
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/schools/filter",
     *     operationId="filterSchoolsByDiocese",
     *     summary="Get schools for a specific diocese with optional filters",
     *     description="Allows super admin to retrieve all schools belonging to a specific diocese. Optional filters include school name, province, and creation date range.",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="diocese_id",
     *         in="query",
     *         description="ID of the diocese (required)",
     *         required=true,
     *         @OA\Schema(type="integer", example=2)
     *     ),
     *
     *     @OA\Parameter(
     *         name="name",
     *         in="query",
     *         description="Filter by school name (optional, partial match)",
     *         required=false,
     *         @OA\Schema(type="string", example="JOSEPH")
     *     ),
     *
     *     @OA\Parameter(
     *         name="province",
     *         in="query",
     *         description="Filter by province (optional)",
     *         required=false,
     *         @OA\Schema(type="string", example="Lagos Province")
     *     ),
     *
     *     @OA\Parameter(
     *         name="from_date",
     *         in="query",
     *         description="Filter schools created from this date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *
     *     @OA\Parameter(
     *         name="to_date",
     *         in="query",
     *         description="Filter schools created up to this date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-31")
     *     ),
     *
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Number of records per page",
     *         required=false,
     *         @OA\Schema(type="integer", example=10)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="diocese_id", type="integer", example=2),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Apapa"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="created_at", type="string", format="date-time")
     *                 )
     *             ),
     *             @OA\Property(
     *                 property="meta",
     *                 type="object",
     *                 @OA\Property(property="current_page", type="integer"),
     *                 @OA\Property(property="last_page", type="integer"),
     *                 @OA\Property(property="per_page", type="integer"),
     *                 @OA\Property(property="total", type="integer")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden. Super admin access only."),
     *     @OA\Response(response=404, description="No schools found for this diocese")
     * )
     */

    public function filterSchoolsByDiocese(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
        }

        if (!$request->filled('diocese_id')) {
            return response()->json(['message' => 'diocese_id is required'], 422);
        }

        $perPage = $request->get('per_page', 10);

        $schools = School::query()
            ->where('diocese_id', $request->diocese_id)
            ->when($request->filled('name'), function ($q) use ($request) {
                $q->where('name', 'LIKE', '%' . $request->name . '%');
            })
            ->when($request->filled('from_date'), function ($q) use ($request) {
                $q->whereDate('created_at', '>=', $request->from_date);
            })
            ->when($request->filled('to_date'), function ($q) use ($request) {
                $q->whereDate('created_at', '<=', $request->to_date);
            })
            ->orderBy('created_at', 'desc')
            ->paginate($perPage);


        if ($schools->isEmpty()) {
            return response()->json(['message' => 'No schools found for this diocese'], 404);
        }

        return response()->json([
            'diocese_id' => $request->diocese_id,
            'data' => $schools->items(),
            'meta' => [
                'current_page' => $schools->currentPage(),
                'last_page' => $schools->lastPage(),
                'per_page' => $schools->perPage(),
                'total' => $schools->total(),
            ]
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/schools/search",
     *     summary="Search schools by name",
     *     description="Allows super admin to search schools using their name",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="name",
     *         in="query",
     *         description="Name of the school to search for",
     *         required=true,
     *         @OA\Schema(
     *             type="string",
     *             example="St Joseph"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="schools",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="St Joseph Catholic School"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Apapa"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="No schools found with that name",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="No schools found with that name")
     *         )
     *     )
     * )
     */
    public function searchSchoolsByName(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
        }

        $name = $request->query('name');

        if (!$name) {
            return response()->json(['message' => 'School name is required'], 422);
        }

        $schools = School::where('name', 'like', "%{$name}%")->get();

        if ($schools->isEmpty()) {
            return response()->json(['message' => 'No schools found with that name'], 404);
        }

        return response()->json([
            'schools' => $schools
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/dioceses/filter-by-date",
     *     summary="Filter dioceses by creation date",
     *     description="Allows super admin to filter dioceses by a creation date range",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="from",
     *         in="query",
     *         description="Start date in YYYY-MM-DD format",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *     @OA\Parameter(
     *         name="to",
     *         in="query",
     *         description="End date in YYYY-MM-DD format",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-24")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Filtered dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total",
     *                 type="integer",
     *                 example=3
     *             ),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(type="object")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Super admin access only."
     *     )
     * )
     */
    public function filterDiocesesByDate(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
        }

        $query = Diocese::query(); // <-- Make sure this queries dioceses

        if ($request->filled('from')) {
            $query->whereDate('created_at', '>=', $request->from);
        }

        if ($request->filled('to')) {
            $query->whereDate('created_at', '<=', $request->to);
        }

        $results = $query->get();

        return response()->json([
            'total' => $results->count(),
            'data' => $results
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/schools/filter-by-date",
     *     summary="Filter schools by creation date",
     *     description="Allows super admin to filter schools by a creation date range",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="from",
     *         in="query",
     *         description="Start date in YYYY-MM-DD format",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *     @OA\Parameter(
     *         name="to",
     *         in="query",
     *         description="End date in YYYY-MM-DD format",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-24")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Filtered schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total",
     *                 type="integer",
     *                 example=10
     *             ),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(type="object")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Super admin access only."
     *     )
     * )
     */
    public function filterSchoolsByDate(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
        }

        $query = School::query();

        if ($request->filled('from')) {
            $query->whereDate('created_at', '>=', $request->from);
        }

        if ($request->filled('to')) {
            $query->whereDate('created_at', '<=', $request->to);
        }

        $results = $query->get();

        return response()->json([
            'total' => $results->count(),
            'data' => $results
        ], 200);
    }


/**
 * @OA\Get(
 *     path="/api/v1/super-admin/students",
 *     summary="Get all students (Super Admin only)",
 *     description="Returns a paginated list of all students with optional filters by state, LGA, province, student name, parent name, and date range. Includes school and diocese names.",
 *     tags={"Api"},
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Parameter(
 *         name="per_page",
 *         in="query",
 *         description="Number of students per page",
 *         required=false,
 *         @OA\Schema(type="integer", default=10)
 *     ),
 *     @OA\Parameter(
 *         name="state",
 *         in="query",
 *         description="Filter by diocese state",
 *         required=false,
 *         @OA\Schema(type="string")
 *     ),
 *     @OA\Parameter(
 *         name="lga",
 *         in="query",
 *         description="Filter by diocese LGA",
 *         required=false,
 *         @OA\Schema(type="string")
 *     ),
 *     @OA\Parameter(
 *         name="province",
 *         in="query",
 *         description="Filter by diocese province",
 *         required=false,
 *         @OA\Schema(type="string")
 *     ),
 *     @OA\Parameter(
 *         name="student_name",
 *         in="query",
 *         description="Filter by full name of student (surname + first name + middle name)",
 *         required=false,
 *         @OA\Schema(type="string")
 *     ),
 *     @OA\Parameter(
 *         name="parent_name",
 *         in="query",
 *         description="Filter by parent name",
 *         required=false,
 *         @OA\Schema(type="string")
 *     ),
 *     @OA\Parameter(
 *         name="from",
 *         in="query",
 *         description="Filter students created from this date (YYYY-MM-DD)",
 *         required=false,
 *         @OA\Schema(type="string", format="date")
 *     ),
 *     @OA\Parameter(
 *         name="to",
 *         in="query",
 *         description="Filter students created up to this date (YYYY-MM-DD)",
 *         required=false,
 *         @OA\Schema(type="string", format="date")
 *     ),
 *
 *     @OA\Response(
 *         response=200,
 *         description="List of students",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(
 *                 property="data",
 *                 type="array",
 *                 @OA\Items(
 *                     type="object",
 *                     @OA\Property(property="id", type="integer"),
 *                     @OA\Property(property="surname", type="string"),
 *                     @OA\Property(property="first_name", type="string"),
 *                     @OA\Property(property="middle_name", type="string"),
 *                     @OA\Property(property="dob", type="string", format="date"),
 *                     @OA\Property(property="parent_name", type="string"),
 *                     @OA\Property(property="parent_relationship", type="string"),
 *                     @OA\Property(property="parent_phone", type="string"),
 *                     @OA\Property(property="school_name", type="string"),
 *                     @OA\Property(property="diocese_name", type="string"),
 *                     @OA\Property(property="created_at", type="string", format="date-time"),
 *                     @OA\Property(property="updated_at", type="string", format="date-time")
 *                 )
 *             ),
 *             @OA\Property(
 *                 property="meta",
 *                 type="object",
 *                 @OA\Property(property="current_page", type="integer"),
 *                 @OA\Property(property="last_page", type="integer"),
 *                 @OA\Property(property="per_page", type="integer"),
 *                 @OA\Property(property="total", type="integer")
 *             )
 *         )
 *     ),
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized"
 *     ),
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden. Super admin access only."
 *     )
 * )
 */

public function getAllStudents(Request $request)
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    if ($user->role !== 'super_admin') {
        return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
    }

    $perPage = $request->get('per_page', 10);

    $learners = Learner::query()
        ->join('schools', 'learners.school_id', '=', 'schools.id')
        ->join('dioceses', 'schools.diocese_id', '=', 'dioceses.id')
        ->select(
            'learners.*',
            // School details
            'schools.id as school_id',
            'schools.name as school_name',
            'schools.email as school_email',
            'schools.state as school_state',
            'schools.lga as school_lga',
            'schools.address as school_address',
            'schools.contact_number as school_contact_number',
            'schools.logo as school_logo',
            // Diocese details
            'dioceses.id as diocese_id',
            'dioceses.name as diocese_name',
            'dioceses.province_id as diocese_province_id',
            'dioceses.state as diocese_state',
            'dioceses.lga as diocese_lga',
            'dioceses.address as diocese_address',
            'dioceses.contact_number as diocese_contact_number'
        )

        // Diocese filters
        ->when($request->filled('state'), function ($q) use ($request) {
            $q->where('dioceses.state', $request->state);
        })
        ->when($request->filled('lga'), function ($q) use ($request) {
            $q->where('dioceses.lga', $request->lga);
        })
        ->when($request->filled('province'), function ($q) use ($request) {
            $q->where('dioceses.province', $request->province);
        })

        // Student full name search
        ->when($request->filled('student_name'), function ($q) use ($request) {
            $name = $request->student_name;
            $q->whereRaw(
                "CONCAT_WS(' ', learners.surname, learners.first_name, learners.middle_name) LIKE ?",
                ["%{$name}%"]
            );
        })

        // Parent name search
        ->when($request->filled('parent_name'), function ($q) use ($request) {
            $q->where('learners.parent_name', 'LIKE', '%' . $request->parent_name . '%');
        })

        // Date filters
        ->when($request->filled('from'), function ($q) use ($request) {
            $q->whereDate('learners.created_at', '>=', $request->from);
        })
        ->when($request->filled('to'), function ($q) use ($request) {
            $q->whereDate('learners.created_at', '<=', $request->to);
        })

        ->orderBy('learners.created_at', 'desc')
        ->paginate($perPage);

    return response()->json([
        'data' => $learners->items(),
        'meta' => [
            'current_page' => $learners->currentPage(),
            'last_page' => $learners->lastPage(),
            'per_page' => $learners->perPage(),
            'total' => $learners->total(),
        ]
    ], 200);
}


    /**
     * @OA\Get(
     *     path="/api/v1/diocesan-admin/schools/search",
     *     summary="Search schools in the diocesan admin's diocese",
     *     description="Allows a diocesan admin to search for schools by name and email within their assigned diocese",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="name",
     *         in="query",
     *         description="School name to search for",
     *         required=false,
     *         @OA\Schema(type="string", example="ST. JOSEPH CATHOLIC SCHOOL")
     *     ),
     *     @OA\Parameter(
     *         name="email",
     *         in="query",
     *         description="School email to search for",
     *         required=false,
     *         @OA\Schema(type="string", example="stjoseph@school.com")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(
     *                 property="total",
     *                 type="integer",
     *                 example=3
     *             ),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="diocese_id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
     *                     @OA\Property(property="email", type="string", example="stjoseph@school.com"),
     *                     @OA\Property(property="province", type="string", example="Lagos Province"),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Apapa"),
     *                     @OA\Property(property="address", type="string", example="40, Whafs road, Apapa"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="logo", type="string", example="uploads/school/1767319302_H72uqynq.png"),
     *                     @OA\Property(property="latest_news", type="string", example="School resumes fully on Monday"),
     *                     @OA\Property(property="created_at", type="string", example="2026-01-01 16:33:18"),
     *                     @OA\Property(property="updated_at", type="string", example="2026-01-03 06:54:23")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Diocesan admin access only or no diocese linked"
     *     )
     * )
     */

    public function searchSchoolsForDiocesanAdmin(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json(['message' => 'Forbidden. Diocesan admin access only.'], 403);
        }

        if (!$user->diocese_id) {
            return response()->json(['message' => 'No diocese linked to this account'], 403);
        }

        $query = School::where('diocese_id', $user->diocese_id);

        if ($request->filled('name')) {
            $query->where('name', 'like', '%' . $request->name . '%');
        }

        if ($request->filled('email')) {
            $query->where('email', 'like', '%' . $request->email . '%');
        }

        $schools = $query->get();

        return response()->json([
            'total' => $schools->count(),
            'data' => $schools
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/diocesan-admin/schools/filter",
     *     summary="Filter schools by state and LGA for diocesan admin",
     *     description="Allows diocesan admin to filter schools under their diocese by state and LGA",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="State of the school",
     *         required=false,
     *         @OA\Schema(type="string", example="Lagos")
     *     ),
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Local Government Area of the school",
     *         required=false,
     *         @OA\Schema(type="string", example="Apapa")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Filtered schools retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="total", type="integer", example=3),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(type="object")
     *             )
     *         )
     *     ),
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden. Diocesan admin access only or no diocese linked")
     * )
     */

    public function filterSchoolsByStateAndLga(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json(['message' => 'Forbidden. Diocesan admin access only.'], 403);
        }

        if (!$user->diocese_id) {
            return response()->json(['message' => 'No diocese linked to this account'], 403);
        }

        $query = School::where('diocese_id', $user->diocese_id);

        if ($request->filled('state')) {
            $query->where('state', $request->state);
        }

        if ($request->filled('lga')) {
            $query->where('lga', $request->lga);
        }

        $schools = $query->get();

        return response()->json([
            'total' => $schools->count(),
            'data' => $schools
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/diocesan-admin/schools/filter-by-date",
     *     summary="Filter schools by date for diocesan admin",
     *     description="Allows diocesan admin to filter schools under their diocese by creation date",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="from",
     *         in="query",
     *         description="Start date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *
     *     @OA\Parameter(
     *         name="to",
     *         in="query",
     *         description="End date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-31")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Schools filtered successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="total", type="integer", example=5),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(type="object")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden or no diocese linked")
     * )
     */

    public function filterSchoolsByDateForDiocesanAdmin(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json(['message' => 'Forbidden. Diocesan admin access only.'], 403);
        }

        if (!$user->diocese_id) {
            return response()->json(['message' => 'No diocese linked to this account'], 403);
        }

        $query = School::where('diocese_id', $user->diocese_id);

        // Filter by date range
        if ($request->filled('from')) {
            $query->whereDate('created_at', '>=', $request->from);
        }

        if ($request->filled('to')) {
            $query->whereDate('created_at', '<=', $request->to);
        }

        $schools = $query->orderBy('created_at', 'desc')->get();

        return response()->json([
            'total' => $schools->count(),
            'data' => $schools
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/diocesan-admin/students",
     *     summary="Get learners under diocesan admin's diocese",
     *     description="Returns learners under the logged-in diocesan admin's diocese with optional filters",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="school_name",
     *         in="query",
     *         description="Filter by school name",
     *         required=false,
     *         @OA\Schema(type="string", example="Joseph School")
     *     ),
     *     @OA\Parameter(
     *         name="school_email",
     *         in="query",
     *         description="Filter by school email",
     *         required=false,
     *         @OA\Schema(type="string", example="school@gmail.com")
     *     ),
     *     @OA\Parameter(
     *         name="parent_name",
     *         in="query",
     *         description="Filter by parent's name",
     *         required=false,
     *         @OA\Schema(type="string", example="Jane Doe")
     *     ),
     *     @OA\Parameter(
     *         name="date",
     *         in="query",
     *         description="Filter by created date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learners retrieved successfully"
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="No learners found"
     *     )
     * )
     */

    public function getStudentsUnderDiocese(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        if (!$user->diocese_id) {
            return response()->json([
                'message' => 'No diocese assigned to this admin.'
            ], 422);
        }

        // Query learners under schools in this diocese
        $query = Learner::query()
            ->join('schools', 'learners.school_id', '=', 'schools.id')
            ->where('schools.diocese_id', $user->diocese_id)
            ->select('learners.*');

        // Optional filters
        if ($request->filled('school_name')) {
            $query->where('schools.name', 'LIKE', '%' . $request->school_name . '%');
        }

        if ($request->filled('school_email')) {
            $query->where('schools.email', 'LIKE', '%' . $request->school_email . '%');
        }

        if ($request->filled('parent_name')) {
            $query->where('learners.parent_name', 'LIKE', '%' . $request->parent_name . '%');
        }

        if ($request->filled('date')) {
            $query->whereDate('learners.created_at', $request->date);
        }

        $learners = $query->orderBy('learners.created_at', 'desc')->get();

        if ($learners->isEmpty()) {
            return response()->json([
                'message' => 'No learners found under this diocese.'
            ], 404);
        }

        return response()->json([
            'diocese_id' => $user->diocese_id,
            'total' => $learners->count(),
            'learners' => $learners
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/school-admin/students",
     *     tags={"School"},
     *     summary="Filter students in a school by name, email, or parent name",
     *     description="Allows a school admin to search students in their school using name, email, or parent name.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="search",
     *         in="query",
     *         description="Search by student name, email, or parent name",
     *         required=false,
     *         @OA\Schema(type="string", example="Ernest")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Students retrieved successfully"
     *     ),
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */
    public function filterStudentsForSchool(Request $request)
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        if (!$user->school_id) {
            return response()->json(['message' => 'No school linked to this account'], 403);
        }

        $query = DB::table('learners')
            ->leftJoin('users', 'users.learner_id', '=', 'learners.id')
            ->where('learners.school_id', $user->school_id)
            ->select(
                'learners.id',
                DB::raw("CONCAT(learners.surname, ' ', learners.first_name, ' ', learners.middle_name) as full_name"),
                'users.email',
                'learners.parent_name',
                'learners.created_at'
            );

        /** 🔍 SEARCH FILTER */
        if ($request->filled('search')) {
            $search = $request->search;

            $query->where(function ($q) use ($search) {
                $q->where('learners.surname', 'like', "%{$search}%")
                    ->orWhere('learners.first_name', 'like', "%{$search}%")
                    ->orWhere('learners.middle_name', 'like', "%{$search}%")
                    ->orWhere('learners.parent_name', 'like', "%{$search}%")
                    ->orWhere('users.email', 'like', "%{$search}%");
            });
        }

        $students = $query->orderBy('learners.created_at', 'desc')->get();

        return response()->json([
            'total' => $students->count(),
            'data' => $students
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/school-admin/students/lga-filter",
     *     tags={"School"},
     *     summary="Filter students by state and local government",
     *     description="Allows a school admin to filter students in their school by state and local government of origin.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="Filter by student's state of origin",
     *         required=false,
     *         @OA\Schema(type="string", example="Lagos")
     *     ),
     *
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Filter by student's local government of origin",
     *         required=false,
     *         @OA\Schema(type="string", example="Apapa")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Students retrieved successfully"
     *     ),
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */

    public function filterStudentsForSchoolLga(Request $request)
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        if (!$user->school_id) {
            return response()->json(['message' => 'No school linked to this account'], 403);
        }

        $query = DB::table('learners')
            ->leftJoin('users', 'users.learner_id', '=', 'learners.id')
            ->where('learners.school_id', $user->school_id)
            ->select(
                'learners.id',
                DB::raw("CONCAT(learners.surname, ' ', learners.first_name, ' ', learners.middle_name) as full_name"),
                'users.email',
                'learners.parent_name',
                'learners.state_of_origin',
                'learners.lga_of_origin',
                'learners.created_at'
            );

        /** 📍 FILTER BY STATE */
        if ($request->filled('state')) {
            $query->where('learners.state_of_origin', $request->state);
        }

        /** 📍 FILTER BY LGA */
        if ($request->filled('lga')) {
            $query->where('learners.lga_of_origin', $request->lga);
        }

        $students = $query->orderBy('learners.created_at', 'desc')->get();

        return response()->json([
            'total' => $students->count(),
            'data' => $students
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/school-admin/students/date-filter",
     *     tags={"School"},
     *     summary="Filter students by date",
     *     description="Allows a school admin to filter students in their school by registration date range.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="start_date",
     *         in="query",
     *         description="Filter students registered from this date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *
     *     @OA\Parameter(
     *         name="end_date",
     *         in="query",
     *         description="Filter students registered up to this date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-31")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Students filtered successfully"
     *     ),
     *     @OA\Response(response=401, description="Unauthorized"),
     *     @OA\Response(response=403, description="Forbidden")
     * )
     */

    public function filterStudentsForSchoolDate(Request $request)
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        if (!$user->school_id) {
            return response()->json(['message' => 'No school linked to this account'], 403);
        }

        $query = DB::table('learners')
            ->leftJoin('users', 'users.learner_id', '=', 'learners.id')
            ->where('learners.school_id', $user->school_id)
            ->select(
                'learners.id',
                DB::raw("CONCAT(learners.surname, ' ', learners.first_name, ' ', learners.middle_name) as full_name"),
                'users.email',
                'learners.parent_name',
                'learners.state_of_origin',
                'learners.lga_of_origin',
                'learners.created_at'
            );

        // 📅 Date filtering
        if ($request->filled('start_date')) {
            $query->whereDate('learners.created_at', '>=', $request->start_date);
        }

        if ($request->filled('end_date')) {
            $query->whereDate('learners.created_at', '<=', $request->end_date);
        }

        $students = $query->orderBy('learners.created_at', 'desc')->get();

        return response()->json([
            'total' => $students->count(),
            'data' => $students
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/learners/class-filter",
     *     summary="Filter learners by class for school admin",
     *     description="Retrieve a list of learners filtered by class. Only accessible to school admins.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="class",
     *         in="query",
     *         description="Class to filter learners by (e.g., 'Primary 4')",
     *         required=false,
     *         @OA\Schema(
     *             type="string",
     *             example="Primary 4"
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="List of learners filtered by class",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="total", type="integer", example=1),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="school_id", type="integer", example=2),
     *                     @OA\Property(property="surname", type="string", example="Isibor"),
     *                     @OA\Property(property="first_name", type="string", example="Ernest"),
     *                     @OA\Property(property="middle_name", type="string", example="Peter"),
     *                     @OA\Property(property="dob", type="string", format="date", example="2010-05-15"),
     *                     @OA\Property(property="present_class", type="string", example="Primary 4"),
     *                     @OA\Property(property="parent_name", type="string", example="Jane Doe"),
     *                     @OA\Property(property="state_of_origin", type="string", example="Lagos"),
     *                     @OA\Property(property="lga_of_origin", type="string", example="Apapa"),
     *                     @OA\Property(property="created_at", type="string", format="date-time", example="2026-01-02T11:35:43"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time", example="2026-01-04T00:24:52")
     *                 )
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Only school admins can access.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. School admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized. User not authenticated.",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */

    public function filterLearnersByClass(Request $request)
    {
        $user = auth('api')->user();

        // Ensure only school admins can access
        if (!$user || $user->role !== 'school_admin') {
            return response()->json([
                'message' => 'Forbidden. School admin access only.'
            ], 403);
        }

        // Start query for learners in the admin's school
        $query = Learner::where('school_id', $user->school_id);

        // Filter by class if provided
        if ($request->filled('class')) {
            $query->where('present_class', $request->class);
        }

        $learners = $query->get();

        return response()->json([
            'total' => $learners->count(),
            'data' => $learners
        ], 200);
    }


/**
 * @OA\Get(
 *     path="/api/v1/super-admin/all/schools",
 *     operationId="getAllSchoolsSuper",
 *     tags={"Api"},
 *     summary="Get all schools (Super Admin)",
 *     description="Retrieve a paginated list of all schools. Supports filtering by diocese ID, school name (partial match), province name (via diocese relationship), and creation date range. Accessible only by super admins.",
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Parameter(
 *         name="per_page",
 *         in="query",
 *         description="Number of records per page",
 *         required=false,
 *         @OA\Schema(type="integer", example=10)
 *     ),
 *
 *     @OA\Parameter(
 *         name="diocese",
 *         in="query",
 *         description="Filter by diocese ID",
 *         required=false,
 *         @OA\Schema(type="integer", example=2)
 *     ),
 *
 *     @OA\Parameter(
 *         name="name",
 *         in="query",
 *         description="Filter by school name (partial match)",
 *         required=false,
 *         @OA\Schema(type="string", example="ST. JOSEPH")
 *     ),
 *
 *     @OA\Parameter(
 *         name="province",
 *         in="query",
 *         description="Filter by province name (via diocese → province relationship)",
 *         required=false,
 *         @OA\Schema(type="string", example="Lagos Province")
 *     ),
 *
 *     @OA\Parameter(
 *         name="from_date",
 *         in="query",
 *         description="Filter schools created on or after this date (YYYY-MM-DD)",
 *         required=false,
 *         @OA\Schema(type="string", format="date", example="2026-01-01")
 *     ),
 *
 *     @OA\Parameter(
 *         name="to_date",
 *         in="query",
 *         description="Filter schools created on or before this date (YYYY-MM-DD)",
 *         required=false,
 *         @OA\Schema(type="string", format="date", example="2026-01-31")
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
 *                     @OA\Property(property="id", type="integer", example=1),
 *                     @OA\Property(property="name", type="string", example="ST. JOSEPH CATHOLIC SCHOOL"),
 *                     @OA\Property(property="state", type="string", example="Lagos"),
 *                     @OA\Property(property="lga", type="string", example="Apapa"),
 *                     @OA\Property(
 *                         property="diocese",
 *                         type="object",
 *                         @OA\Property(property="id", type="integer", example=2),
 *                         @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
 *                         @OA\Property(
 *                             property="province",
 *                             type="object",
 *                             @OA\Property(property="id", type="integer", example=1),
 *                             @OA\Property(property="name", type="string", example="Lagos Province")
 *                         )
 *                     ),
 *                     @OA\Property(property="created_at", type="string", format="date-time", example="2026-01-01T16:33:18Z")
 *                 )
 *             ),
 *             @OA\Property(
 *                 property="meta",
 *                 type="object",
 *                 @OA\Property(property="current_page", type="integer", example=1),
 *                 @OA\Property(property="last_page", type="integer", example=3),
 *                 @OA\Property(property="per_page", type="integer", example=10),
 *                 @OA\Property(property="total", type="integer", example=25)
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized – Invalid or missing JWT token",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Unauthorized")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden – Super admin access only",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
 *         )
 *     )
 * )
 */



public function getAllSchoolsSuper(Request $request)
{
    $user = auth('api')->user();
    if (!$user || $user->role !== 'super_admin') {
        return response()->json([
            'message' => !$user ? 'Unauthorized' : 'Forbidden. Super admin access only.'
        ], !$user ? 401 : 403);
    }

    $perPage = $request->query('per_page', 10);

    $schools = School::with(['diocese', 'province'])
        ->when($request->filled('diocese'), fn($q) => $q->where('diocese_id', $request->diocese))
        ->when($request->filled('name'), fn($q) => $q->where('name', 'LIKE', "%{$request->name}%"))
        ->when($request->filled('province'), fn($q) =>
            $q->whereHas('province', fn($q2) =>
                $q2->whereRaw('LOWER(name) = ?', [strtolower($request->province)])
            )
        )
        ->when($request->filled('from_date'), fn($q) => $q->whereDate('created_at', '>=', $request->from_date))
        ->when($request->filled('to_date'), fn($q) => $q->whereDate('created_at', '<=', $request->to_date))
        ->orderByDesc('created_at')
        ->paginate($perPage);

    return response()->json([
        'data' => $schools->items(),
        'meta' => [
            'current_page' => $schools->currentPage(),
            'last_page'    => $schools->lastPage(),
            'per_page'     => $schools->perPage(),
            'total'        => $schools->total(),
        ]
    ], 200);
}





    /**
     * @OA\Get(
     *     path="/api/v1/diocesan-admin/schools",
     *     summary="Get schools under logged-in diocesan admin",
     *     description="Returns all schools under the diocesan admin's diocese with optional filters",
     *     tags={"Diocese"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="name",
     *         in="query",
     *         description="Filter by school name",
     *         required=false,
     *         @OA\Schema(type="string", example="Joseph")
     *     ),
     *     @OA\Parameter(
     *         name="email",
     *         in="query",
     *         description="Filter by school email",
     *         required=false,
     *         @OA\Schema(type="string", example="school@gmail.com")
     *     ),
     *     @OA\Parameter(
     *         name="state",
     *         in="query",
     *         description="Filter by state",
     *         required=false,
     *         @OA\Schema(type="string", example="Lagos")
     *     ),
     *     @OA\Parameter(
     *         name="lga",
     *         in="query",
     *         description="Filter by LGA",
     *         required=false,
     *         @OA\Schema(type="string", example="Apapa")
     *     ),
     *     @OA\Parameter(
     *         name="date",
     *         in="query",
     *         description="Filter by created date (YYYY-MM-DD)",
     *         required=false,
     *         @OA\Schema(type="string", format="date", example="2026-01-01")
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Schools retrieved successfully"
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized"
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden"
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="No schools found"
     *     )
     * )
     */


    public function getSchoolsUnderDiocese(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        if (!$user->diocese_id) {
            return response()->json([
                'message' => 'No diocese assigned to this admin.'
            ], 422);
        }

        $query = School::where('diocese_id', $user->diocese_id);

        // OPTIONAL FILTERS
        if ($request->filled('name')) {
            $query->where('name', 'LIKE', '%' . $request->name . '%');
        }

        if ($request->filled('email')) {
            $query->where('email', 'LIKE', '%' . $request->email . '%');
        }

        if ($request->filled('state')) {
            $query->where('state', $request->state);
        }

        if ($request->filled('lga')) {
            $query->where('lga', $request->lga);
        }

        if ($request->filled('date')) {
            $query->whereDate('created_at', $request->date);
        }

        $schools = $query->orderBy('created_at', 'desc')->get();

        if ($schools->isEmpty()) {
            return response()->json([
                'message' => 'No schools found for this diocese.'
            ], 404);
        }

        return response()->json([
            'diocese_id' => $user->diocese_id,
            'total' => $schools->count(),
            'schools' => $schools
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/super-admin/provinces",
     *     summary="Get all provinces",
     *     description="Allows super admin to retrieve a list of all unique provinces from dioceses",
     *     tags={"Api"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Provinces retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="total", type="integer", example=5),
     *             @OA\Property(
     *                 property="provinces",
     *                 type="array",
     *                 @OA\Items(type="string", example="Lagos Province")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="No provinces found",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="No provinces found.")
     *         )
     *     )
     * )
     */

    public function getAllProvinces(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden. Super admin access only.'], 403);
        }

        // Get unique provinces
        $provinces = Diocese::select('province')
            ->distinct()
            ->orderBy('province', 'asc')
            ->pluck('province'); // returns a simple array

        if ($provinces->isEmpty()) {
            return response()->json(['message' => 'No provinces found.'], 404);
        }

        return response()->json([
            'total' => $provinces->count(),
            'provinces' => $provinces
        ], 200);
    }


    /**
     * Learners Enrolment Per Month
     *
     * Returns the total number of learners enrolled per month for a given year.
     * - Super Admin: sees enrolments across all schools
     * - School Admin: sees enrolments only under their school
     *
     * @OA\Get(
     *     path="/api/v1/analytics/learners-enrolment-per-month",
     *     operationId="learnersEnrolmentPerMonth",
     *     tags={"Api"},
     *     summary="Get learners enrolment count per month",
     *     description="Returns monthly learner enrolment statistics for a specified year. Defaults to the current year if not provided.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="year",
     *         in="query",
     *         required=false,
     *         description="Year to filter enrolment data (defaults to current year)",
     *         @OA\Schema(
     *             type="integer",
     *             example=2026
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Learners enrolment per month retrieved successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="year", type="integer", example=2026),
     *             @OA\Property(property="total_months", type="integer", example=3),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="year", type="integer", example=2026),
     *                     @OA\Property(property="month_number", type="integer", example=1),
     *                     @OA\Property(property="month", type="string", example="January"),
     *                     @OA\Property(property="total_enrolments", type="integer", example=12)
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden")
     *         )
     *     )
     * )
     */


    public function learnersEnrolmentPerMonth(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        // Default to current year if not provided
        $year = $request->query('year', now()->year);

        $query = Learner::select(
            DB::raw('YEAR(created_at) as year'),
            DB::raw('MONTH(created_at) as month_number'),
            DB::raw('MONTHNAME(created_at) as month'),
            DB::raw('COUNT(*) as total_enrolments')
        )
            ->whereYear('created_at', $year);

        /**
         * Role-based filtering
         * Super Admin -> all learners
         * School Admin -> only learners under his school
         */
        if ($user->role === 'school_admin') {
            $query->where('school_id', $user->school_id);
        }

        $enrolments = $query
            ->groupBy('year', 'month_number', 'month')
            ->orderBy('month_number', 'asc')
            ->get();

        return response()->json([
            'year' => (int) $year,
            'total_months' => $enrolments->count(),
            'data' => $enrolments
        ], 200);
    }


    /**
     * Reset authenticated user's password to default
     *
     * @OA\Post(
     *     path="/api/v1/reset-password-default",
     *     operationId="resetPasswordToDefault",
     *     tags={"Reset Password"},
     *     summary="Reset password to default",
     *     description="Resets the authenticated user's password to a system-defined default password.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Password reset successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Password reset successfully"),
     *             @OA\Property(property="default_password", type="string", example="password222")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */


    public function resetPasswordToDefault()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        $defaultPassword = 'PassWord123!';

        $user->update([
            'password' => Hash::make($defaultPassword),
        ]);

        return response()->json([
            'message' => 'Password reset successfully',
            'default_password' => $defaultPassword
        ], 200);
    }



    /**
     * Reset Diocesan Admin Password
     *
     * This endpoint allows a super admin to reset the password of a diocesan admin
     * to the default password "PassWord123!".
     *
     * @OA\Put(
     *     path="/api/v1/diocesan-admins/{dioceseId}/reset-password",
     *     operationId="resetDiocesanAdminPassword",
     *     summary="Reset diocesan admin password",
     *     description="Allows the super admin to reset the password of a diocesan admin for a specific diocese to the default password 'password222'.",
     *     tags={"Api"},
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="dioceseId",
     *         in="path",
     *         description="ID of the diocese whose admin password is being reset",
     *         required=true,
     *         @OA\Schema(type="integer")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Diocesan admin password reset successfully"),
     *             @OA\Property(property="default_password", type="string", example="password222")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Super admin access only",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. Super admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Diocesan admin not found",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Diocesan admin not found for this diocese")
     *         )
     *     )
     * )
     */

    public function resetDiocesanAdminPassword($dioceseId)
    {
        $authUser = auth('api')->user();

        // Only super admin can do this
        if (!$authUser || $authUser->role !== 'super_admin') {
            return response()->json([
                'message' => 'Forbidden. Super admin access only.'
            ], 403);
        }

        // Find diocesan admin user for this diocese
        $diocesanAdmin = User::where('diocese_id', $dioceseId)
            ->where('role', 'diocesan_admin')
            ->first();

        if (!$diocesanAdmin) {
            return response()->json([
                'message' => 'Diocesan admin not found for this diocese'
            ], 404);
        }

        // Default password
        $defaultPassword = 'PassWord123!';

        // Reset password
        $diocesanAdmin->update([
            'password' => Hash::make($defaultPassword),
        ]);

        return response()->json([
            'message' => 'Diocesan admin password reset successfully',
            'default_password' => $defaultPassword
        ], 200);
    }


    /**
     * Reset School Admin Password
     *
     * This endpoint allows a diocesan admin to reset the password of a school admin
     * under their diocese to the default password "PassWord123!".
     *
     * @OA\Put(
     *     path="/api/v1/schools/{schoolId}/reset-password",
     *     operationId="resetSchoolAdminPassword",
     *     summary="Reset school admin password",
     *     description="Allows the diocesan admin to reset the password of a school admin under their diocese to the default password 'password222'.",
     *     tags={"Diocese"},
     *     security={{"bearerAuth": {}}},
     *     @OA\Parameter(
     *         name="schoolId",
     *         in="path",
     *         description="ID of the school whose admin password is being reset",
     *         required=true,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Password reset successfully",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="School admin password reset successfully"),
     *             @OA\Property(property="default_password", type="string", example="password222")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden. Diocesan admin access only",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="Forbidden. Diocesan admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="School or school admin not found",
     *         @OA\JsonContent(
     *             type="object",
     *             @OA\Property(property="message", type="string", example="School admin not found for this school")
     *         )
     *     )
     * )
     */

    public function resetSchoolAdminPassword($schoolId)
    {
        $authUser = auth('api')->user();

        // Only diocesan admin can do this
        if (!$authUser || $authUser->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        // Find the school under this diocese
        $school = School::where('id', $schoolId)
            ->where('diocese_id', $authUser->diocese_id)
            ->first();

        if (!$school) {
            return response()->json([
                'message' => 'School not found under your diocese'
            ], 404);
        }

        // Get the school admin user
        $schoolAdmin = User::where('school_id', $school->id)
            ->where('role', 'school_admin')
            ->first();

        if (!$schoolAdmin) {
            return response()->json([
                'message' => 'School admin not found for this school'
            ], 404);
        }

        // Default password
        $defaultPassword = 'PassWord123!';

        // Reset password
        $schoolAdmin->update([
            'password' => Hash::make($defaultPassword),
        ]);

        return response()->json([
            'message' => 'School admin password reset successfully',
            'default_password' => $defaultPassword
        ], 200);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/super-admin/create/sessions",
     *     tags={"Api"},
     *     summary="Create a new academic session",
     *     description="Creates a new academic session. Only super admins are allowed. If the session status is set to active, all other active sessions will be automatically set to inactive.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","start_date","end_date","status"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="2024/2025 Academic Session"
     *             ),
     *             @OA\Property(
     *                 property="start_date",
     *                 type="string",
     *                 format="date",
     *                 example="2024-09-01"
     *             ),
     *             @OA\Property(
     *                 property="end_date",
     *                 type="string",
     *                 format="date",
     *                 example="2025-07-31"
     *             ),
     *             @OA\Property(
     *                 property="status",
     *                 type="string",
     *                 enum={"active","inactive"},
     *                 example="active"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Session created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Session created successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="2024/2025 Academic Session"),
     *                 @OA\Property(property="start_date", type="string", format="date", example="2024-09-01"),
     *                 @OA\Property(property="end_date", type="string", format="date", example="2025-07-31"),
     *                 @OA\Property(property="status", type="string", example="active"),
     *                 @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
     *                 @OA\Property(property="updated_at", type="string", example="2026-02-10T12:00:00Z")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "name": {"The name field is required."},
     *                     "end_date": {"The end date must be a date after start date."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */

    public function createSession(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $request->validate([
            'name' => 'required|string',
            'start_date' => 'required|date',
            'end_date' => 'required|date|after:start_date',
            'status' => 'required|in:active,inactive',
        ]);

        // 🔒 Ensure only ONE active session
        if ($request->status === 'active') {
            Session::where('status', 'active')->update([
                'status' => 'inactive'
            ]);
        }

        $session = Session::create([
            'name' => $request->name,
            'start_date' => $request->start_date,
            'end_date' => $request->end_date,
            'status' => $request->status,
        ]);

        return response()->json([
            'message' => 'Session created successfully',
            'data' => $session
        ], 201);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/create/terms",
     *     tags={"School"},
     *     summary="Create a new term",
     *     description="Creates a new academic term for the authenticated school admin's school. Only one active term is allowed per school. If status is set to active, any existing active term for the school will be set to inactive.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name","start_date","end_date","status"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="First Term"
     *             ),
     *             @OA\Property(
     *                 property="start_date",
     *                 type="string",
     *                 format="date",
     *                 example="2026-03-01"
     *             ),
     *             @OA\Property(
     *                 property="end_date",
     *                 type="string",
     *                 format="date",
     *                 example="2026-06-30"
     *             ),
     *             @OA\Property(
     *                 property="status",
     *                 type="string",
     *                 enum={"active","inactive"},
     *                 example="active"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Term created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Term created successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=3),
     *                 @OA\Property(property="school_id", type="integer", example=12),
     *                 @OA\Property(property="name", type="string", example="First Term"),
     *                 @OA\Property(property="start_date", type="string", example="2026-03-01"),
     *                 @OA\Property(property="end_date", type="string", example="2026-06-30"),
     *                 @OA\Property(property="status", type="string", example="active"),
     *                 @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
     *                 @OA\Property(property="updated_at", type="string", example="2026-02-10T12:00:00Z")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "name": {"The name field is required."},
     *                     "start_date": {"The start date is required."},
     *                     "end_date": {"The end date must be a date after start date."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */


    public function createTerm(Request $request)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $request->validate([
            'name' => 'required|string',
            'status' => 'required|in:active,inactive',

        ]);

        // 🔒 Ensure only ONE active term PER SCHOOL
        if ($request->status === 'active') {
            Term::where('school_id', $user->school_id)
                ->where('status', 'active')
                ->update(['status' => 'inactive']);
        }

        $term = Term::create([
            'school_id' => $user->school_id,
            'name' => $request->name,
            'status' => $request->status,
        ]);

        return response()->json([
            'message' => 'Term created successfully',
            'data' => $term
        ], 201);
    }




    /**
     * @OA\Get(
     *     path="/api/v1/sessions",
     *     tags={"Sessions"},
     *     summary="Retrieve all sessions",
     *     description="Returns a list of all academic sessions, ordered by start date descending.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="List of sessions retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="total", type="integer", example=5),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="2024/2025 Academic Session"),
     *                     @OA\Property(property="start_date", type="string", format="date", example="2024-09-01"),
     *                     @OA\Property(property="end_date", type="string", format="date", example="2025-07-31"),
     *                     @OA\Property(property="status", type="string", example="active"),
     *                     @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
     *                     @OA\Property(property="updated_at", type="string", example="2026-02-10T12:30:00Z")
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Unauthorized"))
     *     )
     * )
     */


    public function getAllSessions()
    {
        // Retrieve all sessions, ordered by most recent
        $sessions = Session::orderBy('start_date', 'desc')->get();

        return response()->json([
            'status' => true,
            'total' => $sessions->count(),
            'data' => $sessions
        ], 200);
    }


    /**
     * @OA\Post(
     *     path="/api/v1/learner/login",
     *     tags={"Authentication"},
     *     summary="Learner login using Login ID and password",
     *     description="Authenticates a learner using login_id and password and returns a JWT token.",
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"login_id","password"},
     *             @OA\Property(
     *                 property="login_id",
     *                 type="string",
     *                 example="CSN/ABC/SCH/0001",
     *                 description="Unique learner login ID"
     *             ),
     *             @OA\Property(
     *                 property="password",
     *                 type="string",
     *                 format="password",
     *                 example="123456",
     *                 description="Learner account password"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Login successful"),
     *             @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
     *             @OA\Property(property="token_type", type="string", example="bearer"),
     *             @OA\Property(property="expires_in", type="integer", example=3600),
     *             @OA\Property(
     *                 property="user",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=15),
     *                 @OA\Property(property="name", type="string", example="John Doe"),
     *                 @OA\Property(property="login_id", type="string", example="CSN/ABC/SCH/0001"),
     *                 @OA\Property(property="role", type="string", example="learner"),
     *                 @OA\Property(property="learner_id", type="integer", example=22)
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Invalid credentials",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Invalid login credentials")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "login_id": {"The login id field is required."},
     *                     "password": {"The password field is required."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */

    public function learnerLogin(Request $request)
    {
        $credentials = $request->validate([
            'login_id' => 'required|string',
            'password' => 'required|string|min:6',
        ]);

        // Use JWT guard explicitly
        if (
            !$token = auth('api')->attempt([
                'login_id' => $credentials['login_id'],
                'password' => $credentials['password'],
                'role' => 'learner',
            ])
        ) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid login credentials',
            ], 401);
        }

        $user = auth('api')->user();

        return response()->json([
            'status' => true,
            'message' => 'Login successful',
            'token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60,
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'login_id' => $user->login_id,
                'role' => $user->role,
                'learner_id' => $user->learner_id,
            ],
        ]);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/learner/logout",
     *     summary="Learner Logout",
     *     tags={"Learner"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Logout successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Successfully logged out")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     )
     * )
     */
    public function learnerLogout()
    {
        auth('api')->logout();

        return response()->json([
            'status' => true,
            'message' => 'Successfully logged out',
        ]);
    }



    /**
     * @OA\Put(
     *     path="/api/v1/update/session/{id}",
     *     tags={"Api"},
     *     summary="Update an existing session",
     *     description="Updates the details of a session. Only super admins can perform this action. If status is set to active, all other sessions will be set to inactive.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID of the session to update",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="2024/2025 Academic Session"),
     *             @OA\Property(property="start_date", type="string", format="date", example="2024-09-01"),
     *             @OA\Property(property="end_date", type="string", format="date", example="2025-07-31"),
     *             @OA\Property(property="status", type="string", enum={"active","inactive"}, example="active")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Session updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Session updated successfully"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="2024/2025 Academic Session"),
     *                 @OA\Property(property="start_date", type="string", format="date", example="2024-09-01"),
     *                 @OA\Property(property="end_date", type="string", format="date", example="2025-07-31"),
     *                 @OA\Property(property="status", type="string", example="active"),
     *                 @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
     *                 @OA\Property(property="updated_at", type="string", example="2026-02-10T12:30:00Z")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Unauthorized"))
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Forbidden"))
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Session not found",
     *         @OA\JsonContent(@OA\Property(property="message", type="string", example="Session not found"))
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={
     *                     "end_date": {"The end date must be a date after start date."}
     *                 }
     *             )
     *         )
     *     )
     * )
     */

    public function updateSession(Request $request, $id)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $session = Session::find($id);

        if (!$session) {
            return response()->json(['message' => 'Session not found'], 404);
        }

        $request->validate([
            'name' => 'sometimes|string',
            'start_date' => 'sometimes|date',
            'end_date' => 'sometimes|date|after:start_date',
            'status' => 'sometimes|in:active,inactive',
        ]);

        // Ensure only ONE active session
        if ($request->filled('status') && $request->status === 'active') {
            Session::where('status', 'active')
                ->where('id', '!=', $id)
                ->update(['status' => 'inactive']);
        }

        // Clean update data
        $data = $request->only(['name', 'start_date', 'end_date', 'status']);
        $data = array_filter($data, fn($value) => !is_null($value) && $value !== '');

        $session->update($data);

        return response()->json([
            'message' => 'Session updated successfully',
            'data' => $session
        ], 200);
    }



/**
 * @OA\Put(
 *     path="/api/v1/update/term/{id}",
 *     tags={"School"},
 *     summary="Update an existing term",
 *     description="Updates the name and/or status of a term for the authenticated school admin. Only one active term is allowed per school. If a term is set to active, all other active terms for the same school are automatically set to inactive.",
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Parameter(
 *         name="id",
 *         in="path",
 *         required=true,
 *         description="ID of the term to update",
 *         @OA\Schema(type="integer", example=3)
 *     ),
 *
 *     @OA\RequestBody(
 *         required=true,
 *         @OA\JsonContent(
 *             @OA\Property(
 *                 property="name",
 *                 type="string",
 *                 example="First Term",
 *                 description="Name of the term"
 *             ),
 *             @OA\Property(
 *                 property="status",
 *                 type="string",
 *                 enum={"active","inactive"},
 *                 example="active",
 *                 description="Status of the term"
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=200,
 *         description="Term updated successfully",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Term updated successfully"),
 *             @OA\Property(
 *                 property="data",
 *                 type="object",
 *                 @OA\Property(property="id", type="integer", example=3),
 *                 @OA\Property(property="school_id", type="integer", example=12),
 *                 @OA\Property(property="name", type="string", example="First Term"),
 *                 @OA\Property(property="status", type="string", example="active"),
 *                 @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
 *                 @OA\Property(property="updated_at", type="string", example="2026-02-16T14:30:00Z")
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Unauthorized")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Forbidden")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=404,
 *         description="Term not found",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Term not found")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=422,
 *         description="Validation error",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="The given data was invalid."),
 *             @OA\Property(
 *                 property="errors",
 *                 type="object",
 *                 example={
 *                     "status": {"The selected status is invalid."}
 *                 }
 *             )
 *         )
 *     )
 * )
 */


    public function updateTerm(Request $request, $id)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        if ($user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        // Find the term by ID
        $term = Term::where('id', $id)->where('school_id', $user->school_id)->first();
        if (!$term) {
            return response()->json(['message' => 'Term not found'], 404);
        }

        // Validate input (partial updates allowed)
        $request->validate([
            'name' => 'sometimes|required|string',
            'status' => 'sometimes|required|in:active,inactive',
        ]);

        // Ensure only ONE active term per school
        if ($request->status === 'active') {
            Term::where('school_id', $user->school_id)
                ->where('status', 'active')
                ->where('id', '!=', $id)
                ->update(['status' => 'inactive']);
        }

        // Update the term with provided fields
        $term->update($request->only(['name', 'status']));

        return response()->json([
            'message' => 'Term updated successfully',
            'data' => $term
        ], 200);
    }



/**
 * @OA\Get(
 *     path="/api/v1/school/terms",
 *     tags={"School"},
 *     summary="Retrieve all terms for the authenticated school",
 *     description="Returns all academic terms belonging to the authenticated school admin's school.",
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Response(
 *         response=200,
 *         description="List of terms retrieved successfully",
 *         @OA\JsonContent(
 *             @OA\Property(property="status", type="boolean", example=true),
 *             @OA\Property(property="total", type="integer", example=3),
 *             @OA\Property(
 *                 property="data",
 *                 type="array",
 *                 @OA\Items(
 *                     @OA\Property(property="id", type="integer", example=3),
 *                     @OA\Property(property="school_id", type="integer", example=12),
 *                     @OA\Property(property="name", type="string", example="First Term"),
 *                     @OA\Property(property="status", type="string", example="active"),
 *                     @OA\Property(property="created_at", type="string", example="2026-02-10T12:00:00Z"),
 *                     @OA\Property(property="updated_at", type="string", example="2026-02-16T14:30:00Z")
 *                 )
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Unauthorized")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Forbidden")
 *         )
 *     )
 * )
 */

    public function getTermsForSchool()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        // Only school admin can view their school's terms
        if ($user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        // Retrieve all terms for the admin's school, ordered by start_date
        $terms = Term::where('school_id', $user->school_id)
            ->get();

        return response()->json([
            'status' => true,
            'total' => $terms->count(),
            'data' => $terms
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/sessions/{id}",
     *     operationId="getSessionById",
     *     summary="Get session by ID",
     *     description="Retrieve a single academic session by its ID.",
     *     tags={"Sessions"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Session ID",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Session retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="data", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Session not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Session not found")
     *         )
     *     )
     * )
     */

    public function getSessionById($id)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized'
            ], 401);
        }

        $session = Session::find($id);

        if (!$session) {
            return response()->json([
                'status' => false,
                'message' => 'Session not found'
            ], 404);
        }

        return response()->json([
            'status' => true,
            'data' => $session
        ], 200);
    }


    /**
     * @OA\Get(
     *     path="/api/v1/terms/{id}",
     *     operationId="getTermById",
     *     summary="Get term by ID",
     *     description="Retrieve a single academic term by its ID. School admin access only.",
     *     tags={"School"},
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Term ID",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Term retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="data", type="object")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Term not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Term not found")
     *         )
     *     )
     * )
     */

    public function getTermById($id)
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized'
            ], 401);
        }

        // Optional role check
        if ($user->role !== 'school_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $term = Term::find($id);

        if (!$term) {
            return response()->json([
                'status' => false,
                'message' => 'Term not found'
            ], 404);
        }

        return response()->json([
            'status' => true,
            'data' => $term
        ], 200);
    }



    /**
     * @OA\Post(
     *     path="/api/v1/create/province",
     *     tags={"Api"},
     *     summary="Create a new province",
     *     description="Allows only super admins to create a new province",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="Lagos",
     *                 description="Unique province name"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=201,
     *         description="Province created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Province created successfully"),
     *             @OA\Property(
     *                 property="province",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="LAGOS"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden - User is not a super admin",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={"name": {"The name has already been taken."}}
     *             )
     *         )
     *     )
     * )
     */
    public function createProvince(Request $request)
    {
        $user = auth('api')->user();

        if (!$user || $user->role !== 'super_admin') {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $validated = $request->validate([
            'name' => 'required|string|unique:provinces,name',
        ]);

        $province = Province::create([
            'name' => trim($validated['name']),
        ]);

        return response()->json([
            'message' => 'Province created successfully',
            'province' => $province
        ], 201);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/get/all/provinces",
     *     tags={"Provinces"},
     *     summary="Get all provinces",
     *     description="Retrieve a list of all provinces ordered alphabetically",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Response(
     *         response=200,
     *         description="Successful response",
     *         @OA\JsonContent(
     *             @OA\Property(property="total", type="integer", example=3),
     *             @OA\Property(
     *                 property="provinces",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=1),
     *                     @OA\Property(property="name", type="string", example="ABIA"),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function getAllProvincesSuper()
    {
        return response()->json([
            'total' => Province::count(),
            'provinces' => Province::orderBy('name')->get()
        ]);
    }




    /**
     * @OA\Get(
     *     path="/api/v1/get/provinces/{id}",
     *     tags={"Api"},
     *     summary="Get a single province",
     *     description="Retrieve a province by ID including its dioceses",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="Province ID",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Province retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(
     *                 property="province",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="LAGOS"),
     *                 @OA\Property(
     *                     property="dioceses",
     *                     type="array",
     *                     @OA\Items(
     *                         type="object",
     *                         @OA\Property(property="id", type="integer", example=5),
     *                         @OA\Property(property="name", type="string", example="IKEJA"),
     *                         @OA\Property(property="province_id", type="integer", example=1),
     *                         @OA\Property(property="created_at", type="string", format="date-time"),
     *                         @OA\Property(property="updated_at", type="string", format="date-time")
     *                     )
     *                 ),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Province not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Province not found")
     *         )
     *     )
     * )
     */
    public function getSingleProvinceSuperAdmin($id)
    {
        $province = Province::with('dioceses')->find($id);

        if (!$province) {
            return response()->json([
                'status' => false,
                'message' => 'Province not found'
            ], 404);
        }

        return response()->json([
            'status' => true,
            'province' => $province
        ], 200);
    }



    /**
     * @OA\Put(
     *     path="/api/v1/update/province/{id}",
     *     tags={"Api"},
     *     summary="Update a province",
     *     description="Updates the name of a province by ID",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID of the province to update",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"name"},
     *             @OA\Property(
     *                 property="name",
     *                 type="string",
     *                 example="LAGOS",
     *                 description="New unique province name"
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Province updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Province updated successfully"),
     *             @OA\Property(
     *                 property="province",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="LAGOS"),
     *                 @OA\Property(property="created_at", type="string", format="date-time"),
     *                 @OA\Property(property="updated_at", type="string", format="date-time")
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Province not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Province not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="The given data was invalid."),
     *             @OA\Property(
     *                 property="errors",
     *                 type="object",
     *                 example={"name": {"The name has already been taken."}}
     *             )
     *         )
     *     )
     * )
     */
    public function updateProvince(Request $request, $id)
    {
        $province = Province::find($id);

        if (!$province) {
            return response()->json([
                'message' => 'Province not found'
            ], 404);
        }

        // Validate the request
        $validated = $request->validate([
            'name' => 'required|string|unique:provinces,name,' . $province->id,
        ]);

        // Update province
        $province->update($validated);

        return response()->json([
            'status' => true,
            'message' => 'Province updated successfully',
            'province' => $province
        ], 200);
    }



    /**
     * @OA\Delete(
     *     path="/api/v1/delete/province/{id}",
     *     tags={"Api"},
     *     summary="Delete a province",
     *     description="Deletes a province by ID. Cannot delete if there are dioceses linked to it.",
     *     security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="id",
     *         in="path",
     *         required=true,
     *         description="ID of the province to delete",
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Province deleted successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Province deleted successfully")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Province not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Province not found")
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=422,
     *         description="Cannot delete province due to linked dioceses",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Cannot delete province. There are dioceses linked to it.")
     *         )
     *     )
     * )
     */
    public function deleteProvince($id)
    {
        $province = Province::find($id);

        if (!$province) {
            return response()->json([
                'message' => 'Province not found'
            ], 404);
        }

        if ($province->dioceses()->count() > 0) {
            return response()->json([
                'message' => 'Cannot delete province. There are dioceses linked to it.'
            ], 422);
        }

        $province->delete();

        return response()->json([
            'status' => true,
            'message' => 'Province deleted successfully'
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/provinces/{provinceId}/dioceses",
     *     summary="Get dioceses by province",
     *     description="Fetch all dioceses that belong to a specific province",
     *     tags={"Provinces"},
     *   security={{"bearerAuth":{}}},
     *
     *     @OA\Parameter(
     *         name="provinceId",
     *         in="path",
     *         required=true,
     *         description="ID of the province",
     *         @OA\Schema(
     *             type="integer",
     *             example=1
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=200,
     *         description="Dioceses retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=true),
     *             @OA\Property(
     *                 property="province",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="Lagos Province")
     *             ),
     *             @OA\Property(
     *                 property="dioceses",
     *                 type="array",
     *                 @OA\Items(
     *                     type="object",
     *                     @OA\Property(property="id", type="integer", example=2),
     *                     @OA\Property(property="name", type="string", example="Catholic Diocese of Lagos"),
     *                     @OA\Property(property="province_id", type="integer", example=1),
     *                     @OA\Property(property="state", type="string", example="Lagos"),
     *                     @OA\Property(property="lga", type="string", example="Alimosho"),
     *                     @OA\Property(property="address", type="string", example="12 Ipaja Road, Lagos"),
     *                     @OA\Property(property="contact_number", type="string", example="+2348012345678"),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="updated_at", type="string", format="date-time")
     *                 )
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *         response=404,
     *         description="Province not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="boolean", example=false),
     *             @OA\Property(property="message", type="string", example="Province not found")
     *         )
     *     )
     * )
     */

    public function getDiocesesByProvince($provinceId)
    {
        $province = Province::with('dioceses')->find($provinceId);

        if (!$province) {
            return response()->json([
                'status' => false,
                'message' => 'Province not found'
            ], 404);
        }

        return response()->json([
            'status' => true,
            'province' => [
                'id' => $province->id,
                'name' => $province->name
            ],
            'dioceses' => $province->dioceses
        ], 200);
    }



    /**
     * @OA\Get(
     *     path="/api/v1/education-secretary-id",
     *     tags={"Diocese"},
     *     summary="Get Education Secretary for your Diocese",
     *     description="Retrieve the ID and name of the education secretary for the diocesan admin's diocese. Access restricted to diocesan_admin only.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(
     *         response=200,
     *         description="Education Secretary retrieved successfully",
     *         @OA\JsonContent(
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="id", type="integer", example=5),
     *                 @OA\Property(property="name", type="string", example="John Doe")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Unauthorized")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Forbidden. Diocesan admin access only.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=404,
     *         description="Education Secretary not found",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Education Secretary not found for your diocese")
     *         )
     *     )
     * )
     */

    public function getEducationSecretary()
    {
        $user = auth('api')->user();

        if (!$user) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        if ($user->role !== 'diocesan_admin') {
            return response()->json([
                'message' => 'Forbidden. Diocesan admin access only.'
            ], 403);
        }

        // Fetch the education secretary for the diocesan admin's diocese
        $secretary = EducationSecretary::where('diocese_id', $user->diocese_id)->first();

        if (!$secretary) {
            return response()->json([
                'message' => 'Education Secretary not found for your diocese'
            ], 404);
        }

        return response()->json([
            'data' => [
                'id' => $secretary->id,
                'name' => $secretary->name
            ]
        ], 200);
    }



    /**
 * @OA\Get(
 *     path="/api/v1/school/learners/statistics",
 *     summary="Get learner statistics for a school",
 *     description="Returns the total number of learners in the authenticated school admin's school, broken down by gender (male and female).",
 *     tags={"School"},
 *     security={{"bearerAuth":{}}},
 *
 *     @OA\Response(
 *         response=200,
 *         description="Learner statistics retrieved successfully",
 *         @OA\JsonContent(
 *             type="object",
 *             @OA\Property(property="school_id", type="integer", example=4),
 *             @OA\Property(
 *                 property="statistics",
 *                 type="object",
 *                 @OA\Property(property="boys", type="integer", example=23),
 *                 @OA\Property(property="girls", type="integer", example=20),
 *                 @OA\Property(property="total", type="integer", example=43)
 *             )
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=401,
 *         description="Unauthorized",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Unauthorized")
 *         )
 *     ),
 *
 *     @OA\Response(
 *         response=403,
 *         description="Forbidden",
 *         @OA\JsonContent(
 *             @OA\Property(property="message", type="string", example="Forbidden. School admin only.")
 *         )
 *     )
 * )
 */
    public function learnerStatistics(Request $request)
{
    $user = auth('api')->user();

    if (!$user) {
        return response()->json(['message' => 'Unauthorized'], 401);
    }

    // Only school admins
    if ($user->role !== 'school_admin') {
        return response()->json(['message' => 'Forbidden. School admin only.'], 403);
    }

    if (!$user->school_id) {
        return response()->json(['message' => 'No school linked to this account'], 403);
    }

    $schoolId = $user->school_id;

    $stats = Learner::where('school_id', $schoolId)
        ->selectRaw("
            SUM(CASE WHEN gender = 'male' THEN 1 ELSE 0 END) AS boys,
            SUM(CASE WHEN gender = 'female' THEN 1 ELSE 0 END) AS girls,
            COUNT(*) AS total
        ")
        ->first();

    return response()->json([
        'school_id' => $schoolId,
        'statistics' => [
            'boys' => (int) $stats->boys,
            'girls' => (int) $stats->girls,
            'total' => (int) $stats->total
        ]
    ], 200);
}

}
