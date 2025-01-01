<?php
namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\Controller;
use Laravel\Passport\HasApiTokens;

class UserController extends Controller
{
    /**
     * Handle user registration
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        // Validate the request
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        // Create the user
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        // Return success response with the user data (without password)
        return response()->json(['user' => $user], 201);
    }

    /**
     * Handle user login and generate API token
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        // Validate login request
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        // Find the user by email
        $user = User::where('email', $request->email)->first();

        // Check if user exists and password is correct
        if (!$user || !\Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // Generate personal access token using Passport
        $token = $user->createToken('tabish')->accessToken;

        // Return the token in the response
        return response()->json([
            'token' => $token,
            'user' => $user
        ]);
    }

    /**
     * Get the authenticated user details
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userDetails()
    {
        // Return the authenticated user's details
        return response()->json(Auth::user());
    }
}
