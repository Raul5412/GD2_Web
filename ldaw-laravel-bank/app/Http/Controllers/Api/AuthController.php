<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Account;
use App\Models\Movement;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Creates a user in the system
     *
     * @return \Illuminate\Http\Response
     */
    public function saveUser(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|unique:users,email',
            'password' => 'required'
        ]);

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        return response()->json([
            'message' => 'Successfully created user!'
        ], 201);
    }

    /**
     * Login the user and retrieve the token
     *
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required'],
        ]);

        $credentials = request(['email', 'password']);

        if (!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        }

        $user = auth()->user();
        $tokenResult = $user->createToken('Personal Access Token');

        $token = $tokenResult->token;
        if ($request->remember_me) {
            $token->expires_at = Carbon::now()->addWeeks(1);
        }

        $token->save();

        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($token->expires_at)->toDateTimeString()
        ]);
    }

    /**
     * Create account
     *
     * @return \Illuminate\Http\Response
     */
    public function saveAccount(Request $request){
        $request->validate([
            'name' => 'required'
        ]);

        Account::create([
            'name' => $request->name,
            'user_id' => auth()->user()->id
        ]);

        return response()->json([
            'message' => 'Successfully created account!'
        ], 201);
    }


    /**
     * Get accounts information 
     *
     * @return \Illuminate\Http\Response
     */
    public function accountInfo(Request $request, $account){
        $accountInfo = Account::select("*")->where("account_number", $account)->get();

        return response()->json($accountInfo);
    }

    /**
     * Create movement
     *
     * @return \Illuminate\Http\Response
     */
    public function saveMovement(Request $request, $account){
        $request->validate([
            'amount' => 'required',
            'description' => 'required',
            'type' => 'required'
        ]);

        $balance = \App\Models\Account::where("account_number", $account)->pluck('current_balance');
        $accountId = \App\Models\Account::where("account_number", $account)->pluck('id');
        $after = 0;

        if( $request->type == 1):
            $after = $balance[0] - $request->amount;
        else:
            $after = $balance[0] + $request->amount;
        endif;

        Movement::create([
            'type' => $request->type,
            'description' => $request->description,
            'before_balance' => $balance[0],
            'amount' => $request->amount,
            'after_balance'=> $after,
            'account_id'=> $accountId[0]
        ]);

        return response()->json([
            'message' => 'Successfully created movement!'
        ], 201);
    }

    /**
     * Logs the user out
     *
     * @return \Illuminate\Http\Response
     */
    public function logout(Request $request)
    {
        auth()->user()->token()->revoke();

        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Retrivest the user information
     *
     * @return \Illuminate\Http\Response
     */
    public function user(Request $request)
    {
        return response()->json(auth()->user());
    }
}
