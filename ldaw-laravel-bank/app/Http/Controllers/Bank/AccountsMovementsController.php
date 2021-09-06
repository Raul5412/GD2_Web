<?php

namespace App\Http\Controllers\Bank;

use App\Http\Controllers\Controller;
use App\Models\Account;
use App\Models\Movement;
use Illuminate\Http\Request;

class AccountsMovementsController extends Controller
{

    /**
     * Shows the index page.
     *
     * @param  \App\Models\Account
     * @return \Illuminate\Http\Response
     */
    public function index(Request $rec, Account $account) {
        $movements = $account->movements()
            ->orderBy('id', 'desc')
            ->get();
        return view('bank.accounts-movements.index', compact('account', 'movements'));
    }

    /**
     * Shows the create page.
     *
     * @param  \App\Models\Account
     * @return \Illuminate\Http\Response
     */
    public function create(Request $req, Account $account)
    {
        return view('bank.accounts-movements.create', compact('account'));
    }

    /**
     * Stores the movement
     *
     * @param Request $req
     * @param Account $account
     * @return \Illuminate\Http\Response
     */
    public function store(Request $req, Account $account) {
        $data = $req->validate(['amount' => 'required|numeric', 'description' => 'nullable']);
        $amount = $data['amount'] * 100;
        Movement::Register($account, $amount, $data['description']);
        return redirect()->route('bank.accounts.index');
    }
}
