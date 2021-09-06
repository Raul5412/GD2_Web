<?php

namespace App\Http\Controllers\Bank;

use App\Http\Controllers\Controller;
use App\Models\Account;

use Illuminate\Http\Request;

class AccountsController extends Controller
{
    /**
     * Show index page
     *
     * @return \Illuminate\Http\Response
     */
    public function index() {
        $accounts = auth()->user()->accounts;
        return view('bank.accounts.index', compact('accounts'));
    }

    /**
     * Show create page
     *
     * @return \Illuminate\Http\Response
     */
    public function create() {
        return view('bank.accounts.create');
    }

    /**
     * Show create page
     *
     * @return \Illuminate\Http\Response
     */
    public function store(Request $req) {
        $data = $req->validate(['name' => 'required']);
        $data['user_id'] = auth()->user()->id;

        Account::create($data);
        return redirect()->route('bank.accounts.index');
    }
}
