<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class HomepageController extends Controller
{
    public function index() {

        if (auth()->user() !== null) {
            return redirect()->route('bank.dashboard.index');
        }

        return view('homepage.index');
    }
}
