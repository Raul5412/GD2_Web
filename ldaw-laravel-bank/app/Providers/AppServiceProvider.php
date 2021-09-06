<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Carbon;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if(!Carbon::hasMacro('cloneToLocalTimezone')){
            Carbon::macro('cloneToLocalTimezone', function () {
                $tz = config('app.local_timezone');
                return $this->clone()->setTimezone($tz);
            });
        }
    }
}
