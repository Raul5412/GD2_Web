<?php

if (!function_exists('nowLocal')) {
    /**
     * Carbon instance of the current local time zone
     * @return \Illuminate\Support\Carbon
     */
    function nowLocal() : \Illuminate\Support\Carbon {
        return \Illuminate\Support\Carbon::now(config('app.local_timezone'));
    }
}
