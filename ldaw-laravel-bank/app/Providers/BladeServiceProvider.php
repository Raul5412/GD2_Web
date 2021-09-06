<?php

namespace App\Providers;

use Illuminate\Support\Facades\Blade;
use Illuminate\Support\ServiceProvider;

class BladeServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Remember to clear the views in case you add a new directive
        // php artisan view:clear
        $this->addDatetimeDirective();
        $this->addMoneyDirective();
    }

    /**
     * Add date time directive
     *
     * @return void
     */
    private function addDatetimeDirective() {
        Blade::directive('datetime', function($expression) {
            return "<?php echo ($expression)->format('Y-m-d H:i:s'); ?>";
        });
    }

    /**
     * Add money directive
     *
     * @return void
     */
    private function addMoneyDirective() {
        Blade::directive('money', function($expression) {
            return "<?php echo('$ ' . number_format($expression, 2)); ?>";
        });
    }
}
