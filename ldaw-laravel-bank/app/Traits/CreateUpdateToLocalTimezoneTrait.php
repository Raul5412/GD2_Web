<?php
namespace App\Traits;

trait CreateUpdateToLocalTimezoneTrait {
    /**
     * Converts the created at attribute to local time zone
     *
     * @return \Illuminate\Support\Carbon
     */
    public function getLocalCreatedAtAttribute() : \Illuminate\Support\Carbon {
        return $this->created_at->cloneToLocalTimezone();
    }

    /**
     * Converts the created at attribute to local time zone
     *
     * @return \Illuminate\Support\Carbon
     */
    public function getLocalUpdatedAtAttribute() : \Illuminate\Support\Carbon {
        return $this->updated_at->cloneToLocalTimezone();
    }
}
