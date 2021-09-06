<?php

namespace App\Models;

use App\Traits\CreateUpdateToLocalTimezoneTrait;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Movement extends Model
{
    use CreateUpdateToLocalTimezoneTrait, HasFactory;

    const WITHDRAW = 1;
    const DEPOSIT = 2;

    public $fillable = [
        'type',
        'description',
        'before_balance',
        'amount',
        'after_balance',
        'account_id',
    ];

    /**
     * Account relationship
     */
    public function account() {
        return $this->belongsTo(Account::class);
    }

    /**
     * Retrieve the amount divided by 100 since
     * the system stores the amount in cents
     *
     * @return float
     */
    public function getDecimalAmountAttribute() : float {
        return $this->amount / 100;
    }

    /**
     * Retrieves a readable type description
     *
     * @return string
     */
    public function getReadableTypeAttribute() : string {
        $response = 'desconocido';
        switch ($this->type) {
            case self::WITHDRAW:
                $response = 'Retiro';
                break;
            case self::DEPOSIT:
                $response = 'Depósito';
                break;
        }
        return $response;
    }

    /**
     * Create movement in the given account
     *
     * @param Account $account
     * @param integer $amount
     * @param integer|null $type if not set, if the amount is below 0 then it will be set to
     * Movement withdraw else as movement deposit
     * @param string|null $description
     * @return Movement
     */
    public static function Register(Account $account, int $amount, string $description = null, int $type = null) : Movement {
        $data = [];
        if ($type === null) {
            $type = $amount < 0 ? Movement::WITHDRAW : Movement::DEPOSIT;
        }
        $amount = abs($amount);
        $data['type'] = $type;
        $data['description'] = $description;
        $data['before_balance'] = $account->current_balance;
        $data['amount'] = $amount;
        $factor = $type === Movement::DEPOSIT ? 1 : - 1;
        $data['after_balance'] = $account->current_balance + $amount * $factor;
        $data['account_id'] = $account->id;
        // Creates the movement
        $movement = Movement::create($data);
        // Update the account current balance
        $account->current_balance = $movement->after_balance;
        $account->save();
        return $movement;
    }
}
