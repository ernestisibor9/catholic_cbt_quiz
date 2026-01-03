<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Diocese extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'province',
        'state',
        'lga',
        'address',
        'contact_number',
        'logo',
        'education_secretary',
    ];

    // Diocese has many Schools
    public function schools()
    {
        return $this->hasMany(School::class);
    }

    public function users()
    {
        return $this->hasMany(User::class);
    }
}
