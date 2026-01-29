<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Learner extends Model
{
    use HasFactory;

    protected $fillable = [
        'school_id',
        'surname',
        'first_name',
        'middle_name',
        'dob',
        'session',
        'religion',
        'residential_address',
        'state_of_origin',
        'lga_of_origin',
        'previous_class',
        'present_class',
        'nin',
        'parent_name',
        'parent_relationship',
        'parent_phone',
        'photo',
    ];

    // Learner ➜ School
    public function school()
    {
        return $this->belongsTo(School::class);
    }

    public function diocese()
    {
        return $this->belongsTo(Diocese::class);
    }

    // Learner ➜ User
    public function user()
    {
        return $this->hasOne(User::class);
    }
}
