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
        'session_id',
        'term_id',
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


    public function session()
    {
        return $this->belongsTo(Session::class);
    }

    public function term()
    {
        return $this->belongsTo(Term::class);
    }

    // Learner ➜ User
    public function user()
    {
        return $this->hasOne(User::class);
    }
}
