<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Diocese extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'province_id',
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

    public function educationsecretary()
    {
        return $this->hasMany(EducationSecretary::class);
    }

    // Diocese has many Learners through Schools
    public function learners()
    {
        return $this->hasManyThrough(
            \App\Models\Learner::class, // final model
            \App\Models\School::class,  // intermediate model
            'diocese_id',                // Foreign key on schools table
            'school_id',                 // Foreign key on learners table
            'id',                        // Local key on dioceses table
            'id'                         // Local key on schools table
        );
    }

    public function province()
    {
        return $this->belongsTo(Province::class);
    }

    public function users()
    {
        return $this->hasMany(User::class);
    }
}
