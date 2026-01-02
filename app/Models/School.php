<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class School extends Model
{
    use HasFactory;

    protected $fillable = [
        'diocese_id',
        'name',
        'email',
        'province',
        'state',
        'lga',
        'address',
        'contact_number',
        'latitude',
        'longitude',
        'class_categories',
        'subjects_offered',
        'logo',
        'latest_news',
    ];

    protected $casts = [
        'class_categories' => 'array',
        'subjects_offered' => 'array',
    ];

    // School ➜ Diocese
    public function diocese()
    {
        return $this->belongsTo(Diocese::class);
    }

    // School ➜ Learners
    public function learners()
    {
        return $this->hasMany(Learner::class);
    }

    // School ➜ Users (School Admins)
    public function users()
    {
        return $this->hasMany(User::class);
    }
}
