<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class EducationSecretary extends Model
{
    use HasFactory;

        protected $fillable = [
        'diocese_id',
        'name',
        'email',
        'phone',
        'years_of_service',
        'office_location',
        'biography',
        'education_background',
    ];

        public function diocese()
    {
        return $this->belongsTo(Diocese::class);
    }
}
