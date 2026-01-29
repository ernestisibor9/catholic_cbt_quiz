<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('dioceses', function (Blueprint $table) {
            //
            $table->unique('contact_number');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('dioceses', function (Blueprint $table) {
            //
             $table->dropUnique(['contact_number']);
        });
    }
};
