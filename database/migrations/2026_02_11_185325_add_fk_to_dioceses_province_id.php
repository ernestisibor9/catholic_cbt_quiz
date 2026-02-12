<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('dioceses', function (Blueprint $table) {
            //
            $table->unsignedBigInteger('province_id')->nullable(false)->change();

            $table->foreign('province_id')
                ->references('id')
                ->on('provinces')
                ->cascadeOnDelete();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('dioceses', function (Blueprint $table) {
            //
        });
    }
};
