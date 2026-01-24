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
        Schema::create('education_secretaries', function (Blueprint $table) {
            $table->id();
                        $table->foreignId('diocese_id')
                ->constrained()
                ->cascadeOnDelete();

            $table->string('name')->unique(); // FULL NAME IN UPPERCASE
            $table->string('email')->unique();

            $table->string('phone');
            $table->string('years_of_service')->nullable();

            $table->string('office_location')->nullable();

            $table->text('biography')->nullable();
            $table->text('education_background')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('education_secretaries');
    }
};
