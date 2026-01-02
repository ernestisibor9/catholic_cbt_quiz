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
        Schema::create('schools', function (Blueprint $table) {
            $table->id();
            $table->foreignId('diocese_id')
                ->constrained()
                ->cascadeOnDelete();

            $table->string('name')->unique(); // FULL NAME IN UPPERCASE
            $table->string('email')->unique();

            $table->string('province');
            $table->string('state');
            $table->string('lga');

            $table->string('address')->nullable();
            $table->string('contact_number')->nullable();

            $table->decimal('latitude', 10, 7)->nullable();
            $table->decimal('longitude', 10, 7)->nullable();

            $table->json('class_categories')->nullable();
            $table->json('subjects_offered')->nullable();

            $table->string('logo')->nullable();
            $table->text('latest_news')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('schools');
    }
};
