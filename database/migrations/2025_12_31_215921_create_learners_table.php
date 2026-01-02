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
        Schema::create('learners', function (Blueprint $table) {
            $table->id();
            $table->foreignId('school_id')
                ->constrained()
                ->cascadeOnDelete();

            $table->string('surname');
            $table->string('first_name');
            $table->string('middle_name')->nullable();

            $table->date('dob');
            $table->string('religion')->nullable();

            $table->string('residential_address')->nullable();
            $table->string('state_of_origin')->nullable();
            $table->string('lga_of_origin')->nullable();

            $table->string('previous_class')->nullable();
            $table->string('present_class');

            $table->string('nin')->nullable();

            $table->string('parent_name')->nullable();
            $table->string('parent_relationship')->nullable();
            $table->string('parent_phone')->nullable();

            $table->string('photo')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('learners');
    }
};
