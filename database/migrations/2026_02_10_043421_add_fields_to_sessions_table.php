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
        Schema::table('sessions', function (Blueprint $table) {
            //
            $table->date('start_date')->nullable()->after('name');
            $table->date('end_date')->nullable()->after('start_date');
            $table->enum('status', ['active', 'inactive'])
                ->default('inactive')
                ->after('end_date');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('sessions', function (Blueprint $table) {
            //
            $table->dropColumn(['start_date', 'end_date', 'status']);
        });
    }
};
