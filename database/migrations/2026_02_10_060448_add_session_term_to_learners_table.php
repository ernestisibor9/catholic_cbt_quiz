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
        Schema::table('learners', function (Blueprint $table) {
            //
            $table->unsignedBigInteger('session_id')->nullable()->after('present_class');
            $table->unsignedBigInteger('term_id')->nullable()->after('session_id');

            $table->foreign('session_id')->references('id')->on('sessions')->onDelete('set null');
            $table->foreign('term_id')->references('id')->on('terms')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('learners', function (Blueprint $table) {
            //
            $table->dropForeign(['session_id']);
            $table->dropForeign(['term_id']);
            $table->dropColumn(['session_id', 'term_id']);
        });
    }
};
