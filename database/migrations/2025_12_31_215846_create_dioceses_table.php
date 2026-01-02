<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('dioceses', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique(); // FULL NAME IN UPPERCASE
            $table->string('province');
            $table->string('state');
            $table->string('lga');
            $table->string('address');
            $table->string('contact_number');

            $table->string('logo')->nullable();
            $table->string('education_secretary')->nullable();
            $table->text('latest_news')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('dioceses');
    }


    public function update(Request $request)
{
    $diocese = auth()->user()->diocese;

    if (!$diocese) {
        return response()->json([
            'message' => 'No diocese linked to this account'
        ], 403);
    }

    $validated = $request->validate([
        'province' => 'required|string',
        'state' => 'required|string',
        'lga' => 'required|string',
        'address' => 'required|string',
        'contact_number' => 'required|string',
        'education_secretary' => 'nullable|string',
        'latest_news' => 'nullable|string',
        'logo' => 'nullable|image|mimes:png,jpg,jpeg|max:2048',
    ]);

    /** Handle Logo Upload */
    if ($request->hasFile('logo')) {

        // delete old logo if exists
        if ($diocese->logo) {
            Storage::disk('public')->delete($diocese->logo);
        }

        $validated['logo'] = $request->file('logo')
            ->store('diocese_logos', 'public');
    }

    $diocese->update($validated);

    return response()->json([
        'message' => 'Diocese profile updated successfully',
        'diocese' => $diocese
    ]);
}


};
