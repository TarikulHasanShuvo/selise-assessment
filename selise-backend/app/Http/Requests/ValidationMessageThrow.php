<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Http\Exceptions\HttpResponseException;

class ValidationMessageThrow
{
    /**
     * @param Validator $validator
     */
    public static function sendMessages(Validator $validator)
    {
        $response = response()->json([
            'message' => 'Invalid data send',
            'details' => $validator->errors()->messages(),
        ], 422);

        throw new HttpResponseException($response);
    }
}
