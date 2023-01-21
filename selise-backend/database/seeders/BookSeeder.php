<?php

namespace Database\Seeders;

use App\Models\Book;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class BookSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        Book::insert([
            [
                'name' => 'পাইথন দিয়ে প্রোগ্রামিং',
                'author_name' => 'তামিম শাহরিয়ার সুবিন',
                'price' => 300,
                'discount_price' => 258,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/6f3aabfa2_150795.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'হাতেকলমে পাইথন ডিপ লার্নিং',
                'author_name' => 'রকিবুল হাসান',
                'price' => 700,
                'discount_price' => 650,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/072309788_198757.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'পাইথন দিয়ে প্রোগ্রামিং',
                'author_name' => 'তামিম শাহরিয়ার সুবিন',
                'price' => 250,
                'discount_price' => 215,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/dfb303496d64_143309.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'প্রোগ্রামিং এসেনশিয়ালস',
                'author_name' => 'তাহমিদ রাফি',
                'price' => 300,
                'discount_price' => 258,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/913da2e28_150338.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'পাইথন প্রোগ্রামিং 3.10',
                'author_name' => 'জাকির হোসাইন',
                'price' => 340,
                'discount_price' => 298,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/Python_Programming_310-Zakir_Hossain-0ad51-226630.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'পাইথন প্রোগ্রামিং ফর লিটল স্টারস',
                'author_name' => 'ইয়াসির আরাফাত রাতুল',
                'price' => 300,
                'discount_price' => 258,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/Python_Programming_for_Little_Stars-Yeasir_Arafat_Ratul-6bac6-249796.jpeg',
                'created_at' => now(),
            ],
            [
                'name' => 'পাইথন প্রোগ্রামিং ফাউন্ডেশন',
                'author_name' => 'মোহাম্মদ মিজানুর রহমান (নয়ন)',
                'price' => 280,
                'discount_price' => 258,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/4d86bc9c3574_129453.jpg',
                'created_at' => now(),
            ],
            [
                'name' => 'সহজ ভাষায় পাইথন',
                'author_name' => ' মাকসুদুর রহমান মাটিন',
                'price' => 400,
                'discount_price' => 322,
                'image' => 'https://ds.rokomari.store/rokomari110/ProductNew20190903/260X372/1412d18a3_127980.jpg',
                'created_at' => now(),
            ],
        ]);
    }
}
