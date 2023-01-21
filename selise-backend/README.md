## Backend Installation

### Clone the repository

    git clone https://github.com/TarikulHasanShuvo/selise-assessment.git

### Switch to the repo folder

    cd selise-assessment/selise-backend

### Install all the dependencies using composer

    composer install

### Copy the example env file and make the required configuration changes in the .env file

    cp .env.example .env

### Database configuration

    DB_DATABASE=your_database_name
    DB_USERNAME=your_user_name
    DB_PASSWORD=your_password

### Generate a new application key

    php artisan key:generate


### Create table & dummy data from seeder

    php artisan migrate --seed


### Start the local development server

    php artisan serve

### Credentials

    User Panel 
    ======================
    Email: admin@gmail.com 
    Password: 1234678

### App URL

    http://localhost:8000
