# FastAPI CRUD with User Registration and Item Management

This is a simple FastAPI application that provides User Registration and Item Management functionality. Users can register, and once registered, they can use the CRUD (Create, Read, Update, Delete) operations for items.

## Features

- User registration: Users can register with a username, email, full name, and password.
- Authentication: Users are required to provide a username and password for CRUD operations.
- Item Management: Users can perform CRUD operations on items (Create, Read, Update, Delete).
- Secure Password Storage: Passwords are securely hashed using the bcrypt algorithm.
- JWT Token: The application initially used JWT tokens for authentication, but it has been modified to accept username and password for each request.

## Prerequisites

- Python 3.7 or later
- FastAPI
- SQLAlchemy
- Passlib (for password hashing)
- jose (for JWT tokens, but not used in the modified code)
- Other dependencies mentioned in the code

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   ```
   
1. Install the required dependencies:

   ```bash
   pip install fastapi[all]
   pip install sqlalchemy passlib jose python-dotenv
   ```
   
3. Set environment variables:

Create a .env file in the project root directory with the following variables:

DATABASE_URL: Database URL for SQLAlchemy connection.
SECRET_KEY: Secret key for JWT tokens (not used in the modified code).

4. Run the application:

   ```bash
    uvicorn main:app --reload
   ```
   
5. Access the application in your browser at http://localhost:8000/docs. You can use the Swagger documentation 
to test the API.

Usage
Register a user:

Send a POST request to /register/ with a JSON payload containing a unique username, email, full name, and password.

Authenticate with your username and password for CRUD operations. You can pass your username and password as parameters in the URL or in the request body, as shown in the Swagger documentation.

Use the CRUD endpoints to manage items:

POST /items/: Create a new item.
GET /items/{item_id}: Retrieve an item by ID.
GET /items/: Retrieve all items.
PUT /items/{item_id}: Update an item by ID.
DELETE /items/{item_id}: Delete an item by ID.
Items are simple objects with a name, description, price, and quantity.

Customization
You can customize this application by adding more features, improving authentication, and enhancing the item management functionality.

License
This project is licensed under the MIT License.

Acknowledgments
This project was created with FastAPI.

   ```
    Make sure to replace `<repository-url>` with the actual URL or path to your repository. This README provides an overview of the application, its features, prerequisites, installation instructions, usage guidelines, customization options, and licensing information.
   ```

