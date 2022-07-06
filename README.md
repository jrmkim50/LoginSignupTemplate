# LoginSignupTemplate

## Important files and folders

### Main.go
Run this file to start the web server and connect to the mysql database.

### dbhelper
Contains code to connect to the database and query the database.

### routes
Contains code that sets up the web server's routes. 

### utils
Contains helper functions to do things like hash a password, parse a JWT, etc.

### middlewares
Contains a middleware to check the validity of a JWT.

### models
Specifies each database table's structures.

### .env-TEMPLATE
Fill in this file with your corresponding credentials.
