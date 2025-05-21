**DODOPAYMENTS PROJECT**

This project contains:
- Webservice for User login, registration, and transactions.
- Uses postgres database
- Includes test cases (Incomplete)

**HOW TO SETUP:**
- Make sure you have postgres database installed.
- Change username and password in `.env file` related to postgres database

- To create database and tables use following commands.
   - `psql -U your_username -h localhost -c "CREATE DATABASE auth_db;`
   - `psql -U your_username -h localhost -c "CREATE DATABASE auth_db_test;`

- Run migrations/01_create_tables.sql and migrations/testsetup.sql to create tables for prod and testing
   - use `psql -h localhost  -U your_username -d auth_db -f 01_create_tables.sql`
   - use `psql -h localhost  -U your_username -d auth_db_test -f test_setup.sql`

- Use cargo run to startup the webservice. Server starts on localhost:8080
- Use following sample commands from terminal for basic testing.
   -   `curl -X POST http://localhost:8080/api/register -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}'`
   -   `curl -X POST http://localhost:8080/api/login -H "Content-Type: application/json" -d '{"username":"testuser","password":"testpass"}'`
   -   Use the token received after login to access further endpoints
   -   To create a new transaction :
      -  `curl -X POST http://localhost:8080/api/transactions -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"amount":101.50,"description":"Grocery shoppxxing","transaction_type":"DEPOSIT"}'`
   -   To get transactions
      -  `curl -X GET http://localhost:8080/api/transactions  -H "Authorization: Bearer <token>"`



**DISCLAIMER:**
- Test cases are written for various api endpoints but many of them are failing, it needs more work to be done.

