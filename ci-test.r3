Rebol [
	title: "SQLite extension test"
	needs:  3.13.1 ;; using system/options/modules as extension location
]

print ["Running test on Rebol build:" mold to-block system/build]

system/options/quiet: false
system/options/log/rebol: 4

;; make sure that we load a fresh extension
try [system/modules/postgres: none]

pgsql: import %postgres.reb

system/options/log/postgres: 3

foreach [title code] [
	"Opening a connection" [
		pg: open postgres://postgress:password@localhost
	]

	"Simple query (get PostgreSQL version)" [
		write pg "SELECT version();"
	]

	"Simple query (get list of all databases)" [
		write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
	]

	"Creating test tables" [
		write pg {
BEGIN;

-- Cleanup test tables
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS posts CASCADE;
DROP TABLE IF EXISTS data_types_test;
DROP TABLE IF EXISTS check_constraint_test;
DROP TABLE IF EXISTS not_null_test;

-- Create a simple table
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    age INTEGER CHECK (age >= 0),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create another table with a foreign key
CREATE TABLE posts (
    post_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id),
    title VARCHAR(200) NOT NULL,
    content TEXT,
    posted_at TIMESTAMP DEFAULT NOW()
);

-- Create a table with different data types.
CREATE TABLE data_types_test(
    id SERIAL PRIMARY KEY,
    small_int SMALLINT,
    integer_val INTEGER,
    big_int BIGINT,
    decimal_val DECIMAL(10,2),
    numeric_val NUMERIC(15,5),
    real_val REAL,
    double_precision_val DOUBLE PRECISION,
    char_val CHAR(10),
    varchar_val VARCHAR(255),
    text_val TEXT,
    date_val DATE,
    time_val TIME,
    timestamp_val TIMESTAMP,
    boolean_val BOOLEAN,
    json_val JSON
);

--create a table to test a check constraint.
CREATE TABLE check_constraint_test(
    id SERIAL PRIMARY KEY,
    value INTEGER CHECK (value > 10)
);

--create a table to test a not null constraint.
CREATE TABLE not_null_test(
    id SERIAL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
);

-- Insert sample data into the users table
INSERT INTO users (username, email, age) VALUES
    ('john_doe', 'john.doe@example.com', 30),
    ('jane_smith', 'jane.smith@example.com', 25),
    ('peter_jones', 'peter.jones@example.com', 40);

-- Insert sample data into the posts table
INSERT INTO posts (user_id, title, content) VALUES
    (1, 'First Post', 'This is my first post.'),
    (1, 'Another Post', 'Some more content.'),
    (2, 'Janes Blog', 'Welcome to my blog.');

-- Insert sample data into data_types_test table
INSERT INTO data_types_test (small_int, integer_val, big_int, decimal_val, numeric_val, real_val, double_precision_val, char_val, varchar_val, text_val, date_val, time_val, timestamp_val, boolean_val, json_val) VALUES
    (10, 1000, 1000000000, 123.45, 98765.43210, 3.14, 2.71828, 'test', 'test varchar', 'test text', '2023-10-26', '12:30:00', '2023-10-26 12:30:00', true, '{"key": "value"}');

--Insert data to test check constraint.
INSERT INTO check_constraint_test (value) VALUES (15);

--Insert data to test not null constraint.
INSERT INTO not_null_test (value) VALUES ('test value');
COMMIT;}
	]
	
	"Test query" [
		write pg "SELECT * FROM users;"
	]
	"Test query" [
		write pg "SELECT * FROM posts WHERE user_id = 1;"
	]

	"Sending a SYNC message" [
		write pg 'SYNC
	]

	"Trying to call a not existing function (error expected)" [
		write pg "SELECT unknown_function();"
	]

	"Closing the connection" [
		close pg
	]

	"Testing that the connection is closed" [
		open? pg
	]

	"Trying to write to the closed connection (error expected)" [
		write pg "SELECT version();"
	]

	"Reopening the connection" [
		pg: open pg
	]

	"Sending a TERMINATE message" [
		write pg 'TERMINATE
	]

][
	prin LF
	print-horizontal-line
	print as-yellow join ";; " title
	prin as-red ">> "
	print as-white mold/only code
	set/any 'result try code
	either error? :result [
		print result
	][
		print as-green ellipsize ajoin ["== " mold :result] 300
	]
]


print "DONE"