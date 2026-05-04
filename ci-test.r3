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

pg-url: any [get-env "PG_URL" "postgres://postgres:password@localhost"]

foreach [title code] [
	"Opening a connection" [
		pg: open as url! pg-url
	]

	"Simple query (get PostgreSQL version)" [
		write pg "SELECT version();"
	]

	"Try select from a non existing table." [
		try/with [write pg {SELECT * FROM nonexistingtable;}] :print
	]
	"Simple query (get list of all databases)" [
		write pg "SELECT datname FROM pg_database WHERE datistemplate = false;"
	]

	"Decode demo (enable via PG_URL query params)" [
		write pg "SELECT 1::int4 AS i, 2::int8 AS b, true::bool AS t, 1.5::float8 AS f, '2023-10-26'::date AS d;"
	]

	"Extended query protocol demo (opt-in via PG_EXT=1)" [
		if "1" = any [get-env "PG_EXT" "0"] [
			;; Unnamed statement/portal
			write pg [EXEC "SELECT $1::int4 AS x, $2::text AS y" [123 "hello"]]

			;; Named prepared statement
			write pg [PREPARE demo "SELECT $1::int4 AS x, $2::text AS y" none]
			write pg [EXECUTE demo [123 "hello"]]
			write pg [DEALLOCATE demo]

			;; Cursor / chunk fetch (should suspend at least once)
			res: write pg [CURSOR g "SELECT generate_series(1, 250) AS x" [] 50]
			while [all [map? res select res 'more?]] [
				res: write pg [FETCH g]
			]
			write pg [CLOSE-CURSOR g]
		]
	]

	"Async query (F1)" [
		done: none
		cb-ok: func [res][
			; basic sanity: should be a map-like result with rows
			done: any [all [map? res 'ok] 'ok]
		]
		cb-err: func [err][
			print ["Async error:" mold err]
			done: 'error
		]
		req: write pg [ASYNC "SELECT 1 AS x" :cb-ok :cb-err]
		; wait until callback flips `done` (or timeout)
		until [
			wait [pg 5]
			not none? done
		]
		if done <> 'ok [
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async test failed: " mold done]]
		]
	]

	"Async queue ordering (F4)" [
		seen: copy []
		done-count: 0
		cb1: func [res][append seen first res/rows done-count: done-count + 1]
		cb2: func [res][append seen first res/rows done-count: done-count + 1]
		cb-err: func [err][
			print ["Async error:" mold err]
			append seen 'error
			done-count: done-count + 1
		]
		write pg [ASYNC "SELECT 1 AS x" :cb1 :cb-err]
		write pg [ASYNC "SELECT 2 AS x" :cb2 :cb-err]
		until [
			wait [pg 10]
			done-count = 2
		]
		if seen <> ["1" "2"] [
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async ordering failed; seen=" mold seen]]
		]
	]

	"Async error recovery (F4)" [
		seen: copy []
		done-count: 0
		cb-ok: func [res][append seen first res/rows done-count: done-count + 1]
		cb-err: func [err][append/only seen err done-count: done-count + 1]
		; error first, then success; connection should remain usable
		write pg [ASYNC {SELECT * FROM nonexistingtable;} :cb-ok :cb-err]
		write pg [ASYNC "SELECT 3 AS x" :cb-ok :cb-err]
		until [
			wait [pg 10]
			done-count = 2
		]
		if any [
			not error? first seen
			second seen <> "3"
		][
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async error recovery failed; seen=" mold seen]]
		]
	]

	"Async streaming rows (F2)" [
		rows-seen: 0
		done: none
		cb-row: func [row][
			rows-seen: rows-seen + 1
		]
		cb-ok: func [res][
			done: 'ok
		]
		cb-err: func [err][
			print ["Async stream error:" mold err]
			done: 'error
		]
		write pg [ASYNC-STREAM "SELECT generate_series(1, 250) AS x" :cb-row :cb-ok :cb-err]
		until [
			wait [pg 10]
			not none? done
		]
		if any [done <> 'ok rows-seen <> 250] [
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async stream failed; done=" mold done " rows=" rows-seen]]
		]
	]

	"Async streaming rows chunked via portal (F2)" [
		rows-seen: 0
		done: none
		cb-row: func [row][
			rows-seen: rows-seen + 1
		]
		cb-ok: func [res][
			done: 'ok
		]
		cb-err: func [err][
			print ["Async stream(chunked) error:" mold err]
			done: 'error
		]
		; last argument is max-rows per fetch
		write pg [ASYNC-STREAM "SELECT generate_series(1, 250) AS x" :cb-row :cb-ok :cb-err 50]
		until [
			wait [pg 10]
			not none? done
		]
		if any [done <> 'ok rows-seen <> 250] [
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async stream(chunked) failed; done=" mold done " rows=" rows-seen]]
		]
	]

	"Async streaming on-complete hook (F2)" [
		done: none
		completed: none
		cb-row: func [row][none]
		cb-ok: func [res][done: 'ok]
		cb-err: func [err][done: 'error]
		cb-complete: func [res][completed: res/command-tag]
		write pg [ASYNC-STREAM "SELECT 1 AS x" :cb-row :cb-ok :cb-err :cb-complete]
		until [
			wait [pg 10]
			not none? done
		]
		if any [done <> 'ok none? completed] [
			cause-error 'Access 'Protocol reduce ['message ajoin ["Async on-complete failed; done=" mold done " completed=" mold completed]]
		]
	]

	"LISTEN/NOTIFY delivery (F4)" [
		pg2: open as url! pg-url
		got: none
		listener: func [evt][got: evt]
		pgsql/listen pg "ci_chan" :listener
		; send from second session
		write pg2 {NOTIFY ci_chan, 'hello-ci';}
		until [
			wait [pg 10]
			not none? got
		]
		if any [
			not map? got
			select got 'channel <> "ci_chan"
			select got 'payload <> "hello-ci"
		][
			cause-error 'Access 'Protocol reduce ['message ajoin ["NOTIFY test failed; got=" mold got]]
		]
		close pg2
	]

	"CancelRequest (G)" [
		done: none
		cb-ok: func [res][done: 'ok]
		cb-err: func [err][done: err]
		write pg [ASYNC "SELECT pg_sleep(10);" :cb-ok :cb-err]
		; give the query a moment to start
		wait 0:0:0.2
		; cancel inflight query
		unless pgsql/cancel pg [
			cause-error 'Access 'Protocol reduce ['message "CancelRequest did not send"]
		]
		until [
			wait [pg 15]
			not none? done
		]
		if any [
			done = 'ok
			not map? done
			; usually 57014 query_canceled
			all [select done 'sql-state select done 'sql-state <> "57014"]
		][
			cause-error 'Access 'Protocol reduce ['message ajoin ["CancelRequest failed; done=" mold done]]
		]
		; connection should remain usable
		write pg "SELECT 1 AS x"
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
