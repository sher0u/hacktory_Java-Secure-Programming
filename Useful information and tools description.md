# Useful information and tools description
Here is the clean Markdown code for your `.md` file. Just copy and paste this into any `.md` file (for example, `linux_cheatsheet.md`):

````markdown
# 🐧 Useful Information and Tools — Linux CLI

## 📁 1. `cd` — Change Directory
Changes the current working directory.

### **Examples**
```bash
cd Desktop/Tools   # Go to Desktop/Tools directory
cd ~               # Go to home directory
````

---

## 📌 2. `pwd` — Print Working Directory

Displays the current working directory path.

### **Example**

```bash
admin@ip-10-0-1-11:~$ pwd
/home/admin
```

---

## 📂 3. `ls` — List Directory Contents

Lists files and directories.

### **Useful Options**

* `-a` or `--all` – Show all files (including hidden)
* `-d` or `--directory` – Show directory info instead of contents
* `-F` or `--classify` – Append indicators to entries
* `-h` or `--human-readable` – Human-readable file sizes
* `-l` – Long listing format

---

## 💬 4. `echo` — Print Line of Text

Outputs text to the terminal.

### **Example**

```bash
admin@ip-10-0-1-11:~$ echo HELLO
HELLO
```

---

## 📖 5. `cat` — Concatenate and Display Files

Prints the contents of a file to the terminal.

### **Example**

```bash
admin@ip-10-0-1-11:~$ echo HELLO > test.txt
admin@ip-10-0-1-11:~$ cat test.txt
HELLO
```

---

## 🔍 6. `find` — Search for Files and Directories

Finds files or directories based on various criteria.

### **Useful Options**

* `-name pattern` – Search by name
* `-nouser` – Files with no owner
* `-nogroup` – Files with no group
* `-size n` – Files of specific size
* `-type c` – Search by type (e.g. `f` for file, `d` for directory)
* `-user name` – Owned by a specific user

### **Examples**

```bash
find . -name test.txt
./test.txt

find /home -name test.txt
/home/admin/test.txt
```

---

## 🔎 7. `grep` — Search Inside Files

Searches for patterns in file contents.

### **Useful Options**

* `-i` or `--ignore-case` – Case-insensitive search
* `-r` – Recursive search

### **Examples**

```bash
grep HELLO test.txt
HELLO

grep -r HELLO .
test.txt:HELLO
```

---

## 📄 8. `cp` — Copy Files and Directories

Copies files from one location to another.

### **Example**

```bash
cp test.txt test2.txt
ls test*
# Output: test2.txt test.txt
```

---

## 🔀 9. `mv` — Move or Rename

Moves or renames files and directories.

### **Example**

```bash
mv test.txt newfile.txt
ls -la newfile.txt
# Output:
# -rwxrwxrwx 1 admin admin 6 Sep 13 09:41 newfile.txt
```

---

## 🗑️ 10. `rm` — Remove Files and Directories

Deletes files or directories permanently.

### ⚠️ Warning:

* There is **no undo** for this action.
* Be cautious: `rm * .html` (with a space) will remove **all files** and then return an error.

### **Example**

```bash
ls
# Output: BurpSuiteCommunity Desktop Downloads newfile.txt Pictures test2.txt

rm -f test2.txt
rm -f newfile.txt
ls
# Output: BurpSuiteCommunity Desktop Downloads Pictures
```

---

### ✅ Tip:

Use `man <command>` to get more detailed info on any command:

```bash
man ls
```

```

Let me know if you’d like this in PDF or HTML too!
```

