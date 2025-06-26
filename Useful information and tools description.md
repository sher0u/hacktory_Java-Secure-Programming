# Useful information and tools description
## Theory:
### Linux:
#### **cd**
 Changes directory.
#### **pwd**
Prints the current working directory.
#### **ls**
Lists files.
#### **echo**
Prints line of text.
#### **cat**
Prints content of files.
#### **find**
Finds files.
#### **grep**
Searches inside files
#### **cp**
Copies files.
#### **mv**
Moves / renames files and directories.
#### **rm**
Removes files and directories.

### Tools:
#### Code Editor : is used for editing, compilation, and deployment of the application's source code.

#### Burp Suite : Burp Suite is an integrated platform for testing the security of web apps.
Burp Suite has many tools for various tasks. We will need:
- **Proxy** – intercepting web proxy that works like a man-in-the-middle between a browser and a web app. It allows intercepting, validating, and modifying raw traffic in both directions.
- **Intruder** – a tool that performs automated individual attacks on web apps.
  (Intruder allows you to perform various attacks, like brute-forcing passwords and IDs, fuzzing, etc.)
- **Repeater** – a tool for manipulating with and resending HTTP requests and analyzing the app's responses.

#### SQLmap : SQLmap is an automated tool for finding and exploiting SQL injections. It works with several SQL dialects and supports many techniques, from using a quote to complex time-based injection vectors. It can exploit injections in various DBMS.
-How to use SQLmap?
+ Run LXTerminal console;
+ Run LXTerminal console; sqlmap -u http://www.hacktory.lab/
  
#### TPLmap : TPLmap is a Python tool for automatic detection and exploitation of Server-Side Template Injections. TPLmap has settings and options similar to those of SQLmap. It supports numerous techniques and vectors (including blind injections) and can execute code download/upload arbitrary files
- How to use TPLmap?
+ Run LXTerminal console;
+ Go to the folder Tools/tplmap:cd Desktop/Tools/tplmap
+ Enter the command:./tplmap.py --os-shell -u http://www.hacktory.lab/

#### Nmap: Nmap is a network mapper. Nmap can be used for network security checks. It identifies the computer connected to a network, gets their data (name, OS, software), and identifies the firewalls used on the scanned node.
- How to use Nmap?
+ Run LXTerminal console;
+ Enter the command: nmap -p- -sV --open 10.0.2.0









