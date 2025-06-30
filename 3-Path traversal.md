# Path traversal
## Theory
### Vulnerability : Directory traversal (or path traversal) is a vulnerability, exploitation of which enables an attacker to read arbitrary files on an application's server (source code, application data, backend credentials, OS files). In some cases, an attacker can write information to the files stored on the server, thus changing the data and behaviour of an application.
 ** The vulnerability may arise when:**
    - working with archives;
    - working with paths based on user input (loading files with name ../../../pic.png)
**How it works?**
  <img src="/loadImage?filename=218.png">
the attacker can use it like this 
`https://website.com/loadImage?filename=../../../etc/passwd`
the application will read it like this ` /var/www/images/../../../etc/passwd`

IMPORTANT !! 
**  NB! Sometimes a vulnerable application may encode the symbol / as %2f. Thus, the request may look like the following /..%2f..%2f..%2f..%2fetc%2fpasswd
**

This vulnerability can be found when:

- ZIP archives are unpacked
- dynamic content is loaded to a page
- symlink is processed
- PATH parameter is processed by the web server or proxying requests
- downloading attachments stored in file systems

#### Fixes and Prevention:
- User input validation before processing. It is necessary to check that user input contains only acceptable values, for example, letters and digits.
- After validation, the application must add the input to the base directory and use the API of the file system to canonicalize paths. A canonicalized path must start with a correct/expected base directory.

## Lab1:YAOFR
Everything is straightforward. You have to find out how files are uploaded to the server, where they are stored, and how to download them. You will need your creative thinking to find the vulnerability in the functionality of downloading files.

**- Steps**:
- Open the machine
1. Discovered that the file manager uses the `path` parameter in the URL:
?action=view\&path=/somefolder
2. Tried modifying the `path` parameter to include directory traversal:
/../../../../../../../etc/passwd
3. Tested different depths using `../` until the correct traversal level was found.
4. Successfully accessed the system file:
[http://www.hacktory.lab/?action=view\&path=/../../../../../../../etc/passwd](http://www.hacktory.lab/?action=view&path=/../../../../../../../etc/passwd)
5. Retrieved and submitted the flag from `/etc/passwd`:
PATH\_TRAVERSAL\_fl\@g
- the end
- take notes good luck from kader





