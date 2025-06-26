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
