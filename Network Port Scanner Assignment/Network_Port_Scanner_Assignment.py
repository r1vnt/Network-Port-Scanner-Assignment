import sys
import socket
import argparse 
from datetime import datetime
import re
import threading
import os

#print(os.getcwd())                                          script for working directory (used for testing)

portscannerThreads = []                                      #Empty List that is used to store threads




#NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCAN 
def networkScannerForThreads(verifiedhost, port, verifiedlogfile): 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creates an INET stream socket that will be used to test whether a port is open or not

    sock.settimeout(5)                                       #Timeout set to 5 seconds, if nothing happens after 5 seconds it moves to the next port, it is set at 5 since if it is set at shorter spans the service variable occassionally returned port/proto errors
    try:
        service = socket.getservbyport(int(port))            #Gets the service of the port, so for example port 80 will be HTTP
    except socket.error:
        service = "Unknown Service"                          #If no service is found in correlation with the port, it will just save the service as "Unknown Service"
      
    
    attempt = sock.connect_ex(((verifiedhost, port)))        #Attempting to connect to the port, connect_ex returns 0 if the connection is successful, and an error message if it is deemed unsuccessful
    outputport = port                                        
    if attempt == 0:                                         #if attempt is equal to 0, connection is successful display that the port is open
        
        output = "\nHost : " + verifiedhost + "\nPort : " + str(outputport) + "\n" + "Service : " + service.upper() + "\nStatus : " + "OPEN"+"\n"
            
    else:                                                    #if attempt is something else display that the port is closed, and the corresponding error message
        output = "\nHost : " + verifiedhost + "\nPort : " + str(outputport) + "\n" + "Service : " + service.upper() + "\nStatus : " + "CLOSED ("+str(attempt)+")\n"
    
    print(output)                                            #Display output to the command prompt
    
    try:                            
        verifiedlogfileRW = open(verifiedlogfile, "a")       #Open path if verifiedlogfile is a valid path (it won't be if -L is not selected)
        verifiedlogfileRW.write(output)                      #Write output to log file
    except:
         pass                                                #pass (do nothing) if verifiedlogfile is empty
                    


    sock.close()                                             #Close the socket stream
#NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCANNER (FOR THREADS) NETWORK PORT SCAN 




#NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NET
def networkScanner(verifiedhost,verifiedtargetfile,verifiedport,verifiedlogfile):
            
    try:
        verifiedlogfileRW = open(verifiedlogfile, "w")       #if there is a logfile it will write the Banner too the logfile
        verifiedlogfileRW.write(logfileBanner()[0]+"\n")     #Writes log file banner
        verifiedlogfileRW.write(logfileBanner()[1]+"\n")     #Writes log file banner
        verifiedlogfileRW.write(logfileBanner()[2]+"\n")     #Writes log file banner
        verifiedlogfileRW.write(logfileBanner()[3]+"\n")     #Writes log file banner
        verifiedlogfileRW.close
    except:
        pass                                                 #Do nothing if there is no log file (verifiedlogfile will be "")

    if verifiedtargetfile == "":                             #If there is no verified targetfile therefore it should check the verifiedhost and shouldn't be checking any file's
        
        print(logfileBanner()[0])                            #Display the logfile Banner
        print(logfileBanner()[1])                            #Display the logfile Banner
        print(logfileBanner()[2])                            #Display the logfile Banner
        print(logfileBanner()[3])                            #Display the logfile Banner

        if len(verifiedport) <= 10:                          #If the number of ports being scanned then multithreading isn't nessecary, as it is only used to increase efficiency
            for port in verifiedport:                        #verifiedport, being a list of all the ports as specified by the user
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    #Creates an INET stream socket that will be used to test whether a port is open or not
                sock.settimeout(0.5)                         #Timeout set to 0.5 seconds, if nothing happens after 0.5 seconds it moves to the next port
                
                try:
                    service = socket.getservbyport(port)     #Gets the service of the port, so for example port 80 will be HTTP
                except:
                    service = "Unknown Service"              #If no service is found in correlation with the port, it will just save the service as "Unknown Service"
                    
                attempt = sock.connect_ex((verifiedhost, int(port))) #Attempting to connect to the port, connect_ex returns 0 if the connection is successful, and an error message if it is deemed unsuccessful
                
                if attempt == 0:                             #If attempt is equal to 0, connection is successful display that the port is open
                    output = "Host : " + verifiedhost + "\nPort : " + str(port) + "\n" + "Service : " + service.upper() + "\nStatus : " + "OPEN"+"\n"
                    
                else:                                        #if attempt is something else display that the port is closed, and the corresponding error message
                    output = "Host : " + verifiedhost + "\nPort : " + str(port) + "\n" + "Service : " + service.upper() + "\nStatus : " + "CLOSED ("+str(attempt)+")\n"
                
                print(output)                                #Display output to the command prompt
                
                try:
                    verifiedlogfileRW = open(verifiedlogfile, "a")  #Open path if verifiedlogfile is a valid path (it won't be if -L is not selected)
                    verifiedlogfileRW.write(output)          #Write output to log file
                except:
                    pass                                     #Does nothing if there is no log file
                sock.close()                                 #Closes Socket connection once verified
        else:
            for port in verifiedport:                        #This is if the user is scanning more then 10 ports, to increase efficiency, it will use multithreading, starts a new thread per port, this loop goes through every port
                thread = threading.Thread(target=networkScannerForThreads, args=(verifiedhost, port, verifiedlogfile)) #Creates a new thread, executing the function "networkScannerforThreads", with arguments, verifiedhost, port, verifiedlogfile
                thread.start()                               #Starts (executes) the thread
                portscannerThreads.append(thread)            #Store the thread object for later reference                                                                     
            for thread in portscannerThreads:                #Loops through each thread in the list
                thread.join()                                #Waits for the thread to finish executing before proceeding
                



    elif verifiedhost == "":                                 #If the Verifiedhost is empty and the verifiedtargetfile isn't, therefore the user wants to read from a verified target file

        selecthost = input("please select a from the targeted file (with numbers 1 to length of file, or * if scanning all of them)") #If the file has multiple hosts in it, the program asks the user which host to target
        
        print(logfileBanner()[0])                            #Displays log file banner
        print(logfileBanner()[1])                            #Displays log file banner
        print(logfileBanner()[2])                            #Displays log file banner
        print(logfileBanner()[3])                            #Displays log file banner
        
        
        if selecthost.isdigit():                             #If the input is a digit it means that they are attempting to scan a specific host from the file
            try:
                selecthost = int(selecthost) - 1             #Makes selecthost, selectehost -1 since file lines start at 0
                verifiedhost = verifiedtargetfile[selecthost]#trys to find the host in the targetfile
            except:
                print("Target out of Range")                 #Throws an exception if the target is out of range
                sys.exit()                                   #Exits system since user is attempting to scan something that doesn't exist
                
        if selecthost == "*":                                #If the input is a * (a wildcard) it means that they are attempting to scan all hosts, automatically goes to multithreading, to increase efficiency, since multiple hosts and multiple ports will be heavy
            print("Scanning all ports")                      #Displays to the user that all ports are about to be scanned
            for host in verifiedtargetfile:                  #Loops over every host in verifiedtargetfile
                for port in verifiedport:                    #Loops over every selected port to be scanned
                

                    thread = threading.Thread(target=networkScannerForThreads, args=(host, port, verifiedlogfile)) #Creates a new thread, executing the function "networkScannerforThreads", with arguments, verifiedhost, port, verifiedlogfile
                    thread.start()                           #Starts (executes) the thread
                    portscannerThreads.append(thread)        #Store the thread object for later reference   
                for thread in portscannerThreads:            #Loops through each thread in the list
                    thread.join()                            #Waits for the thread to finish executing before proceeding
            sys.exit()                                       #Exits once everything successful executed


        if len(verifiedport) <= 10:                          #To get to this point we will be scanning a single host, with less tehn 10 ports, 
            for port in verifiedport:                        #verifiedport, being a list of all the ports as specified by the user
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #Creates an INET stream socket that will be used to test whether a port is open or not
                sock.settimeout(0.5)                         #Timeout set to 0.5 seconds, if nothing happens after 0.5 seconds it moves to the next port (Increase efficiency)
                
                try:
                    service = socket.getservbyport(port)     #Gets the service of the port, so for example port 80 will be HTTP
                except:
                    service = "Unknown Service"              #If no service is found in correlation with the port, it will just save the service as "Unknown Service"
                    
                attempt = sock.connect_ex((verifiedhost, int(port))) #Attempting to connect to the port, connect_ex returns 0 if the connection is successful, and an error message if it is deemed unsuccessful
                
                if attempt == 0:                             #If attempt is equal to 0, connection is successful display that the port is open
                    output = "Host : " + verifiedhost + "\nPort : " + str(port) + "\n" + "Service : " + service.upper() + "\nStatus : " + "OPEN"+"\n"

                else:                                        #If attempt is something else display that the port is closed, and the corresponding error message
                    output = "Host : " + verifiedhost + "\nPort : " + str(port) + "\n" + "Service : " + service.upper() + "\nStatus : " + "CLOSED ("+str(attempt)+")\n"
                print(output)                                #Display output to the command prompt
                
                try:
                    verifiedlogfileRW = open(verifiedlogfile, "a") #Open path if verifiedlogfile is a valid path (it won't be if -L is not selected)
                    verifiedlogfileRW.write(output)          #Write output to log file
                except:
                    pass                                     #pass (do nothing) if verifiedlogfile is empty
                    
                sock.close()                                 #Close the socket stream

        else:
            for port in verifiedport:                        #verifiedport, being a list of all the ports as specified by the user
                thread = threading.Thread(target=networkScannerForThreads, args=(verifiedhost, port, verifiedlogfile)) #Creates a new thread, executing the function "networkScannerforThreads", with arguments, verifiedhost, port, verifiedlogfile
                thread.start()                               #Starts (executes) the thread
                portscannerThreads.append(thread)            #Store the thread object for later reference  
    
            for thread in portscannerThreads:                #Loops through each thread in the list
                thread.join()                                #Waits for the thread to finish executing before proceeding
#NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NETWORK PORT SCANNER NET




#BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION 
def logfileBanner():
    
    current_date = datetime.now().strftime('%Y-%m-%d')       #Current Date in Format YY-MM-DD
    current_time =  datetime.now().strftime('%H:%M:%S')      #Current Time in Format HH-MM-SS
    current_timezone = datetime.now().astimezone().tzname()  #Current Timezone which will be helpful for keeping data collected forensically sound
    current_unix = datetime.now().timestamp()                #Current Unix Timestamp which will be helpful for keeping data collected forensically sound
    
    
    logfileBanner  = ["######################## NEW RUN #########################", #Log File Banner inputted as a list so that it can be called later
                     f"############ Date:{current_date} ## Time:{current_time} ############", 
                     f"# Timezone: {current_timezone} ## Unix: {current_unix} #",
                     "##########################################################"]
    return logfileBanner                                     #Returns the Banner as a list meaning it can printed/written too a file by printing a function
#BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION BANNER FUNCTION 




#HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDR
def hostHandling(host):
    ipRegex=r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"   #Regex for an IP address, used to compare inputs by the user, format is x.x.x.x
    webaddressRegex = r"(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?\/[a-zA-Z0-9]{2,}|((https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?)|(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})?" #Regex for a domain address, used to compare user inputs
    if re.match(ipRegex, host) or re.match(webaddressRegex, host): #checks if the users input matches the ipRegex or webaddressRegex
        print("Valid Host - IP Verified as an valid IP address or web address") #Tells the user that the address inputted in a valid host.
        host = host                                                 
        return host                                          #Returns the host         
    else:                                                    #If the host is invalid, it will display an error message
        print("Invalid Host - The host inputted is not a valid IP address or web address\nIP Address has to follow format x.x.x.x (IpV4), where x is a number between 0 and 255\nA valid web address/website domain is also accepted")
        sys.exit()                                           #sys.exit, since an incorrect host means no point executing the test
#HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDRESS VERIFICATION HOST ADDR




#TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERI
def targetfileHandling(targetFile):
    print("Verifying Target File")                           #Displays to the user saying that it is verifying the target file
    ipRegex=r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"   #Regex for an IP address, used to compare inputs by the user, format is x.x.x.x
    webaddressRegex = r"(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?\/[a-zA-Z0-9]{2,}|((https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z]{2,}(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?)|(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}\.[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})?" #Regex for a domain address, used to compare user inputs
    targetFileList = []                                      #List of addresses found withing the target file
    try:
        targetfile = open(targetFile, "r")                   #Attempts to open the targetfile inputted by the user, used to read lines
        displaynumber = 1                                    #Used to display valid addresses to the User

        for line in targetfile:                              #loops over every line in the targetfile
            if re.match(ipRegex, line) or re.match(webaddressRegex, line): #If a line matches the ipRegex or the webaddressregex
                print("Valid address -",displaynumber,"-", line.rstrip("\n\r")) #Display to the user that it it is a valid address and can be used for network scanning
                targetFileList.append(line.rstrip("\n\r"))   #add's this valid address to the, targetfileList, strips newline (/n,/r)
                displaynumber = displaynumber + 1            #increases display number so it can display the next one
            else:
                print("Invalid Host's ("+line+") The host inputted is not a valid IP address or web address \nInvalid address \nIP Address has to follow format x.x.x.x (IpV4), where x is a number between 0 and 255 or be a complete domain\n A valid web address is also accepted") #Display for when host in the target file is invalid
                sys.exit() 
    except:
        print("Invalid Target File, Target file should be in the format of a file path.")                         #If the target file is invalid display to the user that the target file is invalid
        targetFileList = ""                                  #make it = ""
        sys.exit()                                           #sys.exit since there is no host to be scanned
    #print(targetFileList)                                   #used for testing

    return targetFileList                                    #Return the targetFileList
#TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERIFICATION TARGET FILE VERI




#PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFI
def portHandling(port):
    
    portList = []                                            #List of ports to be scanned later
    
    portRegexIndividual = r"^((6553[0-5])|(655[0-2][0-9])|(65[0-4][0-9]{2})|(6[0-4][0-9]{3})|([1-5][0-9]{4})|([0-5]{0,5})|([0-9]{1,4}))$"                                               #Accepted values should be Individual Numbers, e.g. 80,
    portRegexMultiple = r"\b(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(?:,(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))*\b" # Multiple Numbers in format 80,443,43,6
    portRegexRange = r"^(?:([1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))-(?:([1-9]\d{0,4}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]))$"       # or as a number range in format "x-y"
    portRegexWildCard = r"^\*$"                                                                                                                                                         # * is indicated as a wildcard (scans every port)
    
    if re.match(portRegexWildCard, port):                    #if the input by the user is * then the user wants to scan every port
        print("Scanning every port (1-65535)")               #Tells the user that every port is going to be scanned
        for i in range(1,65536):                             #This essentially fills port list with all numbers from 1 to 65535
            portList.append(i)                               #Appends i to list
        return portList                                      #returns portList, which will be a list of numbers from 1 to 65535

    if re.match(portRegexRange, port):                       #if the input by the user is x-y then the user wants to scan a range of ports

        portrange = port.split("-")                          #splits the input by the "-" giving the list x,y
        portlow = portrange[0]                               #portrange[0] will be the first number
        porthigh = portrange[1]                              #portrange[1] will be the first number
        print("Scanning Port Range ("+portlow+"-"+porthigh+")") #Tell the user that it is scanning port range x - y
        for i in range(int(portlow),int(porthigh) + 1):      #This essentially fills port list with all numbers from x to y
            portList.append(i)                               #Appends i to list
        return portList                                      #returns portList, which will be a list of numbers from x to y
    
    if re.match(portRegexIndividual, port):                  #if the input is an individual number (x), user wants to scan a single port
        print("Scanning Individual Ports ("+port+")")        #Tells user that he wants to scan a single port
        portList.append(int(port))                           #Appends port to list
        return portList                                      #returns portList, which will be a single number
    
    elif re.match(portRegexMultiple, port):                  #if the input is multiple formats in format, x,y,z,a,b,c user wants to scan multiple ports
        print("Scanning Multiple Ports ("+port+")")          #Tells user that he wants to scan a multiple ports
        portList = port.split(",")                           #splits port by the "," creating the port list
        portList = [int(x) for x in portList]                #turns every item in portList into an int
        return portList                                      #returns the portList
        
    else:                                                    #if the input isn't caught by any of the other if statements, then it's an invalid input
        print("Invalid Port(s), see -h for more information")                               #Tells the user it is an invalid input
        portList = ""                                        #Makes portList = ""
        sys.exit()                                           #exits program
        
#PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFICATION PORT VERIFI




#LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFI
def logFileHandling(logFile):                                #This is for verification if the -L statement is not left empty
    print("Verifying Log File")                              #Tells the user that the log File they've typed in is going to be verified
    
    try:                                                     #An easy way to test if a log file is valid, simply by attempting to open the file and seeing if it can be read
        logFiletest = open(logFile, "r")                     #Testing to see if the file path can be opened
        print("Log File Found")                              #Tells user that the log file has been found
        return logFile                                       #Returns the logfile so it can be used in the network scanner function later
            
    except:                                                  #Exception for if the log file does not exist/ cannot be opened/ is in the incorrect format
        print("Error, log file does not exist or is not the correct format.") #Display for the user
        logFile = ""                                         #Makes the logFile essentially equal to nothing
        sys.exit(1)                                          #Exits system
#LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFICATION LOG FILE VERIFI




def main():




#ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS 
    parser = argparse.ArgumentParser(                        #Creating parser for argparse, 
                    prog="Network Port Scanner",             #Name of the CLI
                    description="A Network Port Scanner that can be use to detect whether ports in a network are opened or closed, this program has the ability to select a specific host, in the format of a IP address or domain, or hosts from a target file, choose from an individual, range, selection or all (1-65535) ports, it will then display them onto the Command Line, and output them to a logfile if the argument is selected.", #Description as seen in -h argument
                    epilog="-H and -t are arguments that are mandatory in an either or format, attempting to put both arguments into the same command line will end up in an error. -p is a mandatory argument, absence of this command will result in an error. -L is an optional argument, it is not essential for this command to be written in the command line") #Epilog with other useful information
   
    eitheror = parser.add_mutually_exclusive_group(required=True) #Creates a group where it is required to have either -H or -t arguments
    eitheror.add_argument("-H","--host", help = "The host or network to be targetted by the Network Port Scanner. Argument should be formatted as -H <IPADDRESS> or --targethost <WEBADDRESS>. Examples : -H 0.0.0.0, --targethost 0.0.0.0 \n  -H www.example.com,  --targethost www.example.com .") #-H argument
    eitheror.add_argument("-t","--targetfile", help = "The host or network to be targetted by the Network Port Scanner stored in a plaintext file. Argument should be formmated as -t <FILELOCATION> or --targetfile <FILELOCATION>. Examples: -t C:/ProgramData/File/File/your_application_name.txt, --targetfile C:/ProgramData/File/File/your_application_name.txt, -t /var/log/addresses.txt\n --targetfile /var/log/addresses.txt, it is important to denote that either -H or -t is a mandatory argument .") #-t argument
    parser.add_argument("-p", "--port", help="Targetted Port/Ports, This argument is mandatory argument can be in multiple formats, such as -p * (scan all ports), -p 30 (scan single port), -p 30,40,50,60,70,80 (scan multiple ports), or -p 1-100 (scan range of ports from 1 to 100) .") #-p argument
    parser.add_argument('-L', '--logfile',nargs='?', const = "defaultLogFile.txt", help='This will create a text log file if a text file is specified, or if a text file is not specificed it will create a new text file, -L stores all the information collected from the Network Port Scan into a plaintext file, this argument is optional, an empty -L statement will autogenerate a logfile for you .') #-L argument, has the ability to be left empty and defaults to defaultLogFile.txt


    args = parser.parse_args()
#ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS ARGPARSE ARGUMENT FLAGS 

   
    if args.host is not None and args.targetfile is not None:#Redundent code but if argument some how parses to a point where, -H or -t are both selected, it will sys.exit
        print("Error, -H/--host and -t/--targetfile are mutually exclusive arguments and cannot be executed in the same command line, see -h (help) for more information.")
        sys.exit()                                           #Terminates Program

    if args.host is None and args.targetfile is None:        #Redundent code but if argument some how parses to a point where, neither -H or -t are selected, it will sys.exit
        print("Error, -H/--host and -t/--targetfile are mutually exclusive arguments, but either one of them is nessecary and has to be included in the command line, see -h (help) for more information.")
        sys.exit()                                           #Terminates Program

    if args.port is None:                                    #Since port is a mandatory argument, if port is not selected it will sys.exit
        print("Error, -p/--port is a mandatory argument and has to be included in the command line, see -h (help) for more information.")
        sys.exit()                                           #Terminates Program
    else:     
        if args.host is not None:                            #Checks if -H is included in the Command Line
            verifiedhost = hostHandling(args.host)           #Sends to hostHandling function which is used to verify whether it is a valid target host or not
            #print(verifiedhost)                             Used for testing
        if args.targetfile is not None:                      #Checks if -t is included in the Command Line
            verifiedtargetfile = targetfileHandling(args.targetfile) #Sends to targetfileHandling to verify whether it is a valid target file or not
            #print(verifiedtargetfile)
        if args.port is not None:                            #Checks if -p is included in the Command Line
            verifiedport = portHandling(args.port)           #Sends to portHandling to verify whether args.port is valid selection of ports
            #print(verifiedport)
        if args.targetfile is None:                          #if args.targetfile isn't included in the Command Line, then verifiedtargetfile = ""
            verifiedtargetfile = ""                          #Sets verifiedtargetfile to ""
        if args.host is None:                                #if args.host isn't included in the Command Line then verifiedtargetfile = ""
           verifiedhost = ""                                 #Sets verifiedhost to ""
           
        #Log file Handling
        if args.logfile:                                     #if -L is selected verify log file

            if args.logfile == "defaultLogFile.txt":         #if -L is left empty then it automatically sets to defaultLogFile.txt, since const = defaultLogFile.txt, writes to this default file
                print("Target File Empty, writing to defaultLogFile.txt") #Tells use where it's being written too
                verifiedlogfile = args.logfile               #set's verified logfile to defaultLogFile.txt
                
            else:                                            #if -L is not empty then it sends the argument to logfileHandling
                verifiedlogfile = logFileHandling(args.logfile) #setting verifiedlogfile to whatever is returned by logfileHandling
                
                
        else:
            verifiedlogfile = ""                             #if the -L prompt is not selected then verifiedlogfile is equal to notihng
            
           

        
        networkScanner(verifiedhost, verifiedtargetfile, verifiedport, verifiedlogfile) #Executes networkScanner function with all the verified argsparse arguments being the arguments
    

if __name__ == '__main__':                                 
    main()