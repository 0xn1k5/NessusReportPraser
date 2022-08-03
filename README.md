# NessusReportPraser



 **Name** : **Nessus 6 Report visualizer and converter**

 **Author** : **Nikhil Raj ( Twitter: 0xn1k5 | Mail: nikhilraj149[at]gmail.com )**

 **Version: 1.0**
 
 **Last Updated** : 7 Aug 2017

 **Description**:  
 
 The script allows to visualize data from multiple nessus 
 report files on the terminal. It also allows to the 
 filter output by ip, port, severity-level of issue, or 
 name of vulnerability using various command line options 
 described in the below section. The filtered data can be 
 exported in a csv format. 
 
 **Usage**:
  	
  	python ./nessusReportParser.py -h
  	 
  	 -h  or --help               print this help menu
  	 -f  or --file                  space separated input nessus report file(s)
  	 
  	 
  	 
     -o  or --output-file      output file to save data in csv format
     
     
     
     Filter-options:
     
  	 -p  or --port               display records with matching port
  	 
                                       format accepted:
                                       -p 21,53,23"
                                       -p 1-1000"
                                       -p 8090"
  	 
  	 -c  or --severity-level    display records with matching severity level
  	 
  	                       	             format accepted:
  	                       	              -c 2,3,4
  	                                     -c 1-4
  	                                     -c 4 
  	                                        
                                         severity-index:
                                         0 - Info
                                         1 - Low
                                         2 - Medium
                                         3 - High
                                         4 - Critical
  	 
  	 Note: This options can be clubbed with -p option
  	 
  	 -e  or  --exclude-ip       exclude comma seperated ip from output
  	                                    format accepted:
  	                                    -e 192.168.0.1
  	                                    -e 192.168.0.1,10.10.209.11\
  	                                        
     Note: Current version doesn't support filtering via cidr ip notation
                It can be clubbed with all above filters options
     
  	 -v  or --vulnerability      display records with matching vulnerability name
  	                                     format accepted:
  	                                       -v "ms17-010"
  	                                       -v "poodle,smb"                             
  	 
 Examples:
 
    Display help section of the script
    
        #python ./nessusReportParser.py -h
        
    Parse scan01.nessus and scan02.nessus file(s) and display info on terminal 	 
        # python ./nessusReportParser.py -f scan01.nessus scan02.nessus
        
    Parse nessus report files and save output in output-report.csv file    
        # python ./nessusReportParser.py -f scan01.nessus scan02.nessus -o output-report.csv
        
    Display records from nessus report where port number lies between 1 to 1024     
        # python ./nessusReportParser.py -f scan01.nessus scan02.nessus -p 1-1024
    
    Display all the severity-level = 4 [Critical] observations from the nessus report
        # python ./nessusReportParser.py -f scan01.nessus scan02.nessus -c 4
        
    Display all records from nessus report where port number is 22 and severity-level is 4 [Critical]    
        # python ./nessusReportParser.py -f scan01.nessus  -p 22 -c 4
        
    Display all the observations where system is vulnerable to "wannacry"   
        # python ./nessusReportParser.py -f scan01.nessus  -v "wannacry"
        
    Exclude host 10.10.08.108 and 10.10.09.109 from the report    
        # python ./nessusReportParser.py -f scan01.nessus -e 10.10.08.108,10.10.09.109
  	
  	
  	                     

 **Requirements**: This script requires below two libraries which may not be present by default in your
		python installation:

		1) LXML - Required for parsing nessus data
		2) PrettyTable (Optional) - for formatting data in tabular fashion on terminal


**Please share your feedback or any improvements you want to see in the script @ nikhilraj149@gmail.com** 
