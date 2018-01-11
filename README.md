# Pcap-Analyzer

+## 更新说明
++ 将项目从Python2.X移植到Python3.X
++ 修复了多个Bug
+
+## 主要功能

## The main function
+ 1. Show the basic information of the packet
+ 2. Analysis of packet protocols
+ 3. Analyze packet traffic
+ 4. Draw a map of access to IP latitude and longitude
+ 5. Extracts a session connection for a specific protocol in a packet （WEB，FTP，Telnet）
+ 6. Extract sensitive data from conversations （password）
+ 7. A simple analysis of the security risks in a packet （WEB attack，Violent crack）
+ 8. Extract the transfer file of a particular protocol in the datagram or all the binaries

## Show results
### Home:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/index.png)

### Basic data display:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/basedata.png)

### Protocol analysis:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/protoanalyxer.png)

### Traffic Analysis:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/flowanalyzer.png)

### Access the IP latitude and longitude map:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/ipmap.png)

### Session extraction:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/getdata.png)

### Attack message warning:
![Alt Text](https://github.com/ccgcyber/Pcap-Analyzer/blob/master/images/attackinfo.png)

### File extraction:
![Alt Text](https://github.com/HatBoy/Pcap-Analyzer/blob/master/images/getfiles.png)

## Install the deployment process:

+ Operating environment：Python 2.7.X
+ operating system：Linux (To Ubuntu 15.10 As an example)

###1.Python Related environment configuration （Ubuntu Default installation Python2.7 No additional installation required Python）
Python Package manager installed ：sudo apt-get install python-setuptools python-pip

###2. Related third party dependent library installation：
+ sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx
+ sudo pip3 install scapy-python3
+ sudo pip3 install Flask
+ sudo pip3 install Flask-WTF
+ sudo pip3 install geoip2
+ sudo pip3 install pyx
+ sudo pip3 install requests

###3. Modify the configuration file
Note to modify config.py The directory location in the configuration file
+ UPLOAD_FOLDER = '/home/dj/PCAP/'     Upload the location where the PCAP file is saved
+ FILE_FOLDER = '/home/dj/Files/'      The location where the file was saved，The following must be there All、FTP、Mail、Web Subdirectory， Used to store files that extract different protocols
+ PDF_FOLDER = '/home/dj/Files/PDF/'   PCAP saved when saved as a PDF

###4. Server installation
+ Gunicorn server：pip3 install gunicorn
+ Nginx server：sudo apt-get install nginx
+ Nginx configuration: modify the /etc/nginx/nginx.conf file, add the following code in http {}：
```
server { 
listen 81; 
server_name localhost; 
access_log /var/log/nginx/access.log; 
error_log /var/log/nginx/error.log;

     location / {
        #root   html;
        #index  index.html index.htm;
         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
         proxy_set_header Host $http_host;
         proxy_pass http://127.0.0.1:8000;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   html;
    }
```

###5. Start the system：
+ Into the system where the directory：../pcap-analyzer
+ Start the system through the Gunicorn server server，run the command：gunicorn -c deploy_config.py run:app
+ At this point only local access to the system，address：http://127.0.0.1:8000
+ Start the Nginx server：sudo service nginx start
+ At this point other hosts can also access the system，address：http://server_IP:81


## Analysis optimization
###The accuracy of the analysis results for the packet can be improved by modifying the configuration file，Correction
+ replace ./app/utils/GeoIP/GeoLite2-City.mmdb IP address latitude and longitude database file can improve the accuracy of IP latitude and longitude map
+ modify ./app/utils/protocol/ Each of the directories TCP/IP The protocol number of the protocol stack and the corresponding protocol name correct the protocol analysis results
+ modify ./app/utils/waring/HTTP_ATTACK File can improve the accuracy of HTTP protocol attacks in packets
