# elastic_scan
> Dump Elasticsearch Instances

The code is very dirty but works so far :-)  
Define an elasticsearch host and list all indexes and dump them to a file.  
You can write some yara rules to search intressting entries.  
# Installation

```
git clone https://github.com/Ibonok/elastic_scan.git
cd elastic_scan
pip3 install -r requirements.txt
```

> Donate: (ETH) 0x489B56bA505F88a054893d5BdE2c8b35f4A33FAb

<p align="center">
  <img width="800" src="https://cdn.rawgit.com/ibonok/elastic_scan/7b553ae/elastic_scan.svg">
</p>

# Usage

```
python elastic_scan.py --help

usage: elastic_scan.py [-h] [-t [TIMEOUT]] [-r [RETRIES]] [-s [SIZE]]
                       [-v [VERBOSE]] [-i [INDEXES [INDEXES ...]]] [-d [DUMP]]
                       [-o {csv,json}] [-std [STDOUT]] [-y [YARA]] [--ip [IP]]
                       [-f [FILENAME]]

Search for elasticsearch on the Internet. Display all Indexes and
dump the Indexes.

optional arguments:
  -h, --help            show this help message and exit
  -t [TIMEOUT], --timeout [TIMEOUT]
                        Connection Timeout, Default = 30s
  -r [RETRIES], --retries [RETRIES]
                        Connection Retries, Default = 0
  -s [SIZE], --size [SIZE]
                        Define Scroll Size, Default = 1
  -v [VERBOSE], --verbose [VERBOSE]
                        Increase verbosity level 0:INFO, 1:DEBUG, 2:WARNING,
                        3:ERROR, 4:CRITICAL
  -i [INDEXES [INDEXES ...]], --indexes [INDEXES [INDEXES ...]]
                        Give known indexes : index1 index2 indexn, Default = *
  -d [DUMP], --dump [DUMP]
                        Dump indexes of target. Default = False
  -o {csv,json}, --output {csv,json}
                        Output File: ip-indexname, csv=only _source, json=all
  -std [STDOUT], --stdout [STDOUT]
                        Display DUMP to stdout, Default = False
  -y [YARA], --yara [YARA]
                        Turn on yara rule search, Default = False
  --ip [IP]             Target IP:PORT
  -f [FILENAME], --filename [FILENAME]
                        File with IP:PORT
```

# Example
> Get all indexes

```
➜  ~ python3 elastic_scan.py --ip 127.0.0.1:9200                  
##################################################
	Connection Timeout: 30
	Connection Retries: False
	Scroll Size: 1
	Indexes: *
	Dump Elasticsearch Host: False
	Output Format: None
##################################################
Connect to  127.0.0.1:9200
Name: AOw7Lql
Clustername: elasticsearch
Lucene Version: 7.2.1
Try to get INDEXES
Index: pastehunter-2018-26
Index: pastehunter-2018-24
Index: .triggered_watches
Index: .watches
Index: .kibana
Index: pastehunter-2018-25
Index: pastehunter-2018-27
Index: .monitoring-es-6-2018.06.14
Index: .monitoring-alerts-6
```

> Dump the last 3 entries of all Indexes
```
python3 elastic_scan.py --ip 127.0.0.1:9200 -d -s 3 --out csv
##################################################
	Connection Timeout: 30
	Connection Retries: False
	Scroll Size: 3
	Indexes: *
	Dump Elasticsearch Host: True
	Output Format: csv
##################################################
Connect to  127.0.0.1:9200
Name: AOw7Lql
Clustername: elasticsearch
Lucene Version: 7.2.1
Try to get INDEXES
Index: .monitoring-es-6-2018.06.14
Output to CSV IP/filename: 127.0.0.1:9200/.monitoring-es-6-2018.06.14.csv
Index: pastehunter-2018-25
Output to CSV IP/filename: 127.0.0.1:9200/pastehunter-2018-25.csv
Index: pastehunter-2018-27
Output to CSV IP/filename: 127.0.0.1:9200/pastehunter-2018-27.csv
Index: pastehunter-2018-26
Output to CSV IP/filename: 127.0.0.1:9200/pastehunter-2018-26.csv
Index: .watches
Output to CSV IP/filename: 127.0.0.1:9200/.watches.csv
Index: .kibana
Output to CSV IP/filename: 127.0.0.1:9200/.kibana.csv
Index: pastehunter-2018-24
Output to CSV IP/filename: 127.0.0.1:9200/pastehunter-2018-24.csv
Index: .triggered_watches
Output to CSV IP/filename: 127.0.0.1:9200/.triggered_watches.csv
Index: .monitoring-alerts-6
Output to CSV IP/filename: 127.0.0.1:9200/.monitoring-alerts-6.csv


➜  ~ ls
127.0.0.1:9200  elastic_scan.py

```

> Get some Elasticsearch Hosts from shodan

```
shodan download elasticsearch product:"Elastic" --limit 2

Search query:			product:Elastic
Total number of results:	42079
Query credits left:		95
Output file:			elasticsearch.json.gz
  [####################################]  100%             
Saved 1000 results into file elasticsearch.json.gz

shodan parse --fields ip_str,port --separator : elasticsearch.json.gz | sed s'/.$//' > el_ip

cat el_ip

file: el_ip
xxx.xxx.xxx.xxx:80
xxx.xxx.xxx.xxx:80
xxx.xxx.xxx.xxx:80
xxx.xxx.xxx.xxx:80

python3 elastic_scan.py -f el_ip -d -o json -s 10

```

> Write your yara Rules

```
ls Rules/

index.yar  somestring.yar
```

If you create your own rule file you need to at in index.yar

# Roadmap

:white_medium_square:  Clean code  
:white_square_button:  Searching Dump Results with Yara Rules   
:white_medium_square:  etc.  
