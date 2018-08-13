#!/usr/bin/python3
############
# @Author Ibonok
#
# Dump Elasticsearch instances
#
# Do not use this in productiv enviroments.
# For educational use only. 
# 
############ 

from elasticsearch import Elasticsearch, ElasticsearchException
from colorama import init, Fore, Style
from datetime import datetime

import yara
import os, errno, sys, logging
import argparse
import jsbeautifier
import urllib3
import re
import json

def set_debug_level( level):
    init(autoreset=True)
    chooser = { 
            0: logging.INFO,
            1: logging.DEBUG,
            2: logging.WARNING,
            3: logging.ERROR,
            4: logging.CRITICAL
            }

    if level is not None:
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        formatter = logging.Formatter( Fore.GREEN + '%(asctime)s ' + Fore.BLUE + '%(name) -12s ' + Fore.RED + '%(levelname) -8s ' + Style.RESET_ALL + '%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(chooser.get( level))

def check_args ():
    init(autoreset=True)
    global CONNECTION_TIMEOUT
    global CONNECTION_RETRIES
    global SIZE
    global INDEXES
    global DUMP_INDEXES
    global OUTPUT
    global STDOUT
    global YARA

    pars = argparse.ArgumentParser(description=Fore.GREEN + Style.BRIGHT + 'Search for elasticsearch on the Internet. \nDisplay all Indexes and dump the Indexes.' + Style.RESET_ALL)

    pars.add_argument('-t', '--timeout', nargs='?', type=int, default=30, help='Connection Timeout, Default = 30s')
    pars.add_argument('-r', '--retries', nargs='?', type=int, default=False, help='Connection Retries, Default = 0')
    pars.add_argument('-s', '--size', nargs='?', type=int, default=1, help='Define Scroll Size, Default = 1')
    pars.add_argument('-v', '--verbose', type=int, nargs='?', help='Increase verbosity level 0:INFO, 1:DEBUG, 2:WARNING, 3:ERROR, 4:CRITICAL', default=None)
    pars.add_argument('-i', '--indexes', type=str, nargs='*', help='Give known indexes : index1 index2 indexn, Default = *', default='*')
    pars.add_argument('-d', '--dump', type=bool, nargs='?', help='Dump indexes of target. Default = False', default=False, const=True)
    pars.add_argument('-o', '--output', type=str, choices= ('csv', 'json'), help='Output File: out/ip/indexname, csv=only _source, json=all', default=None)
    pars.add_argument('-std', '--stdout', type=bool, nargs='?', help='Display DUMP to stdout, Default = False', default=False, const=True)
    pars.add_argument('-y', '--yara', type=bool, nargs='?', help='Turn on yara rule search, Default = False', default=False, const=True)

    pars.add_argument('--ip', nargs='?', help='Target IP:PORT')
    pars.add_argument('-f', '--filename', nargs='?', help='File with IP:PORT')

    args = pars.parse_args()

    CONNECTION_TIMEOUT = args.timeout
    CONNECTION_RETRIES = args.retries
    SIZE = args.size
    INDEXES = args.indexes
    DUMP_INDEXES = args.dump
    OUTPUT = args.output
    STDOUT = args.stdout
    YARA = args.yara
    set_debug_level ( args.verbose)

    print_settings()

    if args.ip is None and args.filename is None:
        pars.error(Fore.RED + '-f/--filename or --ip required')
    elif args.ip and args.filename is None: 
        return args.ip, True
    elif args.ip is None and args.filename: 
        return args.filename, False
    elif args.ip and args.filename: 
        pars.error(Fore.RED + 'To many Parameters, please choose -f/--filename or --ip')


def print_settings():
    print (Fore.RED + '#' * 50)
    print ('\t' + Fore.GREEN + 'Connection Timeout: ' + Fore.BLUE + str(CONNECTION_TIMEOUT))
    print ('\t' + Fore.GREEN + 'Connection Retries: ' + Fore.BLUE + str(CONNECTION_RETRIES))
    print ('\t' + Fore.GREEN + 'Scroll Size: ' + Fore.BLUE + str(SIZE))
    print ('\t' + Fore.GREEN + 'Indexes: ' + Fore.BLUE + str(INDEXES))

    print ('\t' + Fore.GREEN + 'Dump Elasticsearch Host: ' + Fore.BLUE + str(DUMP_INDEXES))
    print ('\t' + Fore.GREEN + 'Output Format: ' + Fore.BLUE + str(OUTPUT))
    print (Fore.RED + '#' * 50)


def get_indexes ( es, ip):
    try:
        print (Fore.BLUE + 'Try to get INDEXES')
        for index in es.indices.get(INDEXES):
            print (Fore.GREEN + 'Index: ' + Fore.RED + index)
            if DUMP_INDEXES:
                dump_index (es, index, ip)
        print ('\n')
    except ElasticsearchException as e:
        print ('Error: ', e)
    except Exception as e:
        print ('Error: ', e)

def dump_index ( es, this_index, ip):
    page = es.search(
        index = this_index,
        doc_type = '',
        scroll = '1m',
        size = SIZE,
        request_timeout = 10,
        body = {
    })
    sid = page['_scroll_id']
        
    #scroll_size = page['hits']['total']
    oth = True

    page = es.scroll(scroll_id = sid, scroll = '1m')
    if STDOUT and OUTPUT is None:
        if YARA:
            rules = compile_yara()
            check_yara_matches( rules, str(page))
            print (str(page))
        else:
            print (str(page))
        #for hit in page['hits']['hits']:
        #    v = hit["_source"]
        #    data = json.dumps(v)
        #    print (jsbeautifier.beautify(data))
    elif OUTPUT == 'csv':
        print (Fore.RED + 'Output to CSV IP/filename: out/' + Fore.BLUE + ip + Fore.GREEN + '/' + this_index + '.csv')
        for hit in page['hits']['hits']:
            v = hit["_source"]
            data = json.dumps(v)
            data = json.loads(data)
            if YARA:
                rules = compile_yara()
                if check_yara_matches( rules, str(data)):
                    oth = write_csv(data, this_index, ip, oth)
            else:
                oth = write_csv(data, this_index, ip, oth)
    elif OUTPUT == 'json':
        print (Fore.RED + 'Output to IP/JSON filename: out/' + Fore.BLUE + ip + Fore.GREEN + '/' + this_index + '.json')
        if YARA:
            rules = compile_yara()
            if check_yara_matches( rules, str(page)):
                write_json(page, this_index, ip)
        else:
            write_json(page, this_index, ip)

def write_json(data, this_index, ip):
    try: 
        if os.path.exists("out") == False:
            os.makedirs('out')
        os.makedirs('out/' + ip)
    except OSError as e:
        if e.errno != errno.EEXIST:
            print (Fore.RED + 'Cannot create directory')
            raise
    
    try: 
        datei = open('out/' + ip + '/' + this_index + '.json', 'a')
        datei.write(jsbeautifier.beautify(str(data)))
        datei.close()
    except FileNotFoundError:
        print(Fore.RED + 'Input file not found!')

def write_csv(data, this_index, ip, oth):
    try: 
        if os.path.exists("out") == False:
            os.makedirs('out')
        os.makedirs('out/' + ip)
    except OSError as e:
        if e.errno != errno.EEXIST:
            print (Fore.RED + 'Cannot create directory')
            raise

    try:
        datei = open('out/' + ip + '/' + this_index + '.csv', 'a')
        headers = ''
        values = ''
        for key, value in data.items():
            headers += str(key) + ','
            values += str(value) + ','
        if SIZE > 1 and oth:
            oth = False
            datei.write(headers[:-1] + '\n')
        datei.write(values[:-1])
        datei.close()
        return oth
    except FileNotFoundError:
        print(Fore.RED + 'Input file not found!')

def check_ipport(ip):
    if re.findall('^(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[\d]{1,4}$', ip):
        return True
    else:
        print ('Not an ip:port, ', ip)
        return False

def test4elastic(ip):
    if check_ipport(ip):
        ipport = ip.split(':')
        try:
            http = urllib3.PoolManager(timeout=CONNECTION_TIMEOUT, retries=CONNECTION_RETRIES, port=int(ipport[1]))
            check_el = http.request('GET', 'http://' + ip.rstrip())
            if re.search (r'lucene', str(check_el.data)):
                return True
            else:
                print ('Not an Elastic Search Instanz')
                return False
        except urllib3.exceptions.ConnectTimeoutError:
            print (Fore.RED + Style.BRIGHT + 'Error: Connection Timeout')
            return False
    else:
        return (Fore.RED + Style.BRIGHT + 'Error: Go Next')


def create_connection(ip):
    print (Fore.GREEN + 'Connect to ', ip)
    es = Elasticsearch([ip])
    version = es.info()
    print (Fore.BLUE + 'Name: ' + version['name'] + '\nClustername: ' + version['cluster_name'] + '\nLucene Version: ' + version['version']['lucene_version'])
    if version['version']['lucene_version'].startswith('4'):
        print (Fore.RED + 'Wrong elasticsearch version...')
        return None
    else:
        return es

def single_ip(ip):
    if test4elastic(ip):
        es = create_connection(ip)
        if es is not None:
            get_indexes ( es, ip)
    else:
        print ('Error go next')

def input_file(filename):
    file = open (filename, 'r')
    for ip in file:
        if test4elastic(ip.rstrip()):
            es = create_connection(ip.rstrip())
            if es is not None:
                get_indexes (es, ip.rstrip())
        else:
            print ('Error go next')

def compile_yara():
    try:
        indexes = 'Rules/index.yar'
        rules = yara.compile(indexes)
        return rules
    except Exception as e:
        print ('Error create yara index: ', e)
        sys.exit()

def yara_index( indexes):
    with open (indexes, 'w') as yara_rules:
        for filename in os.listdir('Rules'):
            if filename.endswith('.yar') and filename != 'index.yar':
                include = 'include "{0}"\n'.format(filename)
                yara_rules.write(include)

def check_yara_matches( rules, json_data):
    matches = ""
    try:
        matches = rules.match(data=json_data)
    except Exception as e:
        print ('Cannot check json_data: ', e)
        print ('Go next')
    
    results = []
    for match in matches:
        if match.rule == 'core_keywords' or match.rule == 'custom_keywords':
            for s in match.strings:
                rule_match = s[1].lstrip('$')
                if rule_match not in results:
                    results.append(rule_match)
                results.append(str(match.rule))
        else:
            results.append(match.rule)

    if len (results) > 0:
        print ('Rule Match: ', results)
        return True
        #print (json_data)

if __name__ == "__main__":
    try:
        (value, typ) = check_args()
        if typ:
            single_ip(value)
        else:
            input_file(value)
    except KeyboardInterrupt:
        sys.exit()
