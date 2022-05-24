import csv
import itertools
from os import environ
import json
import shodan
import timeit
import logging
class shodan_monitor:
    """
    Aimed at identifying intel exposed on public ips.
    """
    api_key=environ['shodan_key']
    shodan_api = shodan.Shodan(api_key)

    def __init__(self,api_key):
        self.api_key = api_key
        # self.shodan_api = shodan_api

    def convert_csv_to_list(self,file_path):
        """
        A function for conversion of the csv file provided into a list for 
        processing.
        @file_path: relative path of csv file on system
        @return: list of ips to be processed
        """
        try:   
            with open(file_path,'r') as file:
                reader = csv.reader(file)
                temp=[]
                for row in reader:
                    temp.append(row)      
            # * unpacks list -> funcion args parsed by chain method
            ip_list = list(itertools.chain(*temp)) 
        except (TypeError,ValueError):
            print('check provided file path')

        return ip_list

    def populate_host_info(self,host_output,host_query_result):
        """
        A function for assigning values to the host_output.
        @field: key value of host_output 
        @return: host_output populated with field values via get request.
        """
        field = ['ip_str', 'org', 'os', 'device', 'devicetype', 'product',
     'asn','port','location','isp','transport','domains','hostnames','timestamp','vuln']
        try:
            results = host_query_result
            for key in results.keys():
                if key in field:
                    host_output[key] = results[key]  
            return host_output

            
        except (TypeError, ValueError):
            print("non-compatible data type passed, check host_output/results/field")

    def convert_to_json(self,hosts):
        """
        A function for converting the list object into json format for 
        ingestion by sentinel logs.
        @hosts: list of public ips info
        @return json format output
        """
        try:
            json_data = json.dumps(hosts)
            return json_data
        except (TypeError, ValueError):
            print("non-compatible data type passed, check hosts value")

    def get_ip_info(self,ip_list):
        """
        A function for populating individual ip information for the specified fields.
        @ip_list: list of public ips
        @return : json format of all the listed ip info gathered by shodan.
        """
        hosts = []
        query = "net:"
        try:
            for ip_range in ip_list:
                logging.info(f"LOG: Searching Shodan for IP: {ip_range}")
                print('[+]',ip_range)
                results = self.shodan_api.search(query+ip_range)
                '''try using 2 pointer approach instead of loops'''
                for result in results['matches']:
                    host_output = {
                        'ip_str': '',
                        'org': '',
                        'os': '',
                        'device': '',
                        'devicetype': '',
                        'product': ' ',
                        'asn': '',
                        'port': '',
                        'location': '',
                        'isp': '',
                        'transport': '',
                        'domains': '',
                        'hostnames': '',
                        'timestamp': '',
                        'vuln' : ''
                    }
                    temp = self.populate_host_info(host_output,result)
                    hosts.append(temp)
            json_data = self.convert_to_json(hosts)
            return json_data
                
        except shodan.APIError as error:
            print(f"Error: {error}")
