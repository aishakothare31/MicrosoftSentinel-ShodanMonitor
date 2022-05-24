import datetime
import logging
import os
import tempfile
from os import environ

import azure.functions as func
from azure.storage.fileshare import ShareFileClient

from .sentinelLogs import sentinel_logs
from .shodanMonitor import shodan_monitor


def main(mytimer: func.TimerRequest) -> None:
    """
    Driver code for running shodan monitor
    """
    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Python timer trigger function ran at %s', utc_timestamp)

    api_key = environ['shodan_key']

    # Update the customer ID to your Log Analytics workspace ID
    customer_id = environ['customer_id']

    # For the shared key, use either the primary or the secondary
    # Connected Sources client authentication key
    shared_key = environ['shared_key']

    #connection string used for connecting to azure file client
    connection_string = environ['AzureWebJobsStorage']

    # The log type is the name of the event that is being submitted
    log_type = 'ShodanMonitor'

    try:
        logging.info("LOG: Settup Azure File Share client...")
        file_client = ShareFileClient.from_connection_string(conn_str=connection_string,
        share_name="shodanmonitor", file_path="ipv4_ranges.csv")
        temp_directory = tempfile.mkdtemp()
        file_name = "ipv4_ranges.csv"
        mask = 63
        saved_umask = os.umask(mask)

        path = os.path.join(temp_directory,file_name)

        with open(path, "wb") as file_handle:
            data = file_client.download_file()
            data.readinto(file_handle)
        
        shodan = shodan_monitor(api_key)

        sentinel = sentinel_logs(customer_id,shared_key,log_type)
        
        ip_list = shodan.convert_csv_to_list(path)
        
        json_data = shodan.get_ip_info(ip_list)
        logging.info(json_data)

        # Calling the sentinel logs post function usin the json dump from shodan monitor.
        if json_data is not None:
            sentinel.post_data(customer_id, shared_key, json_data, log_type)
    
    except Exception as err:
        print(err)
    else:
        os.remove(path)
    finally:
        os.umask(saved_umask)
        os.rmdir(temp_directory)
if __name__ == "__main__":
    main()

