from airflow.sdk import DAG
from airflow.providers.standard.operators.empty import EmptyOperator
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
import pandas as pd
from io import StringIO

def process_filter_ipv4(task_instance):
    # # Solution without xcom
    # df_solution1 = pd.read_csv('http://httpdata_nginx_intrusion/public_network_logs.csv')
    # Solution with xcom
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_dbip'])
    df = pd.read_csv(StringIO('\n'.join(data)), names=['ip_start_range', 'ip_end_range', 'country_code'])
    df_filtered = df[df['ip_start_range'].str.match(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')] #filter rows
    print(f'Before filter: {df.count()}, After filter: {df_filtered.count()}')
    return df_filtered

def process_filter_remove_col(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_pub_log'])
    df = pd.read_csv(StringIO('\n'.join(data)))
    # Source_IP,Destination_IP,Port,Request_Type,Protocol,Payload_Size,User_Agent,Status,Intrusion,Scan_Type
    # filter cols
    df_filtered = df[['Source_IP', 'Destination_IP', 'Port', 'Request_Type', 'Payload_Size', 'User_Agent', 'Status', 'Intrusion']]
    return df_filtered

def process_convert_ipv4(task_instance):
    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_ipv4'])
    print(df[0:2])
    print(type(df))
    return df[0]
    
def process_convert_ipv4_pub(task_instance):
    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_remove_col'])
    print(df[0:2])
    print(type(df))
    return df[0]

def process_map_ip_country(task_instance):
    df_dbip = task_instance.xcom_pull(key='return_value', task_ids=['convert_into_ipv4'])[0]
    df_logs = task_instance.xcom_pull(key='return_value', task_ids=['convert_into_ipv4_pub'])[0]

    def ip_to_int(ip):
        try:
            return int(ipaddress.ip_address(str(ip).strip()))
        except:
            return None

    df_logs['ip_int'] = df_logs['Source_IP'].apply(ip_to_int)
    df_dbip['ip_start_int'] = df_dbip['ip_start_range'].apply(ip_to_int)
    df_dbip['ip_end_int'] = df_dbip['ip_end_range'].apply(ip_to_int)

    def find_country(ip_int):
        if ip_int is None:
            return None
        match = df_dbip[
            (df_dbip['ip_start_int'] <= ip_int) &
            (df_dbip['ip_end_int'] >= ip_int)
        ]
        return match['country_code'].values[0] if len(match) > 0 else None

    df_logs['country_code'] = df_logs['ip_int'].apply(find_country)
    print(df_logs[['Source_IP', 'country_code', 'Intrusion']].head())
    return df_logs

def process_load(task_instance):
    from sqlalchemy import create_engine
    df = task_instance.xcom_pull(key='return_value', task_ids=['map_ip_country'])[0]
    engine = create_engine('postgresql://airflow:airflow@postgres/datawarehouse')
    df.to_sql('intrusion_logs', engine, if_exists='replace', index=False)
    print(f'{len(df)} lignes chargées dans intrusion_logs')

with DAG(dag_id='intrusion'):
    extract_dbip = HttpOperator(
        task_id='extract_dbip',
        method='GET',
        endpoint='dbip-country-lite-2026-01.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    extract_pub_log = HttpOperator(
        task_id='extract_pub_log',
        method='GET',
        endpoint='public_network_logs.csv',
        http_conn_id='httpdata_nginx_intrusion'
    )
    filter_ipv4 = PythonOperator(
        task_id='filter_ipv4',
        python_callable=process_filter_ipv4
    )
    convert_into_ipv4 = PythonOperator(
        task_id='convert_into_ipv4',
        python_callable=process_convert_ipv4
    )
    filter_remove_col = PythonOperator(
        task_id='filter_remove_col',
        python_callable=process_filter_remove_col
    )
    convert_into_ipv4_pub = PythonOperator(
        task_id='convert_into_ipv4_pub',
        python_callable=process_convert_ipv4_pub
    )
    map_ip_country = PythonOperator(
        task_id='map_ip_country',
        python_callable=process_map_ip_country
    )
    load = PythonOperator(
        task_id='load',
        python_callable=process_load
    )
    
    extract_dbip >> filter_ipv4 >> convert_into_ipv4
    extract_pub_log >> filter_remove_col >> convert_into_ipv4_pub
    [convert_into_ipv4, convert_into_ipv4_pub] >> map_ip_country >> load