from airflow.sdk import DAG, Asset
from airflow.providers.http.operators.http import HttpOperator
from airflow.providers.standard.operators.python import PythonOperator
from airflow.providers.common.sql.operators.sql import SQLExecuteQueryOperator
from io import StringIO
import pandas as pd
import ipaddress

intrusion_log_asset = Asset("intrusion_log_extracted")

def process_filter_remove_col(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_pub_log'])
    df = pd.read_csv(StringIO('\n'.join(data)))
    df_filtered = df[['Source_IP', 'Destination_IP', 'Port', 'Request_Type',
                       'Payload_Size', 'User_Agent', 'Status', 'Intrusion']]
    return df_filtered

def process_load_logs(task_instance):
    from sqlalchemy import create_engine
    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_remove_col'])[0]
    engine = create_engine('postgresql://airflow:airflow@postgres/datawarehouse')
    df.to_sql('staging_intrusion_logs', engine, if_exists='replace', index=False)
    print(f'{len(df)} lignes chargées dans staging_intrusion_logs')

with DAG(
    dag_id='dag_intrusion_log',
    schedule='@hourly',
):
    extract_pub_log = HttpOperator(
        task_id='extract_pub_log',
        method='GET',
        endpoint='public_network_logs.csv',
        http_conn_id='httpdata_nginx_intrusion',
        outlets=[intrusion_log_asset],
    )
    filter_remove_col = PythonOperator(
        task_id='filter_remove_col',
        python_callable=process_filter_remove_col,
    )
    load_logs = PythonOperator(
        task_id='load_logs',
        python_callable=process_load_logs,
    )

    extract_pub_log >> filter_remove_col >> load_logs

def process_filter_ipv4(task_instance):
    data = task_instance.xcom_pull(key='return_value', task_ids=['extract_dbip'])
    df = pd.read_csv(StringIO('\n'.join(data)), names=['ip_start_range', 'ip_end_range', 'country_code'])
    df_filtered = df[df['ip_start_range'].str.match(
        r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    )]
    print(f'Before filter: {df.count()}, After filter: {df_filtered.count()}')
    return df_filtered

def process_convert_and_load_ip_country(task_instance):
    from sqlalchemy import create_engine

    df = task_instance.xcom_pull(key='return_value', task_ids=['filter_ipv4'])[0]

    def ip_to_int(ip):
        try:
            return int(ipaddress.ip_address(str(ip).strip()))
        except:
            return None

    df['ip_start_int'] = df['ip_start_range'].apply(ip_to_int)
    df['ip_end_int'] = df['ip_end_range'].apply(ip_to_int)
    df = df.dropna(subset=['ip_start_int', 'ip_end_int'])

    engine = create_engine('postgresql://airflow:airflow@postgres/datawarehouse')
    df.to_sql('ref_ip_country', engine, if_exists='replace', index=False)
    print(f'{len(df)} lignes chargées dans ref_ip_country')

with DAG(
    dag_id='dag_intrusion_pays',
    schedule=[intrusion_log_asset],
):
    extract_dbip = HttpOperator(
        task_id='extract_dbip',
        method='GET',
        endpoint='dbip-country-lite-2026-01.csv',
        http_conn_id='httpdata_nginx_intrusion',
    )
    filter_ipv4 = PythonOperator(
        task_id='filter_ipv4',
        python_callable=process_filter_ipv4,
    )
    load_ip_country = PythonOperator(
        task_id='load_ip_country',
        python_callable=process_convert_and_load_ip_country,
    )

    extract_dbip >> filter_ipv4 >> load_ip_country

with DAG(
    dag_id='dag_intrusion_db',
    schedule=None,
):
    create_result_table = SQLExecuteQueryOperator(
        task_id='create_result_table',
        conn_id='datawarehouse',
        sql="""
            CREATE TABLE IF NOT EXISTS intrusion_logs_enriched (
                source_ip       TEXT,
                destination_ip  TEXT,
                port            INTEGER,
                request_type    TEXT,
                payload_size    INTEGER,
                user_agent      TEXT,
                status          TEXT,
                intrusion       TEXT,
                country_code    TEXT
            );
        """,
    )

    map_and_load = SQLExecuteQueryOperator(
        task_id='map_and_load',
        conn_id='datawarehouse',
        sql="""
            TRUNCATE TABLE intrusion_logs_enriched;

            INSERT INTO intrusion_logs_enriched (
                source_ip, destination_ip, port, request_type,
                payload_size, user_agent, status, intrusion, country_code
            )
            SELECT
                l."Source_IP",
                l."Destination_IP",
                l."Port",
                l."Request_Type",
                l."Payload_Size",
                l."User_Agent",
                l."Status",
                l."Intrusion",
                r.country_code
            FROM staging_intrusion_logs l
            LEFT JOIN ref_ip_country r
                ON (
                    -- Conversion IP texte en entier pour la comparaison de plages
                    split_part(l."Source_IP", '.', 1)::BIGINT * 16777216 +
                    split_part(l."Source_IP", '.', 2)::BIGINT * 65536 +
                    split_part(l."Source_IP", '.', 3)::BIGINT * 256 +
                    split_part(l."Source_IP", '.', 4)::BIGINT
                ) BETWEEN r.ip_start_int AND r.ip_end_int;
        """,
    )

    create_result_table >> map_and_load