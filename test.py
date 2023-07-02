#!/usr/bin/python
import json
import argparse
import psycopg2



parser = argparse.ArgumentParser()

parser.add_argument('jsonFile')
args = parser.parse_args()

with open(args.jsonFile) as datafile:
    data = json.load(datafile)

store_id=data["store_id"]
def db_connection(store_id,data):
    # Establish a connection to the PostgreSQL database
    conn = psycopg2.connect(database=data["database_name"],user=data["user"],password=data["password"],host=data["host"],port=data["port"])

    # Create a cursor object
    cursor = conn.cursor()
    sql = 'SELECT * FROM Day1_config_db'
    cursor.execute(sql)
    column_names = [desc[0] for desc in cursor.description]
    print(column_names)
    # Execute a query
    cursor.execute('SELECT * FROM Day1_config_db WHERE StoreID='+"'"+store_id+"'"+';')
    # Fetch all records
    records = cursor.fetchall()
    json_data = []
    # Process the fetched records
    for record in records:
        #print(record)
        json_row = {}
        for i, column in enumerate(column_names):
            json_row[column] = record[i]
        json_data.append(json_row)
        file_name=str(store_id)+"output"
        with open(file_name, 'w') as file:
            json.dump(json_data, file, indent=4)
        
        
# Close the cursor and the connection
    cursor.close()
    conn.close()

db_connection(store_id,data)
