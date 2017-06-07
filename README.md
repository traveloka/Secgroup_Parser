This tools is used to parsing security group from csv format to yaml

Prerequisite:
This tools is built in python, some library that need to be installed in your machine to run this tools:
- `netaddr`

How to use it:
- make sure you already downloaded csv file, or security group requierement from user
- make sure csv format is valid source, destination, from_port, to_port, proto
- all you need to do is to run the python script with command, `python SecgroupParser.py --file /path/to/csv/file.csv`

Notes:
Please pay attention for Warn message, there might be an invalid group names defined  
