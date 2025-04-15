## Usage:
1. Copy the ```detector.lua``` file to the default Wireshark plugins directory. This is usually located at: ```C:\Users\<username>\AppData\Roaming\Wireshark\plugins``` on Windows (idk about Linux).
2. Download the public tor relays list from https://www.dan.me.uk/tornodes as ```tor_relays.txt``` and update the path to this relays list file in ```detector.lua:25```.
3. Restart Wireshark and open the provided pcap file - ```p3.pcapng```. 
    - Right click on the column bar and select "Column Preferences".
    - Add a new column by clicking the "+" button. 
    - Set title as "Tor Status" or anything you want, doesn't really matter. 
    - Select type as "Custom" and field as "tor_detect.status". 
    - Click OK and then click OK again to close the preferences window. 

Voila! You should see a new column with the Tor status of each packet - whether it is Tor (```"Tor!"```) or not (empty).

Additionally, all tor packets' rows will be highlighted in red. 