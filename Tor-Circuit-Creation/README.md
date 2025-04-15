### Steps to run
1. Add these 3 lines to `torrc` file:
```
ControlPort 9051
CookieAuthentication 1
UseMicrodescriptors 0
```
2. Run the following command to start Tor with the new configuration:
```bash
tor -f <path_to_torrc_file>
```
3. Activate a python virtual environment and install the required packages:
```bash
python3 -m venv venv
source venv/bin/activate
pip3 install pycurl stem
```
4. Change the path to Tor cache consensus file in `selection.py` appropriately at line 139.
```python
with open("/.tor/cached-consensus", "rb") as f:
```
5. Install and run nyx in another terminal to monitor the Tor circuits:
```bash
sudo apt install nyx
nyx
```
6. Run the following command to start the script:
```bash
python3 selection.py
```
7. You shall see the output of the script and output of nyx in the terminal like the screenshots present in the report pdf that I have submitted.


### Important Notes
1. Description of how the system works and what assumptions I have made are thoroughly explained in the report pdf that I have submitted. The report also has appropriate screenshots and diagrams. Kindly refer to that for more information.
2. The script is designed to run on a Debian Linux system with Tor installed and configured properly. It may not work on other operating systems without modifications.
