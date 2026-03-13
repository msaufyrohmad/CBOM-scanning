# CBOM-SCANNER

## This is the codes for scanning various types of cryptography sources in the systems.
This is the series of scrips to help organization to scan their servers and clients internally. The code run on both linux and windows but we are imporoving the windows detection.


### Cryptography in the system
<img width="1003" height="565" alt="image" src="https://github.com/user-attachments/assets/a51c4196-c402-45d9-8ea4-e5295a0c9be9" />


### Crypography in All Layers
<img width="1003" height="565" alt="image" src="https://github.com/user-attachments/assets/4d13abde-fb15-461e-b5dd-041594ee7dc0" />


### Types of Cryptographic Sources
<img width="931" height="472" alt="image" src="https://github.com/user-attachments/assets/16be887d-f637-4f00-bf61-d47e9137841a" />



## 1. DEPENCENCY LIBRAIRES INSTALLATION 

Download all codes in a directory
```bash
$git clone https://github.com/msaufyrohmad/CBOM-scanning.git
$cd CBOM-scanning
$pip install pipreqs 
$pipreqs .
$pip install -r requirements.txt
```
## 2. RUNNING SCRIPT 1 to 8 

```bash
$sudo python <script> 
```

## 3. RUNNING SCRIPT 9

### 3.1 Create directory to store results
   ``` bash
   $mkdir result
   ```
   
### 3.2 Create a file to store all tls server that you want to scan 
   ```bash
   $vim target 
   uitm.edu.my 
   upm.edu.my
   ```
    
### 3.3 Run the script
   ``` bash
   $sudo python 9NetworkProtocol.py --out-dir=result target
   ```

## 4.The code will be updated from time to time 

We are improving the scanning accuracy (even we have a few version of crypto_scan()) that we will published soon. 
The (promise) version contains:
4.1 CycloneDX v1.7 output
4.2 PTPKM information added as cycloneDX Property
4.3 Configuration inspection of Software 

## 5.Contact 
Muhammad Saufy Rohmad 

Malaysia Cryptology Technology and Management Center

saufy@uitm.edu.my

