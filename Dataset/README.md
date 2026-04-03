# Dataset

The PCAPNG files are trimmed to keep within Github file size limit, i.e. "{filename}" -> "{filename}Trim", and "{filename}" -> "{filename}-{sec}"
is {sec} of the original file. The video stream takes up the bulk of the file size. The original PCAPNG files can be downloaded from [AEVisionLab-Dataset](https://drive.google.com/drive/folders/1qfMiHUbrCk3vzuZcVE4XlRY8PSFQXIYZ?usp=share_link).

| Dataset | Description |
| :-------- | :---------- |
| 20230517_allLinks-3_5s.pcapng | Normal AE messages for 3.5 sec with video stream of the four cameras |
| 20230517_allLinksTrim.pcapng | Normal AE messages without video stream |
| 20230524_HU_SvcEavesdrop0x3544Trim.pcapng | Attack AE messages without video stream : SomeIP - Eavesdrop BDC service |
| 20230524_HU_SvcEavesdrop0x3544-1Trim.pcapng | Attack AE messages without video stream : SomeIP - Eavesdrop BDC service |
| 20230530_allLinks_Attk0x3544EavesdropTrim.pcapng | Attack AE messages without video stream : SomeIP - Eavesdrop BDC service |
| 20230606_allLinks_Attk0x3544HijackTrim.pcapng | Attack AE messages without video stream : SomeIP - Hijack BDC service |
| 20230607_allLinks_Attk0x3544HijackTrim.pcapng | Attack AE messages without video stream : SomeIP - Hijack BDC service |
| 20230608_allLinks_Attk0x3544HijackTrim.pcapng | Attack AE messages without video stream : SomeIP - Hijack BDC service |
| 20230608_allLinks_Attk0x3544Hijack-1Trim.pcapng | Attack AE messages without video stream : SomeIP - Hijack BDC service |
| 20230619_allLinks_Attk0x3531Hijack117Trim.pcapng | Attack AE messages without video stream : SomeIP - Hijack TSRVC service |
| latency_test_ifc5-8-2s.pcapng | Bridged AE messages for 2s with video stream of the front camera |

## Some/IP Attack Datasets Distribution

### SomeIP - Eavesdrop BDC service attack
TSRVC (160.48.199.117) sends service 0x3544 to both BDC (160.48.199.16) and attacker (160.48.199.99).
| Dataset File | Sets of Messages |
| :----------- | :--------------: |
| 20230524_HU_SvcEavesdrop0x3544.pcapng | 17 |
| 20230524_HU_SvcEavesdrop0x3544-1.pcapng | 15 |
| 20230530_allLinks_Attk0x3544Eavesdrop.pcapng | 16 |

### SomeIP - Hijack BDC service attack
TSRVC (160.48.199.117) sends service 0x3544 to attacker (160.48.199.99) and then attacker sends to BDC (160.48.199.16).
| Dataset File | Sets of Messages |
| :----------- | :--------------: |
| 20230606_allLinks_Attk0x3544Hijack.pcapng | 21 |
| 20230607_allLinks_Attk0x3544Hijack.pcapng | 15 |
| 20230608_allLinks_Attk0x3544Hijack.pcapng | 8 |
| 20230608_allLinks_Attk0x3544Hijack-1.pcapng | 6 |

### SomeIP - Hijack TSRVC service attack
BDC (160.48.199.16)  sends service 0x3531 to attacker (160.48.199.99) and then attacker sends to TSRVC (160.48.199.117).
| Dataset File | Sets of Messages |
| :----------- | :--------------: |
| 20230619_allLinks_Attk0x3531Hijack117.pcapng | 5 |

## Tools

The accompanying python tools can facilitate smooth usage of our datasets:

| Tool | Description | Example Usage |
| :-------- | :-------- |:--------|
| [pcap_videolinkV1.py](./pcap_videolinkV1.py) | View the video stream extracted from an AE link on the screen and extract the individual video frames to a local folder, *./jfif* . | *python3 pcap_videolinkV1.py --pcap <pcap_filename> --link <link_ID>*, e.g. *python3 pcap_videolinkV1.py --pcap 20230517_allLinks.pcapng  --link 6* | 
| [pcap_ProInfoV1.py](./pcap_ProInfoV1.py) | Extracts and decodes protocol information used in an AE link. Such information is stored in a text file attributed to each protocol. The text files are saved in a local folder, *./ProInfo* . | *python3 pcap_ProInfoV1.py --pcap <pcap_filename> --link <link_ID>*, e.g. *python3 pcap_ProInfoV1.py --pcap 20230517_allLinks.pcapng  --link 5* |

The extracted video frames can be displayed using the two python programs, [read_jfifV1.py](../read_jfifV1.py) and [read_jfif_videoV1.py](../read_jfif_videoV1.py).

### Automotive Ethernet (AE) Link

| *link_ID* | ECU | IP Address |
| :-------- | :-------- |:--------|
| 1 | Headunit (HU) | 160.48.199.99 |
| 2 | Body Domain Controller (BDC) | 160.48.199.16 |
| 3 | Camera ECU (TSRVC) | 160.48.199.117 |
| 4 | Body Domain Controller (BDC) | 160.48.199.16 |
| 5 | Camera ECU (TSRVC) | 160.48.199.6 |
| 6 | Front Camera (Fcam) | 160.48.199.12 |
| 7 | Camera ECU (TSRVC) | 160.48.199.6 |
| 8 | Driver Camera (Dcam) | 160.48.199.10 | Master |
| 9 | Camera ECU (TSRVC) | 160.48.199.6 |
| 10 | Passenger Camera (Pcam) | 160.48.199.8 |
| 11 | Camera ECU (TSRVC) | 160.48.199.6 |
| 12 | Rear Camera (Rcam) | 160.48.199.7 |

### Protocol Decoded Information

| File Name | Protocol |
| :-------- | :-------- |
| arp.txt | ARP |
| avtp.txt | IEEE1722 (AVTP) |
| others.txt | Unknown |
| ptpV2.txt | IEEE1588 (PTPv2) |
| someIP.txt | Some/IP (Services) |
| someIP-SD.txt | Some/IP (Discovery) |
| udp.txt | UDP |
