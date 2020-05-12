
# GETTING COMFY INTO DK-PROXY

## First steps to start to work easier in dk-proxy

### (A and B seem to be necessary)

---

## 0) Change keyboard layout:

1. run ```cd ..``` (go to root folder)
2. run ```sudo nano /etc/default/keyboard```
3. modify ```XKBLAYOUT="de"``` to ```XKBLAYOUT="es"``` (or correspondent)
4. CTRL + O, Y, CTRL + X
5. reboot machine

## A) Installing scapy and making it available from sudo:

1. run ```sudo pip3 uninstall scapy```
2. run ```sudo pip3 install scapy```

## B) Adding scapy path to pythonpath on both, normal and sudo modes:

1. run ```which scapy```
2. (anotate returned path)
3. run ```cd ..``` (go to root folder)
4. run ```sudo nano ~/.bashrc```
5. add ```export PYTHONPATH="${PYTHONPATH}:path"```, where _path_ is the one from step 2.
6. run ```source /.bashrc```
7. run ```sudo nano etc/sudoers```
8. add ```Defaults    env_keep += PYTHONPATH```
9. reboot machine

### To check if scapy was successfully added to paths:

1. run ```python3```
2. run ```import os```
3. run ```print(os.sys.path)```
4. check if the path from step 2. is present
5. run ```exit()```
6. if present, it means scapy was successfully added to the path on that mode
7. repeat from 1. but this time running ```sudo python3```
8. reboot machine

## C) Installing git:

1. run ```sudo apt-get install git```

## D) Cloning git repository:

1. run ```cd dk-project``` (go to desired folder)
2. run ```git init```
3. run ```git clone https://www.github.com/username/repositoryname.git```, where _username_ and _repositoryname_ are the correspondent to the user and repository on github.