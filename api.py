
import requests
import os
import sys
import urllib3
import subprocess
import configparser
import logging
import socket
import paramiko

from pathlib import Path
from time import sleep

NODES = 'nodes'
PXMX = 'pxmx'
QEMU = 'qemu'
STATUS = 'status'
CURRENT = 'current'
AGENT = 'agent'
SET_USER_PASSWORD = 'set-user-password'
CLONE = 'clone'
TYPE_REQUEST = 'typeRequest'
API_PATH = 'path'
START = 'start'
EXEC_STATUS = 'exec-status'
STOP = 'stop'
EXEC = 'exec'
# Types methods request
GET_REQUEST = 'GET'
POST_REQUEST = 'POST'
PUT_REQUEST = 'PUT'
DELETE_REQUEST = 'DELETE'
SNAPSHOT = 'snapshot'

class ProxmoxAPI:
    # Подробнее  можно посмотреть здесь
    # https://github.com/proxmoxer/proxmoxer/blob/develop/proxmoxer/backends/https.py
    def __init__(self):
        urllib3.disable_warnings()
        self.rootPath = Path(__file__).parent.resolve()
        config = configparser.ConfigParser()
        self.config_path = self.rootPath / 'config.ini'
        try:
            config.read(self.config_path)
            self.username = config['Authorization']['username']
            self.realm = None if '@' in self.username else self.username.split('@')[-1]
            self.tokenName = config['Authorization']['tokenName']
            self.tokenID = config['Authorization']['tokenID']
            self.ipAddress = config['Authorization']['ipAddressProxmox']
        

            self.service = 'PVE'
            self.port = int(config['Authorization']['port'])
            self.minVMID = int(config['Settings']['minVMID'])
            self.maxVMID = int(config['Settings']['maxVMID'])
        except KeyError as e:
            logging.error(e)
        
        if not 'Windows' in str(os.environ.get('OS')):
            import pwd
            self.user_host = pwd.getpwuid(os.getuid())[0]
        self.verify = False


    def set_config(self,username,token_name,token_id,ip_address,port,**kwargs):
        config = configparser.ConfigParser()
        config['Authorization'] ={
            'username': username,
            'tokenName': token_name,
            'tokenID': token_id,
            'ipAddressProxmox': ip_address,
            'port':port
        }

        config['Settings'] = {
            'minVMID': kwargs.get('vmid_min','1000'),
            'maxVMID': kwargs.get('vmid_max','1100')
        }
        with open(self.config_path, 'w') as configfile:
            config.write(configfile)
        logging.info(f'Config was created: {self.config_path}')
    def _check_lock(self, vmid,expected_status,delay=10):
        status = expected_status
        while status == expected_status:
            response = self._request_hieracly(GET_REQUEST,NODES,PXMX,QEMU,vmid,STATUS,CURRENT)[0].json()
            status = response['data'].get('lock')
            sleep(delay)
    
    def _set_user_password(self,vmid):
        response = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,AGENT,SET_USER_PASSWORD)
    def _request_hieracly(self,type_req,*items,options={},**kwargs):
        addit = "/".join(items)
        url = f'https://{self.ipAddress}:{self.port}/api2/json/{addit}'

        headers = {'Authorization':"{0}APIToken={1}!{2}={3}".format(self.service, self.username, self.tokenName, self.tokenID)}

        query = ["=".join([ite[0],ite[1]]) for ite in kwargs.items()]
        query = "?" + "&".join(query)
    
        def _output_request(responseObj):
             if responseObj.status_code != 200:
                # logging.info(responseObj.request.url)
                # logging.info(responseObj.text)
                errorTemplate = f'Error {type_req} request {url} Status code: {responseObj.status_code}\nReason: {responseObj.reason}'
                if responseObj.reason == 'No QEMU guest agent configured':
                    errorTemplate+="\nSolution: Install on a virtual machine QEMU guest agent\n\t Doc: https://pve.proxmox.com/wiki/Qemu-guest-agent "
                    logging.error(errorTemplate)
                    sys.exit(1)
                raise AssertionError(errorTemplate)

        if type_req == 'GET':
            responseObj = requests.get(url+query, verify=self.verify,headers=headers)
            _output_request(responseObj)
        elif type_req == 'POST':
            responseObj = requests.post(url, verify=self.verify,headers=headers,json=kwargs)
            _output_request(responseObj)
        elif type_req == 'DELETE':
            responseObj = requests.delete(url+query, verify=self.verify,headers=headers)
            _output_request(responseObj)
        elif type_req == 'PUT':
            responseObj = requests.put(url, verify=self.verify,headers=headers,json=kwargs)
            _output_request(responseObj)
        else:
            raise AssertionError(f'Type requests <{type_req}> is not supported')

        return responseObj, responseObj.status_code
        
    def get_all_virtual_machines(self):
        response = self._request_hieracly(GET_REQUEST,NODES,PXMX,QEMU)
        return response[0].json()

    def get_id_from_name_vm(self,name_vm,useprefix=False, error=True):
        '''
            useprefix: adding the project name to the beginning of the vm name
        '''
        if useprefix:
            name_vm = f'{self.nameProject}-{name_vm}'
        all_vm = self.get_all_virtual_machines()['data']
        id_vm = None
        for vm in all_vm:
            if vm['name'] == name_vm:
                id_vm = vm['vmid']
                break
        if error:
            if not id_vm:
                logging.error(f'The virtual machine: "{name_vm}" is`t exists ')
                sys.exit(1)
        return id_vm
    
    def get_status_vm(self,ids):
        response = self._request_hieracly(GET_REQUEST,NODES,PXMX,QEMU,ids,STATUS,CURRENT)
        return response[0].json()

    def start_vm(self, vmid):
        statusLast = self.get_status_vm(vmid)
        statusLast = statusLast['data']['status']
        if statusLast != 'running':
            response = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,STATUS,START)
            self.ping_vm(vmid)
            return response[0].json()
        else:
            self.ping_vm(vmid)
            logging.info('The virtual machine has already been started!')
            return 
    
    def stop_vm(self, vmid):

        statusLast = self.get_status_vm(vmid)
        statusLast = statusLast['data']['status']
        if statusLast != 'stopped':
            response = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,STATUS,STOP)
            self._check_lock(vmid,'stop')
            logging.info('The virtual machine now is stopped!')
            return response[0].json()
        else:
            logging.info('The virtual machine has already been stopped!')
            return 
    
    def exec_command(self,vmid,command_line):
        response = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,AGENT,EXEC,command=command_line)
        response = response[0].json()
        pid = response['data']['pid']
        response = self._request_hieracly(GET_REQUEST,NODES,PXMX,QEMU,vmid,AGENT,EXEC_STATUS,pid=str(pid))
        try:
            outdata = response[0].json()
            outdata = outdata['data']["out-data"]
        except KeyError:
            outdata = ''
        return outdata
    
    def create_clone(self,vmid,name_new_vm,snapname=None,useprefix=False):
        logging.info(f'New name VM: {name_new_vm}')
        exists_vmids = self.get_all_virtual_machines()['data']
        exists_vmids =  tuple(int(v['vmid']) for v in exists_vmids)
        
        new_vmid = self.get_id_from_name_vm(name_new_vm,useprefix=useprefix, error=False)
        if new_vmid:
            self.get_status_vm(new_vmid)
            logging.error(f'A virtual machine named "{name_new_vm}" already exists!')
            return

        prepare_vmid = int(vmid)
        prepare_vmid = prepare_vmid if prepare_vmid>=self.minVMID else self.minVMID
        countTry = self.maxVMID-self.minVMID
        createVM = False
        logging.info('The virtual machine is being cloned...')
        kwargsArgs = {
            'name': name_new_vm,
        }
        if snapname:
            kwargsArgs['snapname'] = snapname
        
        if countTry <=0:
            logging.error(f'IDs ran out: [{self.minVMID,self.maxVMID}]')
            sys.exit(1)

        for _ in range(countTry):
            prepare_vmid+=1
            try:
                r = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,CLONE,newid=str(prepare_vmid),**kwargsArgs)
                createVM = True
                break
            except AssertionError as e:
                if 'Parameter verification failed' in e.args[0]:
                    logging.error(e)
                    sys.exit(1)
                continue
            
        if not createVM:
            logging.info(f'A virtual machine with the same name already exists!\nIDS range: [{self.minVMID,self.maxVMID}]')
        else:
            self._check_lock(str(prepare_vmid),'clone')
            logging.info('Clone has been completed!')

    
    def delete_vm(self,vmid):
        self._request_hieracly(DELETE_REQUEST,NODES,PXMX,QEMU,vmid)
        for i in range(10):
            try:
                self.get_status_vm(vmid)
                sleep(i*3)
            except:
                break
        logging.info('VM was deleted')
                

    def reset_snapshot(self,vmid,snapshot_name):
        response = self._request_hieracly(POST_REQUEST,NODES,PXMX,QEMU,vmid,SNAPSHOT,snapshot_name,'rollback')
        status = 'rollback'
        while status == 'rollback':
            response = self._request_hieracly('GET','nodes','pxmx','qemu',vmid,'status','current')[0].json()
            status = response['data'].get('lock')
            sleep(5)
        logging.info('Rollback has been completed!')

    def ping_vm(self,vmid):
        count = 1000
        for ty in range(count):
            try:
                r = self.get_status_vm(vmid)
                ballooninfo = r['data']['ballooninfo']
                statusBallonInfo = [
                    ballooninfo.get('free_mem',),
                    ballooninfo.get('last_update'),
                    ballooninfo.get('total_mem'),
                    ballooninfo.get('minor_page_faults'),
                    ballooninfo.get('total_mem'),
                    ballooninfo.get('max_mem')
                ]
                resTypes = [int(v) for v in statusBallonInfo if int(v)>0]
                assert len(statusBallonInfo) == len(resTypes)
            except Exception:
                logging.info(f'Trying to get full started VM... {ty+1}')
                sleep(20)
                continue
            
            try:
                self._request_hieracly('POST','nodes','pxmx','qemu',vmid,'agent','ping')
                break
            except AssertionError:
                logging.info(f'Trying to ping full started VM... {ty+1}')
                sleep(20)
                continue
        else:
            logging.error('VM is not available for work!')
            sys.exit(1)

        logging.info('VM is available for work!')

    def copy_files_folders(self,vmid,path_source:Path,path_target:Path,toVM=True):
        ip_addr = self.get_ip_address(vmid)
        
        self.exec_command(vmid,f'mkdir -p {path_target}')
        if toVM:
            ssh_st = f'scp -r {path_source}* root@{ip_addr}:{path_target}'
        else:
            ssh_st = f'scp -r root@{ip_addr}:{path_source} {path_target}'
        subprocess.run(ssh_st,shell=True,check=True)
    
        # ss = f'chown -R {self.user_host}: {path_target}'
        # subprocess.check_output(ss,shell=True)
       
    

    def get_ip_address(self,vmid):
        count = 100
        sleepInterval = 10

        def _expression_check_eth(name) -> bool:
            type_devices = ['eth0', 'ens']
            for tp in type_devices:
                if tp in name:
                    return True
            return False

        for tt in range(count):
            try:
                response = self._request_hieracly('GET','nodes','pxmx','qemu',vmid,'agent','network-get-interfaces')[0].json()
                response = response['data']['result']
                ips = [v for v in response if _expression_check_eth(v['name'])][0]['ip-addresses']
                ips = [ip for ip in ips if ip['ip-address-type']=='ipv4'][0]['ip-address']
                socket.inet_aton(ips)
                return ips
            except KeyError:
                logging.info(f'Trying to get IP: {tt+1} ')
                sleep(sleepInterval)
            
            except IndexError:
                logging.info(f'Trying to get IP: {tt+1} ')
                sleep(sleepInterval)
            
        logging.error('Failed to get IP')
        sys.exit(1)

    def _read_file(self,vmid,file_path) -> str:
        rsp = self._request_hieracly('GET','nodes','pxmx','qemu',vmid,'agent','file-read',file=file_path)
        return rsp[0].json()['data']['content']

    def _write_file(self,vmid,content,file_path):
        rsp = self._request_hieracly('POST','nodes','pxmx','qemu',vmid,'agent','file-write',content=content,file=file_path)
        return rsp[0].json()
    
    def _exec_command_with_ssh(self, vmid:int,username, command:str,password=None, port=22):
        ip_addr = self.get_ip_address(vmid)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=ip_addr,username=username,password=password,port=port)
        # ssh_st = f'ssh {username}@{ip_addr} {command}'
        stdin, stdout, stderr = client.exec_command(command)
        stderr = stderr.read().decode()
        stdout = stdout.read().decode()
        client.close()
        if stderr:
            logging.error(stderr)
            sys.exit(1)
        data:bytes = stdout + stderr
        logging.info(data)
    
    def adding_public_key_on_remote_machine(self,vmid, path_authkeys:str,path_pubkey, name_authorized_keys='authorized_keys'):
        pathAuthorizedKeys:Path = Path(path_authkeys) / name_authorized_keys
        pathPublicKeys = Path(path_pubkey)

        if pathPublicKeys.exists():
            publicKey = open(pathPublicKeys).read()
        else:
            raise AssertionError(f'Encryption keys not generated for path: {path_pubkey}')

        try:
            contentAuthorizedKeys:str = self._read_file(vmid,str(pathAuthorizedKeys))
            if publicKey not in contentAuthorizedKeys:
                if contentAuthorizedKeys.endswith('\n'):
                    contentAuthorizedKeys+=f"{publicKey}\n"
                else:
                    contentAuthorizedKeys+=f"\n{publicKey}\n"

                self._write_file(vmid,contentAuthorizedKeys,str(pathAuthorizedKeys))
                logging.info('Public key has been added successfully!')
            else:
                logging.info('Public key already added successfully!')

        except Exception as e:
            if 'No such file' in e.args[0]:
                contentAuthorizedKeys = f"{publicKey}\n"
                self.exec_command(vmid,f'mkdir -p {pathAuthorizedKeys.parent}')
                self._write_file(vmid,contentAuthorizedKeys,str(pathAuthorizedKeys))
                logging.info('Authorized keys file was created!')
                logging.info('Public key has been added successfully!')
            else:
                raise AssertionError(e)
    
            
        

    def permit_password_root(self,vmid):
        sshd_file = self._read_file(vmid,'/etc/ssh/sshd_config')
        sshd_file = sshd_file.split('\n')
        findPermitPass = False
        nameSettingPermRoot = 'PermitRootLogin'
        permitPass = f'{nameSettingPermRoot} yes'
        if permitPass not in sshd_file:
            for index, row in enumerate(sshd_file):
                if not findPermitPass:
                    if row.startswith(nameSettingPermRoot):
                        sshd_file[index] = permitPass
                        findPermitPass = True
                    elif row.startswith('#%s'% nameSettingPermRoot):
                        sshd_file[index] = permitPass
                        findPermitPass = True
                else:
                    if row.startswith(nameSettingPermRoot):
                        sshd_file[index] = ''
                

            sshd_file = "\n".join(sshd_file)    
            self._write_file(vmid,sshd_file,'/etc/ssh/sshd_config')
            self.exec_command(vmid,'systemctl restart sshd || service ssh restart')  

    def permit_root_login(self,vmid):
        sshd_file = self._read_file(vmid,'/etc/ssh/sshd_config')
        home_directory = Path('/home') / self.user_host
        pub_key = open(home_directory / '.ssh' / 'id_rsa.pub').read()
        exception = False
        try:
            current_auther = self._read_file(vmid,'/root/.ssh/authorized_keys')
        except:
            exception = True
        if '\nPermitRootLogin yes' not in sshd_file or exception or pub_key not in current_auther:
            sshd_file = sshd_file.split('\n')
            ip_addr = self.get_ip_address(vmid)
            for index, row in enumerate(sshd_file):
                if 'PermitRootLogin' in row:
                    sshd_file[index] = 'PermitRootLogin yes'
                if 'PasswordAuthentication' in row:
                    sshd_file[index] = 'PasswordAuthentication no'
                    
            sshd_file = "\n".join(sshd_file)    
            self._write_file(vmid,sshd_file,'/etc/ssh/sshd_config')
            r = self.exec_command(vmid,'systemctl restart sshd || service ssh restart')
        
            pub_key = open(home_directory / '.ssh' / 'id_rsa.pub').read()
            self.exec_command(vmid,'mkdir -p /root/.ssh')
            self._write_file(vmid,content=pub_key,file_path='/root/.ssh/authorized_keys')
            self.exec_command(vmid,'chmod 600 /root/.ssh/authorized_keys')
            result = subprocess.run(f'ssh-keyscan -H {ip_addr} >> ~/.ssh/known_hosts',shell=True,check=True)
        
    
    def create_snapshot(self,vmid,name_new_snapshot):
        rsp = self._request_hieracly('POST','nodes','pxmx','qemu',vmid,'snapshot',snapname=name_new_snapshot,description='autocreated')
        logging.info(rsp[0].json())