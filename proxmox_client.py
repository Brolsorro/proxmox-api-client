#!/usr/local/bin/python3
import logging

from cli import ProxmoxCli



if __name__ == '__main__':
    
    optionFunc,proxmoxApi = ProxmoxCli()
    usePrefixStatus = False
    if optionFunc.command == 'start':
        name_vm = optionFunc.name
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.start_vm(vmid)

    if optionFunc.command == 'info':
        if optionFunc.subcommand == 'about':
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            result = proxmoxApi.get_status_vm(vmid)
            import json
    
            result = json.dumps(result)
            print(result)

        if optionFunc.subcommand == 'status':
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            result = proxmoxApi.get_status_vm(vmid)['data']['status']
            print(result)
        
        if optionFunc.subcommand == 'exists':
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            proxmoxApi.get_status_vm(vmid)
            print(f'{name_vm} is exists!')

    if optionFunc.command == 'stop':
        name_vm = optionFunc.name
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.stop_vm(vmid)

    if optionFunc.command == 'delete':
        name_vm = optionFunc.name
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.delete_vm(vmid)

    if optionFunc.command == 'config':
        proxmoxApi.set_config(
            username=optionFunc.user,
            token_name=optionFunc.token_name,
            token_id=optionFunc.token_id,
            ip_address=optionFunc.ip_address_proxmox,
            port=optionFunc.port,
            vmid_min = optionFunc.vmid_min,
            vmid_max = optionFunc.vmid_max
        )

    if optionFunc.exec_command:
        name_vm = optionFunc.exec_command[0]
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi._exec_command_with_ssh(vmid,optionFunc.exec_command[1])
    
    if optionFunc.command == 'clone':
        name_base_vm = optionFunc.base_name
        name_new_vm = optionFunc.new_name
        snapshot = optionFunc.snapname
        vmid = proxmoxApi.get_id_from_name_vm(name_base_vm,useprefix=usePrefixStatus)
        proxmoxApi.create_clone(vmid,name_new_vm,snapshot,usePrefixStatus)
    
    if optionFunc.command == 'snapshot':
        if optionFunc.subcommand == 'reset':
            name_vm = optionFunc.name_vm
            snapshot_name = optionFunc.snapname
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            proxmoxApi.reset_snapshot(vmid,snapshot_name)

        if optionFunc.subcommand == 'create':
            name_vm = optionFunc.name_vm
            snapshot_name = optionFunc.snapname
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            proxmoxApi.create_snapshot(vmid,snapshot_name)

        if optionFunc.subcommand == 'delete':
            name_vm = optionFunc.name_vm
            logging.info('НЕ РЕАЛИЗОВАНА!')

    if optionFunc.command == 'settings-ssh':
        if optionFunc.permit_root_login:
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            proxmoxApi.permit_root_login(vmid)
        if optionFunc.permit_password_root:
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            proxmoxApi.permit_password_root(vmid)
        elif optionFunc.get_ip:
            name_vm = optionFunc.name_vm
            vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
            print(proxmoxApi.get_ip_address(vmid))
        else:
            print('Action is not selected! Try --help')

    if optionFunc.command == 'add-public-key':
        name_vm = optionFunc.name_vm
        path_to_publickey = optionFunc.path_to_public_key
        path_to_authkeys = optionFunc.path_to_authorized_keys
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.adding_public_key_on_remote_machine(vmid,path_to_authkeys,path_to_publickey)

    if optionFunc.command == 'agent':
        name_vm = optionFunc.name_vm
        command = " ".join(optionFunc.agent_command)
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        print(proxmoxApi.exec_command(vmid,command))

    if optionFunc.command == 'ssh':
        name_vm = optionFunc.name_vm
        password = optionFunc.password
        command = " ".join(optionFunc.ssh_command)
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi._exec_command_with_ssh(vmid,optionFunc.user, command,password)
    
    if optionFunc.scp_to_vm:
        name_vm = optionFunc.scp_to_vm[0]
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.copy_files_folders(vmid,optionFunc.scp_to_vm[1],optionFunc.scp_to_vm[2])
    
    if optionFunc.scp_from_vm:
        name_vm = optionFunc.scp_from_vm[0]
        vmid = proxmoxApi.get_id_from_name_vm(name_vm,useprefix=usePrefixStatus)
        proxmoxApi.copy_files_folders(vmid,optionFunc.scp_from_vm[1],optionFunc.scp_from_vm[2],toVM=False)
    