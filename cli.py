import logging
import argparse



def ProxmoxCli():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s:PROXMOX:%(levelname)s:%(message)s')
    parser = argparse.ArgumentParser(description='Proxmox API Client')

    # Подкоманды
    subparsers = parser.add_subparsers(dest='command',required=True)
    # Info
    statusarg= subparsers.add_parser('info', help='Get Info about VM')
    sub_statusarg=statusarg.add_subparsers(dest='subcommand', required=True)
    # Подкоманды Info
    status_sub_statusarg = sub_statusarg.add_parser('status',help = 'Get status start/stop/pause VM by name')
    status_sub_statusarg.add_argument('--name-vm','-n',type=str, required=True,help='Virtual machine name')

    exists_sub_statusarg = sub_statusarg.add_parser('exists',help = 'Get information if the machine exists')
    exists_sub_statusarg.add_argument('--name-vm','-n',type=str, required=True,help='Virtual machine name')

    about_sub_statusarg = sub_statusarg.add_parser('about',help = 'All information about the machine')
    about_sub_statusarg.add_argument('--name-vm','-n',type=str, required=True,help='Virtual machine name')

    
    # Start
    startarg= subparsers.add_parser('start', help='Start VM by name')
    startarg.add_argument('--name','-n',type=str, required=True, help='Virtual machine name')
    # Start
    stoparg= subparsers.add_parser('stop', help='Stop VM by name')
    stoparg.add_argument('--name','-n',type=str, required=True, help='Virtual machine name')
    # Delete
    delete_vmarg= subparsers.add_parser('delete', help='Delete Virtual Machine by name')
    delete_vmarg.add_argument('--name','-n',type=str, required=True, help='Virtual machine name')
    
    # SSH Connection
    ssharg = subparsers.add_parser('ssh',help='Use SSH Client for remote VM')
    ssharg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    ssharg.add_argument('--user','-u',type=str, required=False, default='root', help='User name')
    ssharg.add_argument('--password','-p',type=str,default=None,required=False, help='Password')
    ssharg.add_argument('ssh_command', metavar='command', type=str, nargs='+',
                    help='Command to ssh')

    configarg = subparsers.add_parser('config',help='Create Config')
    configarg.add_argument('--user','-u',type=str, required=True, help='Username who has access to Proxmox')
    configarg.add_argument('--token-name','-tn',type=str,required=True, help='Token name Proxmox')
    configarg.add_argument('--token-id','-ti',type=str,required=True, help='Token ID Proxmox')
    configarg.add_argument('--ip-address-proxmox','-ip',type=str,required=True,help='IP Address where hosted Proxmox')
    configarg.add_argument('--port','-p',type=int,default=443,required=False,help='IP Address where hosted Proxmox')
    configarg.add_argument('--vmid-min','-vi',type=int,default=1000,required=False,help='Lower limit of available IDS for VM')
    configarg.add_argument('--vmid-max','-va',type=int,default=1100,required=False,help='Upper limit of available IDS for VM')

    # QEMU AGENT Connection
    agentarg = subparsers.add_parser('agent',help='Use Qemu Agent for remote execution commands')
    agentarg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    agentarg.add_argument('agent_command', metavar='command', type=str, nargs='+',
                    help='Command to ssh')

    settingsssharg = subparsers.add_parser('settings-ssh',help='Configuring the ability and access to connect to SSH Connection')
    settingsssharg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    settingsssharg.add_argument('--permit-root-login',action="store_true",help='Configuring the ability and access to connect to SSH Connection')
    settingsssharg.add_argument('--permit-password-root',action="store_true",help='Configuring the ability and access to connect to SSH Connection')
    settingsssharg.add_argument('--get-ip',action="store_true",help='Get an IP address for SSH connection through other systems')
    
    settingsssharg = subparsers.add_parser('add-public-key',help='Configuring the ability and access to connect to SSH Connection via Public Key')
    settingsssharg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    settingsssharg.add_argument('--path-to-public-key','-pk',type=str,required=True,help='Host path to public key, e.g. /root/.ssh/id_rsa.pub')
    settingsssharg.add_argument('--path-to-authorized-keys','-ak',type=str,required=True,help='Path to list authorized keys on remote machine/VM, e.g. /root/.ssh/')

    clonearg = subparsers.add_parser('clone', help='Cloning a virtual machine from a base one')
    clonearg.add_argument('--base-name','-b',type=str, required=True)
    clonearg.add_argument('--new-name','-n',type=str, required=True)
    clonearg.add_argument('--snapname','-s',type=str,default='ready_for_test')

    snapshotarg= subparsers.add_parser('snapshot', help='Snapshot functions')
    # Подкоманда подкоманды
    sub_snapshotarg=snapshotarg.add_subparsers(dest='subcommand', required=True)
    create_snapshots_arg = sub_snapshotarg.add_parser('create',help = 'Create snapshot VM by name')
    create_snapshots_arg.add_argument('--name-vm','-n',type=str, required=True,help='Virtual machine name')
    create_snapshots_arg.add_argument('--snapname','-s',type=str,required=True,help='Snapshot name')

    reset_snapshots_arg = sub_snapshotarg.add_parser('reset',help = 'Reset snapshot VM by name')
    reset_snapshots_arg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    reset_snapshots_arg.add_argument('--snapname','-s',type=str,required=True, help='Snapshot name')

    delete_snapshots_arg = sub_snapshotarg.add_parser('delete',help = 'Delete snapshot VM by name')
    delete_snapshots_arg.add_argument('--name-vm','-n',type=str, required=True, help='Virtual machine name')
    delete_snapshots_arg.add_argument('--snapname','-s',type=str,required=True, help='Snapshot name')
    
    # snapshotarg.add_argument('--name','-n',type=str, required=True)
    # snapshotarg.add_argument('--snapname','-s',type=str, required=True)

    parser.add_argument('--exec_command',type=str, nargs='+', help='Run command on remote virtual machine, e.g "ls -la" ')
    parser.add_argument('--scp_to_vm',type=str, nargs='+',help='Copy files from host machine to VM')
    parser.add_argument('--scp_from_vm',type=str, nargs='+',help='Copy files from VM to host machine')
    
    optionFunc = parser.parse_args()
    from api import ProxmoxAPI
    proxmoxApi = ProxmoxAPI()

    return optionFunc, proxmoxApi