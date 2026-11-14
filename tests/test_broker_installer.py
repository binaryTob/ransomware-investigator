"""Installer tests use only synthetic files/mocked administration; never root."""
import ast
import copy
import importlib.util
import json
import os
import socket
import stat
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ROOT, ProjectTest

spec = importlib.util.spec_from_file_location('ri_installer_tests', ROOT / 'admin/broker_installer.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def facts(path):
    return {'path':path, 'resolved':path, 'sha256':'a'*64, 'mode':0o755, 'uid':0, 'gid':0,
            'size_bytes':1, 'identity':[1, 2, 1, 3, 4, 1]}


def plan():
    import pwd
    user = pwd.getpwuid(os.getuid())
    payloads = {name: ('SYNTHETIC ONLY ' + name).encode() for name in installer.FILES}
    doc = {'schema_version':1, 'operation':'first_install_only', 'operator_uid':os.getuid(),
           'operator_gid':user.pw_gid, 'operator_name':user.pw_name,
           'payloads':{name:installer.sha(data) for name,data in payloads.items()},
           'dependencies':[facts(p) for p in (*installer.TOOLS, '/etc/ld.so.cache')],
           'unit_sha256':installer.sha(installer.unit_bytes(user.pw_gid)), 'bootstrap_sha256':'b'*64,
           'actions':list(installer.ACTIONS), 'physical_read_authorized':False}
    return doc, payloads


class BrokerInstallerTests(ProjectTest):
    def test_payload_copy_rejects_symlink_hardlink_fifo_size_and_changed_bytes(self):
        path = self.work / 'input'; path.write_bytes(b'SYNTHETIC')
        self.assertEqual(installer.read_regular(path), b'SYNTHETIC')
        link = self.work / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): installer.read_regular(link)
        hardlink = self.work / 'hard'; os.link(path, hardlink)
        with self.assertRaises(installer.InstallError): installer.read_regular(path)
        fifo = self.work / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(installer.InstallError): installer.read_regular(fifo)
        other = self.work / 'bounded'; other.write_bytes(b'12345')
        with self.assertRaises(installer.InstallError): installer.read_regular(other, cap=4)

    def test_plan_rejects_root_extra_commands_paths_grants_and_boolean_schema(self):
        good, _ = plan(); installer.validate_plan(good)
        for key,value in (('operator_uid',0), ('schema_version',True), ('physical_read_authorized',True),
                          ('operation','upgrade_and_fix_permissions'), ('actions',['mount','install'])):
            bad = copy.deepcopy(good); bad[key] = value
            with self.subTest(key=key), self.assertRaises(installer.InstallError): installer.validate_plan(bad)
        bad = copy.deepcopy(good); bad['payloads']['shell.sh']='a'*64
        with self.assertRaises(installer.InstallError): installer.validate_plan(bad)
        for path in ('/dev/SYNTHETIC', '/proc/1/environ', '/home/SYNTHETIC/evidence', '/usr/../dev/x'):
            bad=copy.deepcopy(good); bad['dependencies'][0]['path']=path
            with self.subTest(path=path), self.assertRaises(installer.InstallError): installer.validate_plan(bad)
        bad=copy.deepcopy(good); bad['dependencies']=[]
        with self.assertRaises(installer.InstallError): installer.validate_plan(bad)

    def test_hash_or_dependency_change_stops_before_privilege_request(self):
        doc,payloads=plan(); bundle=self.work/'bundle'; bundle.mkdir()
        # This normal-user launcher itself must also match the plan.
        doc['payloads']['broker_installer.py']=installer.sha(Path(installer.__file__).read_bytes())
        payloads['broker_installer.py']=Path(installer.__file__).read_bytes()
        for name,data in payloads.items(): installer.write_new(bundle/name,data)
        installer.write_new(bundle/'bootstrap.py',b'SYNTHETIC bootstrap')
        doc['bootstrap_sha256']=installer.sha(b'SYNTHETIC bootstrap')
        installer.write_new(bundle/'plan.json',installer.canonical(doc))
        approved=installer.sha(installer.canonical(doc))
        with patch.object(installer.subprocess,'run',side_effect=AssertionError('No privilege request')):
            with self.assertRaises(installer.InstallError): installer.launch(bundle/'plan.json','c'*64)
            (bundle/'core.py').write_bytes(b'CHANGED SYNTHETIC')
            with self.assertRaises(installer.InstallError): installer.launch(bundle/'plan.json',approved)

    def test_launch_is_one_os_authentication_attempt_without_password_or_fallback(self):
        doc,payloads=plan(); bundle=self.work/'bundle'; bundle.mkdir()
        payloads['broker_installer.py']=Path(installer.__file__).read_bytes()
        doc['payloads']['broker_installer.py']=installer.sha(payloads['broker_installer.py'])
        for name,data in payloads.items(): installer.write_new(bundle/name,data)
        bootstrap=b'# SYNTHETIC: never execute\n'; doc['bootstrap_sha256']=installer.sha(bootstrap)
        installer.write_new(bundle/'bootstrap.py',bootstrap)
        installer.write_new(bundle/'plan.json',installer.canonical(doc))
        result=SimpleNamespace(returncode=126,stdout=b'',stderr=b'SYNTHETIC auth denied')
        with patch.object(installer,'verify_dependencies'),patch.object(installer.subprocess,'run',return_value=result) as call:
            with self.assertRaises(installer.InstallError): installer.launch(bundle/'plan.json',installer.sha(installer.canonical(doc)))
        self.assertEqual(call.call_count,1)
        argv=call.call_args.args[0]
        self.assertEqual(argv[:7],['/usr/bin/pkexec','--disable-internal-agent','/usr/bin/python3','-I','-S','-B','-c'])
        self.assertFalse(call.call_args.kwargs['shell'])
        self.assertEqual(call.call_args.kwargs['stdin'],installer.subprocess.DEVNULL)
        self.assertTrue((bundle/'launch-receipt.json').is_file())

    def test_launcher_os_error_keeps_unconfirmed_receipt_and_never_retries_elevation(self):
        doc,payloads=plan(); bundle=self.work/'bundle'; bundle.mkdir()
        payloads['broker_installer.py']=Path(installer.__file__).read_bytes()
        doc['payloads']['broker_installer.py']=installer.sha(payloads['broker_installer.py'])
        for name,data in payloads.items(): installer.write_new(bundle/name,data)
        bootstrap=b'# SYNTHETIC bootstrap\n'; doc['bootstrap_sha256']=installer.sha(bootstrap)
        installer.write_new(bundle/'bootstrap.py',bootstrap)
        installer.write_new(bundle/'plan.json',installer.canonical(doc))
        with patch.object(installer,'verify_dependencies'),patch.object(installer.subprocess,'run',side_effect=PermissionError('SYNTHETIC cannot signal elevated process')) as call:
            with self.assertRaises(installer.InstallError): installer.launch(bundle/'plan.json',installer.sha(installer.canonical(doc)))
        self.assertEqual(call.call_count,1)
        receipt=json.loads((bundle/'launch-receipt.json').read_bytes())
        self.assertEqual(receipt['status'],'execution_unconfirmed')
        self.assertFalse(receipt['automatic_retry'])

    def test_dependency_facts_hash_mode_and_identity_changes_are_not_repaired(self):
        doc,_=plan()
        original=copy.deepcopy(doc['dependencies'][0])
        for key,value in (('sha256','c'*64),('mode',0o777),('identity',[1,99,1,3,4,1])):
            changed={**original,key:value}
            with self.subTest(key=key),patch.object(installer,'dependency_facts',return_value=changed):
                with self.assertRaises(installer.InstallError): installer.verify_dependencies(doc)

    def test_unit_never_mounts_changes_ro_enables_boot_or_auto_restarts(self):
        unit=installer.unit_bytes(1234).decode()
        self.assertIn('--serve --socket-gid 1234',unit)
        self.assertIn('-I -S -B',unit)
        self.assertIn('Restart=no',unit)
        self.assertIn('KillMode=control-group',unit)
        for denied in ('ExecStartPre=', 'PrivateMounts=', 'PrivateDevices=', '[Install]', 'BLKROSET','mount '):
            self.assertNotIn(denied,unit)

    def test_elf_class_and_machine_distinguish_multilib_without_executing_binaries(self):
        def header(cls,machine):
            value=bytearray(20); value[:4]=b'\x7fELF'; value[4]=cls; value[5]=1; value[18:20]=machine.to_bytes(2,'little')
            return bytes(value)
        self.assertNotEqual(installer.elf_arch(header(1,3)),installer.elf_arch(header(2,62)))
        self.assertIsNone(installer.elf_arch(b'SYNTHETIC non-ELF'))
        with self.assertRaises(installer.InstallError): installer.elf_arch(b'\x7fELF')

    def test_multilib_resolution_requires_matching_architecture_and_rejects_ambiguity(self):
        def header(cls,machine):
            value=bytearray(20); value[:4]=b'\x7fELF'; value[4]=cls; value[5]=1; value[18:20]=machine.to_bytes(2,'little')
            return bytes(value)
        worker=self.work/'worker'; worker.write_bytes(header(2,62))
        lib32=self.work/'lib32'; lib32.write_bytes(header(1,3))
        lib64=self.work/'lib64'; lib64.write_bytes(header(2,62))
        with patch.object(installer,'trusted',side_effect=lambda p,**kw:Path(p)),patch.object(installer,'run',return_value='(NEEDED) Shared library: [libSYNTH.so]'):
            self.assertEqual(installer.elf_edges(worker,'SYNTHETIC_READELF',{'libSYNTH.so':[str(lib32),str(lib64)]}),[str(lib64)])
            other=self.work/'other64'; other.write_bytes(header(2,62))
            with self.assertRaises(installer.InstallError): installer.elf_edges(worker,'SYNTHETIC_READELF',{'libSYNTH.so':[str(lib64),str(other)]})

    def test_bootstrap_capture_validator_uses_bounded_no_follow_descriptors(self):
        tree=ast.parse((ROOT/'admin/broker_bootstrap.py').read_text())
        functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ('fail','capture')]
        source=os.open(self.work,os.O_RDONLY|os.O_DIRECTORY)
        try:
            namespace={'os':os,'stat':stat,'source':source,'flags':os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC}
            exec(compile(ast.Module(body=functions,type_ignores=[]),'<synthetic capture test>','exec'),namespace)
            (self.work/'good').write_bytes(b'SYNTHETIC')
            (self.work/'link').symlink_to(self.work/'good')
            os.mkfifo(self.work/'fifo')
            self.assertEqual(namespace['capture']('good',64),b'SYNTHETIC')
            with self.assertRaises(OSError): namespace['capture']('link',64)
            with self.assertRaises(SystemExit): namespace['capture']('fifo',64)
            with self.assertRaises(SystemExit): namespace['capture']('good',2)
        finally: os.close(source)

    def test_administrative_audit_is_exclusive_hash_chained_and_durable(self):
        audit=installer.Audit(self.work)
        try:
            audit.event('synthetic_intent',physical_reads=False)
            audit.event('synthetic_complete')
        finally: os.close(audit.fd)
        rows=[json.loads(line) for line in (self.work/'administration.jsonl').read_bytes().splitlines()]
        previous='0'*64
        for row in rows:
            self.assertEqual(row['event']['previous_sha256'],previous)
            self.assertEqual(installer.sha(installer.canonical(row['event'])),row['sha256'])
            previous=row['sha256']
        with self.assertRaises(FileExistsError): installer.Audit(self.work)

    def test_apply_guard_never_executes_checkout_as_root(self):
        with patch.object(installer.os,'getuid',return_value=0),patch.object(installer.os,'geteuid',return_value=0),patch.object(installer.sys,'flags',SimpleNamespace(isolated=1,no_site=1)),patch.object(installer,'trusted',return_value=Path(installer.__file__)),patch.object(installer.subprocess,'run',side_effect=AssertionError('No admin command')):
            with self.assertRaises(installer.InstallError): installer.apply(self.work/'plan.json','a'*64)

    def test_bootstrap_and_installer_have_closed_process_and_network_boundaries(self):
        bootstrap=(ROOT/'admin/broker_bootstrap.py').read_text()
        source=(ROOT/'admin/broker_installer.py').read_text()
        self.assertIn('os.O_NOFOLLOW',bootstrap)
        self.assertIn('os.execv',bootstrap)
        self.assertIn("review / 'broker_installer.py'",bootstrap)
        self.assertIn('read_regular',source)
        for text in (source,bootstrap):
            tree=ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
                    self.assertNotIn(node.func.attr,('system','urlopen','download','popen'))
            for denied in ('sudo ', 'apt-get', 'pip install', 'BLKROSET', 'probe_physical(', 'chmod /dev', 'AF_INET'):
                self.assertNotIn(denied,text)

    def test_existing_targets_and_accounts_block_instead_of_overwrite(self):
        with patch.object(installer.os.path,'lexists',return_value=True),patch.object(installer.subprocess,'run',side_effect=AssertionError('No change')):
            with self.assertRaises(installer.InstallError): installer.check_absent()
        with patch.object(installer.os.path,'lexists',return_value=False),patch.object(installer.pwd,'getpwnam',return_value=object()):
            with self.assertRaises(installer.InstallError): installer.check_absent()

    def simulate_apply(self, *, fail=None):
        """Real exclusive filesystem writes ONLY in the project; all root/OS ops mocked."""
        doc,payloads=plan()
        approved=installer.sha(installer.canonical(doc))
        reviews=self.work/'reviews'; reviews.mkdir()
        review=reviews/approved; review.mkdir()
        for name,data in payloads.items(): installer.write_new(review/name,data)
        installer.write_new(review/'plan.json',installer.canonical(doc))
        host=self.work/'synthetic-host'; host.mkdir()
        code=host/'code'; state=host/'state'; runtime=host/'runtime'; unit=host/'unit.service'
        parser=SimpleNamespace(pw_uid=555,pw_gid=555,pw_shell='/usr/sbin/nologin',pw_dir='/nonexistent')
        commands=[]; created=False; server=None
        def account(name):
            if not created: raise KeyError(name)
            return parser
        def command(argv,**kwargs):
            nonlocal created,server
            commands.append(argv)
            if argv[0]=='/usr/sbin/useradd': created=True
            if argv[:2]==['/usr/bin/systemctl','start']:
                runtime.mkdir(); server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                server.bind(str(runtime/'broker.sock')); self.addCleanup(server.close)
            if fail=='command' and argv[:2]==['/usr/bin/systemctl','daemon-reload']:
                raise installer.InstallError('SYNTHETIC administrative failure')
            return ''
        original_lstat=Path.lstat
        def lstat(path,*args,**kwargs):
            if path==runtime/'broker.sock':
                return SimpleNamespace(st_uid=0,st_gid=doc['operator_gid'],st_mode=stat.S_IFSOCK|0o660)
            return original_lstat(path,*args,**kwargs)
        with ExitStack() as stack:
            for name,value in (('REVIEWS',reviews),('CODE',code),('STATE',state),('RUNTIME',runtime),('UNIT_PATH',unit)):
                stack.enter_context(patch.object(installer,name,value))
            stack.enter_context(patch.object(installer,'__file__',str(review/'broker_installer.py')))
            stack.enter_context(patch.object(installer.os,'getuid',return_value=0))
            stack.enter_context(patch.object(installer.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(installer.sys,'flags',SimpleNamespace(isolated=1,no_site=1)))
            stack.enter_context(patch.object(installer,'trusted',side_effect=lambda p,**kw:Path(p)))
            stack.enter_context(patch.object(installer,'host_prechecks'))
            stack.enter_context(patch.object(installer,'verify_dependencies'))
            stack.enter_context(patch.object(installer.pwd,'getpwnam',side_effect=account))
            stack.enter_context(patch.object(installer.grp,'getgrnam',side_effect=KeyError('SYNTHETIC absent')))
            stack.enter_context(patch.object(installer.os,'getgrouplist',return_value=[555]))
            stack.enter_context(patch.object(installer,'root_directory',side_effect=lambda p,m:p.mkdir(mode=m)))
            stack.enter_context(patch.object(installer,'run',side_effect=command))
            stack.enter_context(patch.object(Path,'lstat',lstat))
            smoke=stack.enter_context(patch.object(installer,'smoke',side_effect=installer.InstallError('SYNTHETIC smoke failure') if fail=='smoke' else None))
            if fail:
                with self.assertRaises(installer.InstallError): installer.apply(review/'plan.json',approved)
                result=None
            else:
                result=installer.apply(review/'plan.json',approved)
                smoke.assert_called_once()
        return result,commands,code,state,review,unit

    def test_simulated_install_writes_only_four_payloads_creates_no_grants_and_no_boot_enablement(self):
        result,commands,code,state,review,unit=self.simulate_apply()
        self.assertEqual(result['status'],'installed_and_smoke_checked')
        self.assertFalse(result['physical_device_reads'])
        self.assertEqual(sorted(p.name for p in code.iterdir()),sorted(installer.FILES[:-1]))
        self.assertEqual(list((state/'approved').iterdir()),[])
        self.assertEqual(list((state/'used').iterdir()),[])
        self.assertTrue(unit.is_file())
        self.assertTrue((review/'receipt.json').is_file())
        self.assertFalse(any('enable' in argv or 'restart' in argv for argv in commands))

    def test_simulated_failure_stops_without_retry_deletion_or_control_repair(self):
        _,commands,code,_,review,_=self.simulate_apply(fail='command')
        self.assertEqual(sum(argv[0]=='/usr/sbin/useradd' for argv in commands),1)
        self.assertFalse(any('start' in argv for argv in commands))
        self.assertTrue(code.is_dir())  # preserve partial installation for administrative review
        self.assertFalse((review/'receipt.json').exists())
        events=[json.loads(line)['event']['action'] for line in (review/'administration.jsonl').read_bytes().splitlines()]
        self.assertIn('installation_failed_no_repair',events)

    def test_simulated_smoke_failure_only_stops_the_new_service_for_containment(self):
        _,commands,_,_,review,_=self.simulate_apply(fail='smoke')
        self.assertEqual(sum('start' in argv for argv in commands),1)
        self.assertEqual(sum('stop' in argv for argv in commands),1)
        self.assertFalse((review/'receipt.json').exists())

    def test_socket_configuration_is_restrictive_before_listening(self):
        from tests.test_ntfs_broker import broker
        from unittest.mock import Mock
        for gid,mode in ((None,0o600),(1234,0o660)):
            server=Mock(); server.accept.side_effect=RuntimeError('SYNTHETIC stop before requests')
            context=Mock(); context.__enter__=Mock(return_value=server); context.__exit__=Mock(return_value=False)
            with self.subTest(gid=gid),patch.object(broker,'RUNTIME',self.work),patch.object(broker.socket,'socket',return_value=context),patch.object(broker.os,'chmod') as chmod,patch.object(broker.os,'chown') as chown:
                with self.assertRaises(RuntimeError): broker.serve(None,None,None,socket_gid=gid)
                chmod.assert_called_once_with(self.work/'broker.sock',mode)
                if gid is None: chown.assert_not_called()
                else: chown.assert_called_once_with(self.work/'broker.sock',0,gid)
        with self.assertRaises(ValueError): broker.serve(None,None,None,socket_gid=0)
