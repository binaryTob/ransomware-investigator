"""Synthetic kernel metadata only; no block opens, live udev or host mutations."""
import copy
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ProjectTest
from tests.ntfs_support import PIN, state
from tests.test_ntfs_broker import broker, request
from ransomware_investigator.ntfs import core, physical


def session_pin():
    pin={key:value for key,value in PIN.items() if key!='wwid'}
    pin.update(partition_table_type='dos',partition_table_id='11112222',identity_scheme=physical.SESSION_SCHEME,
        station_binding={'boot_id':'11111111-2222-3333-4444-555555555555','diskseq':42,
            'disk_by_path':'/dev/disk/by-path/pci-SYNTHETIC-usb-0:2:1.0-scsi-0:0:0:0',
            'target_by_path':'/dev/disk/by-path/pci-SYNTHETIC-usb-0:2:1.0-scsi-0:0:0:0-part1',
            'usb_sysfs_path':'/sys/devices/pci0000:00/usb1/1-2','usb_vendor_id':'1234','usb_product_id':'5678',
            'usb_busnum':1,'usb_devnum':2,'usb_devpath':'2','layout_sha256':'a'*64,'volume_uuid':'0123456789abcdef'})
    return pin


def session_state():
    return {**{k:v for k,v in state().items() if k!='wwid'},**session_pin()}


class StationIdentityTests(ProjectTest):
    def test_explicit_scheme_requires_complete_binding_and_never_wwid_placeholder(self):
        good=session_pin(); self.assertEqual(physical.validate_pin(good),good)
        for change in ({'wwid':'UNAVAILABLE'},{'identity_scheme':'automatic_fallback'},{'station_binding':{}},
                       {'target_by_id':'/dev/sda1'}):
            with self.subTest(change=change),self.assertRaises(ValueError): physical.validate_pin({**good,**change})
        for key in physical.SESSION_FIELDS:
            bad=copy.deepcopy(good); del bad['station_binding'][key]
            with self.subTest(missing=key),self.assertRaises(ValueError): physical.validate_pin(bad)
        for key,value in (('diskseq',True),('diskseq',0),('disk_by_path','/dev/sda'),('usb_sysfs_path','/sys/devices/../../tmp'),('volume_uuid','unknown')):
            bad=copy.deepcopy(good); bad['station_binding'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): physical.validate_pin(bad)

    def test_every_session_field_change_and_ro_mount_protection_still_block(self):
        pin=session_pin(); baseline=session_state(); physical.validate_state(pin,baseline)
        for key,value in pin['station_binding'].items():
            changed=copy.deepcopy(baseline); changed['station_binding'][key]=value+1 if type(value) is int else value+'X'
            with self.subTest(field=key),self.assertRaises(ValueError): physical.validate_state(pin,changed)
        for key,value in (('protected',True),('mounted',True),('holders',True),('swap_active',True),('identity_unique',False),('disk_read_only',False),('partition_read_only',False),('all_children_read_only',False)):
            with self.subTest(field=key),self.assertRaises(ValueError): physical.validate_state(pin,{**baseline,key:value})

    def test_known_missing_vpd_is_not_general_io_error_fallback(self):
        for code in (errno.ENXIO,errno.ENOENT):
            with patch.object(physical,'_text',side_effect=OSError(code,'SYNTHETIC VPD unavailable')):
                self.assertIsNone(physical._wwid(self.work))
        for code in (errno.EACCES,errno.EIO,errno.ETIMEDOUT):
            with patch.object(physical,'_text',side_effect=OSError(code,'SYNTHETIC failure')):
                with self.assertRaises(OSError): physical._wwid(self.work)

    def test_fd_diskseq_must_match_both_parent_and_partition(self):
        for values in ([42,42],[41],[42,43]):
            with patch.object(physical,'_ioctl',side_effect=values) as ioctl:
                if values==[42,42]: physical.validate_fd_diskseq({'diskseq':42},3,4)
                else:
                    with self.assertRaises(ValueError): physical.validate_fd_diskseq({'diskseq':42},3,4)
                self.assertTrue(all(call.args[1:]==(0x80081280,'Q') for call in ioctl.call_args_list))

    def test_no_unprivileged_physical_shortcut(self):
        with patch.object(physical,'_selector',side_effect=AssertionError('No device lookups')):
            with self.assertRaises(ValueError): physical.probe_physical(session_pin())

    def fixture(self):
        classes=self.work/'class'; classes.mkdir()
        usb=self.work/'devices/usb1/1-2'; disk=usb/'host/block/sdx'; part=disk/'sdx1'
        part.mkdir(parents=True)
        for name,value in {'idVendor':'1234','idProduct':'5678','busnum':'1','devnum':'2','devpath':'2'}.items(): (usb/name).write_text(value)
        (disk/'diskseq').write_text('42')
        for name,value in {'partition':'1','start':'2048','size':'32768'}.items(): (part/name).write_text(value)
        (classes/'sdx').symlink_to(disk,target_is_directory=True)
        props={'sdx':{'ID_PART_TABLE_UUID':'11112222'},'sdx1':{'ID_PART_ENTRY_UUID':'11112222-01','ID_FS_TYPE':'ntfs','ID_FS_UUID':'0123456789ABCDEF','ID_PART_ENTRY_OFFSET':'2048','ID_PART_ENTRY_SIZE':'32768'}}
        return classes,disk,part,props

    def observe(self,classes,disk,part,props,wwid=None):
        original=physical._text
        def read(path):
            if str(path)=='/proc/sys/kernel/random/boot_id': return session_pin()['station_binding']['boot_id']
            return original(path)
        with patch.object(physical,'_wwid',return_value=wwid),patch.object(physical,'_udev',side_effect=lambda name:props[name]),patch.object(physical,'_text',side_effect=read):
            return physical.observe_station(disk,part,session_pin()['station_binding'],class_root=classes)

    def test_station_observation_is_metadata_only_complete_and_stable(self):
        classes,disk,part,props=self.fixture()
        observed=self.observe(classes,disk,part,props)
        self.assertEqual(observed['diskseq'],42)
        self.assertEqual(observed['volume_uuid'],'0123456789abcdef')
        self.assertEqual(set(observed),physical.SESSION_FIELDS)
        self.assertEqual(observed,self.observe(classes,disk,part,props))
        (disk/'diskseq').write_text('43')
        self.assertNotEqual(observed,self.observe(classes,disk,part,props))

    def test_available_or_cached_hardware_id_never_silently_downgrades(self):
        classes,disk,part,props=self.fixture()
        with self.assertRaises(ValueError): self.observe(classes,disk,part,props,wwid='naa.SYNTHETIC')
        props['sdx']['ID_WWN']='0xSYNTHETIC'
        with self.assertRaises(ValueError): self.observe(classes,disk,part,props)

    def test_logical_clone_table_or_volume_and_missing_uuid_are_rejected(self):
        classes,disk,part,props=self.fixture()
        other=self.work/'other/sdz'; opart=other/'sdz1'; opart.mkdir(parents=True)
        for name,value in {'partition':'1','start':'2048','size':'32768'}.items(): (opart/name).write_text(value)
        (classes/'sdz').symlink_to(other,target_is_directory=True)
        props.update(sdz={'ID_PART_TABLE_UUID':'33334444'},sdz1={'ID_PART_ENTRY_UUID':'33334444-01','ID_FS_TYPE':'ntfs','ID_FS_UUID':'FEDCBA9876543210'})
        self.observe(classes,disk,part,props)
        props['sdz']['ID_PART_TABLE_UUID']='11112222'
        with self.assertRaises(ValueError): self.observe(classes,disk,part,props)
        props['sdz']['ID_PART_TABLE_UUID']='33334444'
        props['sdz1']['ID_FS_UUID']='0123456789ABCDEF'
        with self.assertRaises(ValueError): self.observe(classes,disk,part,props)
        del props['sdz1']['ID_FS_UUID']
        with self.assertRaises(ValueError): self.observe(classes,disk,part,props)

    def test_postcheck_rejects_new_kernel_instance_and_closes_fresh_descriptor(self):
        path=self.work/'fd'; path.write_bytes(b'SYNTHETIC descriptor')
        fd=os.open(path,os.O_RDONLY)
        try:
            before={**session_state(),'rdev':os.fstat(fd).st_rdev}; after=copy.deepcopy(before)
            after['station_binding']['diskseq']+=1
            fresh=[]
            def probe(pin):
                new=os.open(path,os.O_RDONLY); fresh.append(new); return new,after
            with self.assertRaises(ValueError): physical.recheck_physical(session_pin(),fd,before,probe=probe)
            with self.assertRaises(OSError): os.fstat(fresh[0])
        finally: os.close(fd)


class SessionGrantTests(ProjectTest):
    def test_root_approval_and_consumption_require_custody_attestation(self):
        storage=self.work/'admin'; storage.mkdir()
        for name in ('approved','used'): (storage/name).mkdir()
        req=request('ntfs.records',{'inode':5,'max_entries':1}); req['source']['pin']=session_pin()
        with patch.object(broker,'STATE',storage),patch.object(broker,'root_file',side_effect=lambda p,**kw:Path(p)),patch.object(broker,'ledger',return_value='c'*64),patch.object(broker,'parser_identity',return_value=SimpleNamespace(pw_uid=555,pw_gid=555)):
            with self.assertRaises(ValueError): broker.approve_request(core,physical,req,broker.digest(req),os.getuid(),'SYNTHETIC metadata')
            self.assertFalse(list((storage/'approved').iterdir()))
            broker.approve_request(core,physical,req,broker.digest(req),os.getuid(),'SYNTHETIC metadata',custody_attestation='SYNTHETIC human verified custody/USB port, not real evidence')
            path=storage/'approved'/(req['request_id']+'.json'); grant=json.loads(path.read_bytes())
            attestation=grant.pop('custody_attestation'); path.write_bytes(broker.canonical(grant))
            with self.assertRaises(ValueError): broker.consume(core,physical,req,os.getuid())
            grant['custody_attestation']=attestation; path.write_bytes(broker.canonical(grant))
            self.assertEqual(broker.consume(core,physical,req,os.getuid())['custody_attestation'],attestation)
