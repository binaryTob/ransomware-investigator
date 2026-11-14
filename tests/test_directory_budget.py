"""Explicit bounded directory budgets; synthetic regular files only."""
import os
from pathlib import Path
import subprocess

from tests.common import ProjectTest,ROOT
from tests.ntfs_support import NTFSTest
from ransomware_investigator.ntfs import core
from ransomware_investigator.ntfs_triage import run_image


class DirectoryBudgetContractTests(ProjectTest):
    def test_higher_ceiling_is_explicit_and_directory_only(self):
        self.assertEqual(core.parameters('ntfs.directory',{})['read_budget'],64*1024*1024)
        for budget in (256*1024*1024+1,512*1024*1024):
            self.assertEqual(core.parameters('ntfs.directory',{'read_budget':budget})['read_budget'],budget)
            for scope in core.SCOPES-{'ntfs.directory'}:
                with self.subTest(scope=scope,budget=budget),self.assertRaises(core.TriageError):
                    core.parameters(scope,{'read_budget':budget})

    def test_higher_budget_never_removes_byte_or_deadline_bounds(self):
        for params in ({'read_budget':512*1024*1024+1},{'read_budget':True},{'read_budget':2**63},
                       {'read_budget':512*1024*1024,'timeout_ms':15001}):
            with self.subTest(params=params),self.assertRaises(core.TriageError):
                core.parameters('ntfs.directory',params)
        self.assertEqual(core.parameters('ntfs.directory',{'read_budget':512*1024*1024,'timeout_ms':15000})['timeout_ms'],15000)

    def test_native_provider_call_byte_extent_and_deadline_gates_remain_finite(self):
        source=self.work/'limits.c'; binary=self.work/'limits'; fixture=self.work/'synthetic.bin'
        fixture.write_bytes(b'SYNTHETIC')
        source.write_text(r'''
#define main production_worker_main
#include "''' + str(ROOT/'native/ntfs_worker.c') + r'''"
#undef main
#include <assert.h>
static void init_source(Source *s,int fd,const char *op,uint64_t budget) {
    memset(s,0,sizeof(*s)); s->fd=fd; s->length=9; s->budget=budget;
    s->call_limit=source_call_limit(op,budget); s->deadline=millis()+15000;
}
int main(int argc,char **argv) {
    assert(argc==2); int fd=open(argv[1],O_RDONLY|O_NOFOLLOW); assert(fd>=0);
    Source s; char byte[2];
    assert(source_call_limit("directory",256*1024*1024)==4096);
    assert(source_call_limit("records",512*1024*1024)==4096);
    init_source(&s,fd,"directory",512*1024*1024);
    assert(s.call_limit==8192);
    for (unsigned i=0;i<8192;i++) assert(source_read(&s.image,0,byte,1)==1);
    assert(s.calls==8192 && source_read(&s.image,0,byte,1)==-1 && s.calls==8192);
    init_source(&s,fd,"directory",256*1024*1024);
    for (unsigned i=0;i<4096;i++) assert(source_read(&s.image,0,byte,1)==1);
    assert(source_read(&s.image,0,byte,1)==-1 && s.calls==4096);
    init_source(&s,fd,"directory",512*1024*1024); s.used=s.budget-1;
    assert(source_read(&s.image,0,byte,2)==-1 && s.calls==0);
    init_source(&s,fd,"directory",512*1024*1024);
    assert(source_read(&s.image,9,byte,1)==-1 && s.calls==0);
    init_source(&s,fd,"directory",512*1024*1024); s.deadline=millis()-1;
    assert(source_read(&s.image,0,byte,1)==-1 && s.calls==0);
    close(fd); return 0;
}
''')
        subprocess.run(['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-D_FILE_OFFSET_BITS=64',
                        '-I/usr/local/include',str(source),'-L/usr/local/lib','-Wl,-rpath,/usr/local/lib','-ltsk','-o',str(binary)],
                       check=True,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        result=subprocess.run([str(binary),str(fixture)],capture_output=True,timeout=30,check=True)
        self.assertEqual(result.stdout,b'')
        self.assertEqual(result.stderr.count(b'RI_READ_INTENT '),8192+4096)
        self.assertEqual(result.stderr.count(b'RI_DENIED read_budget_extent_or_deadline'),5)


class DirectoryBudgetImageTests(NTFSTest):
    def test_directory_with_explicit_higher_budget_keeps_sandbox_and_matches_legacy_output(self):
        responses=[]
        for budget in (64*1024*1024,512*1024*1024):
            result=run_image(self.store,self.case,self.image['id'],'ntfs.directory',
                    {'inode':5,'max_entries':128,'read_budget':budget,'timeout_ms':15000},
                    actor='Synthetic Operator',reason='Explicit synthetic directory budget regression; not real evidence',
                    authorized=True,provided_scope='ntfs.directory')
            self.assertEqual(result['status'],'completed')
            saved=result['results'][0]
            self.assertEqual(saved['receipt']['status'],'ok')
            self.assertIn('RI_SANDBOX seccomp_no_open_exec_network_writefiles',saved['receipt']['stderr'])
            responses.append(saved['result'])
        self.assertEqual(responses[0],responses[1])

    def test_new_maximum_still_does_not_hide_small_budget_failure(self):
        result=run_image(self.store,self.case,self.image['id'],'ntfs.directory',
                {'inode':5,'read_budget':4096},actor='Synthetic Operator',reason='Synthetic insufficient budget must fail',
                authorized=True,provided_scope='ntfs.directory')
        self.assertEqual(result['status'],'failed')
        self.assertIsNone(result['results'][0]['result'])
