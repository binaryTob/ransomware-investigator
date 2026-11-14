from unittest.mock import patch

from tests.ntfs_support import NTFSTest
from ransomware_investigator import ntfs_scan as scan


class ScanPhaseBudgetTests(NTFSTest):
    def test_phase_specific_budgets_are_frozen_without_expanding_record_pages(self):
        job=scan.start_scan(self.store,self.case,self.image['id'],actor='Synthetic Operator',page_size=256,
                directory_read_budget=512*1024*1024,directory_timeout_ms=15000)
        state=self.store.ntfs_scan_state(job['id'])
        scope,parameters=scan.next_page(self.store,job,state)
        self.assertEqual((scope,parameters['read_budget'],parameters['timeout_ms']),('ntfs.volume',64*1024*1024,10000))
        state.update(phase='records',next_inode=0,volume_identity={'last_inode':999})
        scope,parameters=scan.next_page(self.store,job,state)
        self.assertEqual((scope,parameters['read_budget'],parameters['timeout_ms'],parameters['max_entries']),('ntfs.records',64*1024*1024,10000,256))
        state.update(phase='directories',after_directory=0,directory_cursor=0)
        with patch.object(self.store,'ntfs_scan_directory',return_value={'inode':5}):
            scope,parameters=scan.next_page(self.store,job,state)
        self.assertEqual((scope,parameters['read_budget'],parameters['timeout_ms']),('ntfs.directory',512*1024*1024,15000))

    def test_defaults_and_invalid_directory_bounds_remain_closed(self):
        job=scan.start_scan(self.store,self.case,self.image['id'],actor='Synthetic Operator')
        self.assertEqual(job['plan']['directory_read_budget'],job['plan']['read_budget'])
        self.assertEqual(job['plan']['directory_timeout_ms'],job['plan']['timeout_ms'])
        for params in ({'directory_read_budget':512*1024*1024+1},{'directory_read_budget':True},
                       {'directory_timeout_ms':15001},{'read_budget':512*1024*1024}):
            with self.subTest(params=params),self.assertRaises(ValueError):
                scan.start_scan(self.store,self.case,self.image['id'],actor='Synthetic Operator',**params)

    def test_real_synthetic_scan_completes_and_verifies_with_phase_specific_budgets(self):
        job=scan.start_scan(self.store,self.case,self.image['id'],actor='Synthetic Operator',page_size=256,
                directory_read_budget=512*1024*1024,directory_timeout_ms=15000)
        result=scan.run_image_batch(self.store,self.case,job['id'],actor='Synthetic Operator',
                reason='Synthetic phase-specific budget regression only',authorized=True,scope='ntfs.scan-metadata',max_pages=256)
        self.assertEqual(result['status'],'completed')
        self.assertTrue(scan.verify_saved_scan(self.store,self.case,job['id'])['valid'])
