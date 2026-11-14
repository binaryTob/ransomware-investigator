from tests.common import ROOT,ProjectTest
from tests.ntfs_support import load_module,build_worker

class NTFSDemoTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass(); build_worker()

    def test_complete_cli_workflow_uses_real_libtsk_on_synthetic_image(self):
        module=load_module("ntfs_demo_test",ROOT/"examples/ntfs/run_demo.py")
        result=module.demo(self.work/"demo")
        self.assertEqual(result["mode"],"synthetic_ntfs_real_libtsk")
        self.assertEqual(result["extension_search"]["entries"],2)
        self.assertGreaterEqual(result["deleted_mft_records"]["entries"],1)
        self.assertEqual(result["bounded_listing_status"],"partial")
        self.assertTrue(result["repeat_reused"])
        self.assertTrue(result["audit"]["valid"])
        self.assertFalse(result["physical_devices_accessed"])
        self.assertFalse(result["broker_started"])
