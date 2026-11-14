import importlib.util
from unittest.mock import patch

from tests.common import ROOT, ProjectTest


class ArtifactDemoTests(ProjectTest):
    def test_complete_offline_cli_demo_with_only_synthetic_files(self):
        spec = importlib.util.spec_from_file_location("artifact_demo", ROOT / "examples/artifacts/run_demo.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch("subprocess.Popen", side_effect=AssertionError("No ejecutar procesos de muestras o discos")):
            result = module.demo(self.work / "demo")
        self.assertEqual(result["registered_copies"], 3)
        self.assertTrue(result["assessments"]["synthetic-note.txt"]["candidate"])
        self.assertFalse(result["assessments"]["benign-readme.txt"]["candidate"])
        self.assertFalse(result["assessments"]["educational-example.txt"]["candidate"])
        self.assertTrue(result["audit"]["valid"])
        self.assertFalse(result["physical_devices_accessed"])
        self.assertFalse(result["network_used"])
