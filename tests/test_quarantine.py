import tempfile, unittest
from pathlib import Path
from q_safe.quarantine import quarantine, restore
class QuarantineTests(unittest.TestCase):
 def test_round_trip(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); p=root/"sample.txt"; p.write_text("safe test"); qdir=root/"quarantine"
   rec=quarantine(str(p),str(qdir)); self.assertFalse(p.exists())
   result=restore(str(qdir/(rec["id"]+".json")))
   self.assertEqual(Path(result["restored_path"]).read_text(),"safe test")
if __name__=="__main__": unittest.main()
