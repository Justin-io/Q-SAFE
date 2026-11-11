import tempfile, unittest
from pathlib import Path
from q_safe.quarantine import quarantine, restore
from q_safe.baseline import save, compare

class QuarantineTests(unittest.TestCase):
 def test_round_trip(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); p=root/"sample.txt"; p.write_text("safe test"); qdir=root/"quarantine"
   rec=quarantine(str(p),str(qdir)); self.assertFalse(p.exists())
   result=restore(str(qdir/(rec["id"]+".json")))
   self.assertEqual(Path(result["restored_path"]).read_text(),"safe test")
 def test_symlink_refused(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); target=root/"target.txt"; target.write_text("keep")
   link=root/"link.txt"; link.symlink_to(target)
   with self.assertRaises(ValueError): quarantine(str(link),str(root/"q"))
   self.assertTrue(target.exists())
 def test_baseline_detects_change(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); f=root/"file.txt"; f.write_text("one")
   manifest=root/"baseline.json"; save(str(manifest),[str(root)])
   f.write_text("two")
   changes=compare(str(manifest),[str(root)])
   self.assertIn("CONTENT_CHANGED",[x["change"] for x in changes])

if __name__=="__main__": unittest.main()
