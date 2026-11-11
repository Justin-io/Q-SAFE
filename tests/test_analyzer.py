import tempfile, unittest
from pathlib import Path
from q_safe.analyzer import analyze_file
class AnalyzerTests(unittest.TestCase):
 def test_clean_text(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"clean.py"; p.write_text('print("hello")\n')
   self.assertEqual(analyze_file(p).verdict,"NO_STATIC_INDICATORS")
 def test_dangerous_script(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"bad.sh"; p.write_text('#!/bin/sh\nrm -rf /\n')
   self.assertGreaterEqual(analyze_file(p).score,20)
 def test_pe_signature(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/"sample.exe"; p.write_bytes(b"MZ"+b"\x00"*1024)
   self.assertEqual(analyze_file(p).file_type,"PE/Windows executable")
if __name__=="__main__": unittest.main()
