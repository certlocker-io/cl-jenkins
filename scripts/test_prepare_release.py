import tempfile
import unittest
from pathlib import Path

from prepare_release import prepare_release


class PrepareReleaseTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.pom = Path(self.directory.name) / "pom.xml"
        self.source = (
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            '  <parent><version>6.2250</version></parent>\n'
            '  <version>0.2.0-SNAPSHOT</version>\n'
            '</project>\n'
        )
        self.pom.write_text(self.source)

    def test_release_removes_snapshot_without_changing_parent_or_format(self):
        self.assertEqual("0.2.0", prepare_release("v0.2.0", self.pom))
        self.assertEqual(self.source.replace("0.2.0-SNAPSHOT", "0.2.0"), self.pom.read_text())

    def test_release_candidate_uses_tag_version(self):
        self.assertEqual("0.2.0-rc.1", prepare_release("v0.2.0-rc.1", self.pom))
        self.assertIn("<version>0.2.0-rc.1</version>", self.pom.read_text())

    def test_exact_release_version_can_be_prepared_again(self):
        prepare_release("v0.2.0", self.pom)
        self.assertEqual("0.2.0", prepare_release("v0.2.0", self.pom))

    def test_mismatched_versions_leave_source_unchanged(self):
        with self.assertRaises(ValueError):
            prepare_release("v0.3.0", self.pom)
        self.assertEqual(self.source, self.pom.read_text())

    def test_invalid_tags_leave_source_unchanged(self):
        for tag in ["0.2.0", "v0.2", "v0.2.0-SNAPSHOT", "v00.2.0", "v0.2.0;echo unsafe"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                prepare_release(tag, self.pom)
            self.assertEqual(self.source, self.pom.read_text())

    def test_ambiguous_version_replacement_leaves_source_unchanged(self):
        source = self.source.replace("</project>", "<dependency><version>0.2.0-SNAPSHOT</version></dependency></project>")
        self.pom.write_text(source)
        with self.assertRaises(ValueError):
            prepare_release("v0.2.0", self.pom)
        self.assertEqual(source, self.pom.read_text())


if __name__ == "__main__":
    unittest.main()
