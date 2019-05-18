from unittest import TestCase
import hashlib

import app


class TestApp(TestCase):

    def test_isFileMalicious(self):
        hasher = hashlib.md5()
        with open('../testFiles/eicar.com.txt') as afile:
            buf = afile.read()
            hasher.update(buf)
        hash = hasher.hexdigest()

        self.assertTrue(app.isFileHashMalicious(hash))