from unittest import TestCase
import hashlib

import app


class TestApp(TestCase):

    def test_isFileMalicious(self):
        wannaCryMd5Hash = 'db349b97c37d22f5ea1d1841e3c89eb4'
        hasher = hashlib.md5()
        with open('../testFiles/eicar.com.txt', 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        hash = hasher.hexdigest()

        self.assertTrue(app.isFileHashMalicious(hash))
        self.assertTrue(app.isFileHashMalicious(wannaCryMd5Hash))