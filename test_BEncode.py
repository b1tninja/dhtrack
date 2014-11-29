from unittest import TestCase

from bencode import BEncode

class TestBEncode(TestCase):
    def test_parse(self):
        # TODO: add some test cases for UTF-8 and binary blobs
        tests = [(b'i0e', 0),
                 (b'i-123e', -123),
                 (b'i123e', 123),
                 (b'3:hey', b'hey'),
                 (b'0:', b''),
                 (b'le:', []),
                 (b'de:', {}),
                 (b'd3:heyi0ee', {b'hey':0}),
                 (b'llee:', [[]]),
                 ]

        for (encoded, value) in tests:
            if BEncode.parse(encoded) != value:
                self.fail()