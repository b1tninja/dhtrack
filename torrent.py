import pymongo
import asyncio

from hashlib import sha1

from contextlib import closing

from bencode import BEncode

class Torrent(object):
    mongo = pymongo.MongoClient()
    db = mongo.dht
    torrents = db.torrents

    torrents.ensure_index('infohash', unique=True)

    def __init__(self, d):
        self.dict = d
        print(sha1(BEncode.encode([b'info'])).hexdigest())

    @classmethod
    def parse(cls, buffer):
        return cls(BEncode.parse(buffer))

    @classmethod
    def parse_file(cls, path):
        with closing(open(path, 'rb')) as fd:
            return cls.parse(fd.read())


