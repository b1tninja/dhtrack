# in order to be consistent, the byte strings are always bytes, not strings,
# so no character translation, this is to avoid problems handling binary blobs like node ids and info hashes

class BEncode:

    @staticmethod
    def parse(buffer):
        return BEncode.parse_buffer(buffer)[0]

    @staticmethod
    def parse_buffer(buffer, n=0):
        if buffer[n] == ord('i'):  # integer
            m = n + 1
            while buffer[m] != ord('e'):
                m += 1
            else:
                return int(buffer[n+1:m]), m+1

        elif ord('0') <= buffer[n] <= ord('9'):  # byte string
            m = n+1
            while buffer[m] != ord(':'):
                m += 1
            else:
                l = int(buffer[n:m])
                return buffer[m+1:m+1+l], m+1+l

        elif buffer[n] == ord('d'):  # dict
            obj = {}
            m = n + 1
            while buffer[m] != ord('e'):
                assert(ord('0') <= buffer[m] <= ord('9'))
                (k, m) = BEncode.parse_buffer(buffer, m)
                k = k.decode('UTF-8')
                (v, m) = BEncode.parse_buffer(buffer, m)
                obj[k] = v
            else:
                return obj, m+1

        elif buffer[n] == ord('l'):  # list
            obj = []
            m = n + 1
            while buffer[m] != ord('e'):
                (subobj, m) = BEncode.parse_buffer(buffer, m)
                obj.append(subobj)
            else:
                return obj, m+1

        else:
            raise Exception('Unsupported object-type.')

    @staticmethod
    def encode(obj):
        # TODO: test sorting problems-- should always be sorted by the UTF-8 encoded key bytes, OrderedDict?
        # TODO: Accept ASCII/UTF-8 strings instead of only bytes
        if isinstance(obj, bytes):
            return bytes('%d:' % len(obj), encoding='ASCII') + obj

        if isinstance(obj, str):
            return ('%d:%s' % (len(obj), obj)).encode('ASCII')

        elif isinstance(obj, int):
            return bytes('i%de' % obj, encoding='ASCII')

        elif isinstance(obj, list):
            buffer = bytearray()
            for v in obj:
                buffer.extend(BEncode.encode(v))
            return b'l' + bytes(buffer) + b'e'

        elif isinstance(obj, dict):
            buffer = bytearray()
            for (k, v) in obj.items():
                if isinstance(k, str):
                    k = k.encode(('UTF-8'))
                # if isinstance(v, str):
                #     v = v.encode(('UTF-8'))
                buffer.extend(BEncode.encode(k) + BEncode.encode(v))
            return b'd' + bytes(buffer) + b'e'

        else:
            raise Exception('Unsupported object-type.')