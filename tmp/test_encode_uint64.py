import io
from struct import pack
from array import array
from functools import reduce


def encode(value):
    first_byte = 0
    mask = 0x80
    i = 0
    while i < 8:
        if value < (1 << (7 * (i + 1))):
            first_byte |= value >> (8 * i)
            break
        first_byte |= mask
        mask >>= 1
        i += 1

    res = b''
    res += pack('<B', first_byte)
    while i > 0:
        res += pack('<B', value & 0xff)
        value >>= 8
        i -= 1

    return res


def decode(buf):
    b = ord(buf.read(1))
    mask = 0x80
    for i in range(8):
        if b & mask == 0:
            bytes = array('B', buf.read(i))
            bytes.reverse()
            value = (bytes and reduce(lambda x, y: x << 8 | y, bytes)) or 0
            highpart = b & (mask - 1)
            return value + (highpart << (i * 8))

        mask >>= 1


if __name__ == '__main__':
    data = io.BytesIO(b'\xa2\xcf')
    value = decode(data)
    print(value)

    encoded_data = encode(8911)
    print(encoded_data)
    assert b'\xa2\xcf' == encoded_data

    data = io.BytesIO(b'\xc0\x44\x69')
    value = decode(data)
    print(value)

    encoded_data = encode(26948)
    print(encoded_data)
    assert b'\xc0\x44\x69' == encoded_data
