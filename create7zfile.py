import os
import io
import lzma
from binascii import unhexlify
from zlib import crc32
from struct import pack
from collections import OrderedDict

compression_lzma = 1
compression_lzma2 = 2

MAGIC_7Z = unhexlify('377abcaf271c')
VERSION_7Z = (0, 4)

_PROPERTY_HEADER = unhexlify('01')
_PROPERTY_MAIN_STREAMS_INFO = unhexlify('04')
_PROPERTY_FILES_INFO = unhexlify('05')
_PROPERTY_PACK_INFO = unhexlify('06')
_PROPERTY_UNPACK_INFO = unhexlify('07')
_PROPERTY_SUBSTREAMS_INFO = unhexlify('08')
_PROPERTY_SIZE = unhexlify('09')
_PROPERTY_CRC = unhexlify('0a')
_PROPERTY_FOLDER = unhexlify('0b')
_PROPERTY_CODERS_UNPACK_SIZE = unhexlify('0c')
_PROPERTY_END = unhexlify('00')

_FILE_PROPERTY_NAME = unhexlify('11')
_FILE_PROPERTY_LAST_WRITE_TIME = unhexlify('14')
_FILE_PROPERTY_DUMMY = unhexlify('19')
_FILE_PROPERTY_ATTRIBUTES = unhexlify('15')


_TIMESTAMP_ADJUST = -11644473600


def timestamp_from_sztime(timestamp):
    return (timestamp / 10000000.0) + _TIMESTAMP_ADJUST


def sztime_from_timestamp(sztime):
    return (sztime - _TIMESTAMP_ADJUST) * 10000000.0


class SZInfo:
    def __init__(self, filename, modify_time, uncompressed_size, attributes):
        self.filename = filename
        self.uncompressed_size = uncompressed_size
        self.attributes = attributes
        self.compressed_size = 0
        self.crc = 0
        self.modify_time = modify_time


class SZFile:
    def __init__(self, filename, compression=compression_lzma2):
        self._fd = open(filename, 'wb')
        self._compression = compression
        self._header_written = False
        self._files = OrderedDict()
        self._src_pos = 32
        self._end_header_pos = None
        self._end_header = None
        self._sig_header_pos = None

    def close(self):
        self._fd.flush()
        self._fd.close()

    def write(self, filename):
        if not self._header_written:
            self._write_sig_header()
            self._header_written = True

        # Read file info
        _stat = os.stat(filename)
        sz_info = SZInfo(filename, _stat.st_mtime, _stat.st_size, 8192)

        self._compress(filename, sz_info)
        self._files[filename] = sz_info
        # Write lzma file

        self._write_end_header()
        # Write ArchiveProperties id
        # Write PackInfo

    def _compress(self, filename, sz_info):
        props = lzma._encode_filter_properties({'id': lzma.FILTER_LZMA2})
        compressor = lzma.LZMACompressor(format=lzma.FORMAT_RAW,
                                         filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA2, props)])
        self._fd.seek(self._src_pos)
        with open(filename, 'rb') as uncompressed_fd:
            while True:
                data = uncompressed_fd.read(io.DEFAULT_BUFFER_SIZE)
                if not data:
                    break
                compressed_data = compressor.compress(data)
                self._fd.write(compressed_data)
                sz_info.compressed_size += len(compressed_data)
                sz_info.crc = crc32(data, sz_info.crc)

            compressed_data = compressor.flush()
            self._fd.write(compressed_data)
            sz_info.compressed_size += len(compressed_data)

        self._fd.flush()
        self._src_pos = self._fd.tell()

    def _write_sig_header(self):
        self._fd.write(MAGIC_7Z)
        self._fd.write(pack('<BB', *VERSION_7Z))
        self._sig_header_pos = self._fd.tell()
        # UINT32 Start header CRC
        # REAL_UINT64 NextHeaderOffset
        # REAL_UINT64 NextHeaderSize
        # UINT32 NextHeaderCRC

    def _write_end_header(self):
        # Save current pos
        self._end_header_pos = self._src_pos
        self._end_header = io.BytesIO()
        self._end_header.write(_PROPERTY_HEADER)
        self._write_main_streams()
        self._write_files_info()
        self._end_header.write(_PROPERTY_END)

        end_header_offset = pack('<Q', self._end_header_pos - 32)   # 32 is sigheader size
        end_header_size = pack('<Q', len(self._end_header.getvalue()))
        end_header_crc = pack('<L', crc32(self._end_header.getvalue()))
        start_header_crc = pack('<L', crc32(end_header_offset+end_header_size+end_header_crc))

        self._fd.write(self._end_header.getvalue())

        self._fd.seek(self._sig_header_pos, os.SEEK_SET)
        self._fd.write(start_header_crc)
        self._fd.write(end_header_offset)
        self._fd.write(end_header_size)
        self._fd.write(end_header_crc)

    def _write_main_streams(self):
        self._end_header.write(_PROPERTY_MAIN_STREAMS_INFO)
        self._write_main_pack_info()
        self._write_main_unpack_info()
        self._write_main_substreams()
        self._end_header.write(_PROPERTY_END)

    def _write_main_pack_info(self):
        self._end_header.write(_PROPERTY_PACK_INFO)
        # Pack pos 64bit
        self._write_64_bit(0, self._end_header)

        # Num streams 64bit
        streams = len(self._files)
        self._write_64_bit(streams, self._end_header)

        self._end_header.write(_PROPERTY_SIZE)

        # For each stream write pack size 64bit
        for f in self._files.values():
            self._write_64_bit(f.compressed_size, self._end_header)

        # For each stream write crc32 64bit (optional)
        # Write _PROPERTY_END
        self._end_header.write(_PROPERTY_END)

    @staticmethod
    def _write_64_bit(value, file):
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

        file.write(res)

    def _write_main_unpack_info(self):
        # Write _PROPERTY_FOLDER
        self._end_header.write(_PROPERTY_UNPACK_INFO)
        self._end_header.write(_PROPERTY_FOLDER)

        # Num folders 64bit
        folders = len(self._files)
        self._write_64_bit(folders, self._end_header)

        # External flag \x00
        self._end_header.write(unhexlify('00'))
        self._write_folders_info()

        # Write _PROPERTY_CODERS_UNPACK_SIZE
        self._end_header.write(_PROPERTY_CODERS_UNPACK_SIZE)
        # For each folder write unpack size 64bit
        for f in self._files.values():
            self._write_64_bit(f.uncompressed_size, self._end_header)

        # Write _PROPERTY_CRC
        # Write crc for each folder 4byte

        # Write _PROPERTY_END
        self._end_header.write(_PROPERTY_END)

    def _write_folders_info(self):
        # Num coders 64bit
        self._write_64_bit(1, self._end_header)

        self._write_coder_info()

        # Compression method
        self._end_header.write(b'!')    # \0x33

        # Compression properties size
        self._write_64_bit(1, self._end_header)

        # Compression properties
        self._end_header.write(b'\x06')

    def _write_coder_info(self):
        """
        0:3 CodecIdSize
        4:  Is Complex Coder
        5:  There Are Attributes
        6:  Reserved
        7:  There are more alternative methods. (Not used anymore, must be 0).
        """
        coder_info = 0

        # with properties
        coder_info |= 0x20

        # is complex
        # coder_info |= 0x10

        # method_size
        coder_info |= 1

        self._end_header.write(chr(coder_info).encode())

    def _write_main_substreams(self):
        self._end_header.write(_PROPERTY_SUBSTREAMS_INFO)
        # Write _PROPERTY_CRC
        self._end_header.write(_PROPERTY_CRC)

        # Write crc
        self._write_main_digests()

        self._end_header.write(_PROPERTY_END)

    def _write_main_digests(self):
        # Write digest defined flag
        self._end_header.write(b'\x01')

        # Pack crc to UINT32
        for f in self._files.values():
            packed_crc = pack('L', f.crc)
            self._end_header.write(packed_crc)

    def _write_files_info(self):
        self._end_header.write(_PROPERTY_FILES_INFO)
        # Write numfiles
        numfiles = len(self._files.values())
        self._write_64_bit(numfiles, self._end_header)

        # Write dummy prop
        # self._end_header.write(_FILE_PROPERTY_DUMMY)
        # self._write_64_bit(9, self._end_header)   # size
        # self._end_header.seek(9, os.SEEK_CUR)   # size = 9 is magic right now

        # Write filename
        additional_data_len = 3
        self._end_header.write(_FILE_PROPERTY_NAME)
        size = additional_data_len
        for f in self._files.values():
            size += len(f.filename)*2

        self._write_64_bit(size, self._end_header)  # filename size
        self._end_header.write(unhexlify('00'))  # External flag set to 0
        for f in self._files.values():
            encoded_name = f.filename.encode('utf-16')[2:]   # Encoded filename without bom
            self._end_header.write(encoded_name)
            self._end_header.write(unhexlify('0000'))

        # Write dummy prop
        # self._end_header.write(_FILE_PROPERTY_DUMMY)
        # self._write_64_bit(2, self._end_header)  # size
        # self._end_header.seek(2, os.SEEK_CUR)  # size = 9 is magic right now

        # Write last modify time
        self._end_header.write(_FILE_PROPERTY_LAST_WRITE_TIME)
        self._write_64_bit(10, self._end_header)  # size = 10
        self._end_header.write(unhexlify('01'))     # Flag defined
        self._end_header.write(unhexlify('00'))  # External flag set to 0
        self._end_header.write(b'\xf3\xcf\x95\x08|\x1f\xd4\x01')  # Change to write real64bit

        # Write file properties
        self._end_header.write(_FILE_PROPERTY_ATTRIBUTES)
        self._write_64_bit(6, self._end_header)   # size = 6
        self._end_header.write(unhexlify('01'))  # Flag defined
        self._end_header.write(unhexlify('00202000'))   # Attributes 2105344

        self._end_header.write(_PROPERTY_END)
        self._end_header.write(_PROPERTY_END)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


if __name__ == '__main__':
    with SZFile('new.7z') as szf:
        szf.write('LICENSE')
