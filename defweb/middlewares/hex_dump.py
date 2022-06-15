from defweb.objects.middlewarebase import DefWebMiddlewareBase


class HexDump(DefWebMiddlewareBase):

    __protocol__ = "general"
    __hook__ = "printers"
    __weight__ = 100

    def initialize(self) -> bool:
        return True

    def execute(self) -> bool:
        print("\n".join(self.hexdump(src=self.data)))
        return True

    def hexdump(self, src, length=16, sep="."):
        """Hex dump bytes to ASCII string, padded neatly
        In [107]: x = b'\x01\x02\x03\x04AAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB'

        In [108]: print('\n'.join(hexdump(x)))
        00000000  01 02 03 04 41 41 41 41  41 41 41 41 41 41 41 41  |....AAAAAAAAAAAA|
        00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 42 42  |AAAAAAAAAAAAAABB|
        00000020  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42  |BBBBBBBBBBBBBBBB|
        00000030  42 42 42 42 42 42 42 42                           |BBBBBBBB        |
        """
        FILTER = "".join(
            [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)]
        )
        lines = []
        for c in range(0, len(src), length):
            chars = src[c : c + length]
            hex_ = " ".join(["{:02x}".format(x) for x in chars])
            if len(hex_) > 24:
                hex_ = "{} {}".format(hex_[:24], hex_[24:])
            printable = "".join(
                ["{}".format((x <= 127 and FILTER[x]) or sep) for x in chars]
            )
            lines.append(
                "{0:08x}  {1:{2}s}  |{3:{4}s}|".format(
                    c, hex_, length * 3, printable, length
                )
            )
        return lines
