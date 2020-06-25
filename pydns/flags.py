"""
"""
from .const import *

#** Variables **#
__all__ = ['Flags']

#** Classes **#

class Flags:
    """
    dns-flags object for serialization/deserilization

     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

    QR    => specifies if message is a query (0), or a response (1)
    OP    => A four bit field to desginate desired operation
    AA    => declares whether packet is authorative answer
    TC    => declared whether packet if truncated
    RD    => declares whether recursion is desired
    RA    => declares whether recursion is available
    AD    => indicates the resolver believes the responses to be authentic,
             validated by DNSSEC
    CD    => indicates a security-aware resolver should disable signature
             validation, (not check DNSSEC records)
    RCODE => response/error codes
    """

    def __init__(self,
        qr:    QR,
        op:    OpCode,
        aa:    bool  = False,
        tc:    bool  = False,
        rd:    bool  = False,
        ra:    bool  = True,
        ad:    bool  = False,
        cd:    bool  = False,
        rcode: RCode = RCode.NoError
    ):
        """
        :param qr:    question/response flag (1 bit)
        :param op:    operation-code flag (4 bits)
        :param aa:    authorative-answer (1 bit)
        :param tc:    truncated (1 bit)
        :param rd:    recursion-desired (1 bit)
        :param ra:    recursion-available (1 bit)
        :param ad:    authentic-data (1 bit) (DNSSEC)
        :param cd:    checking-disabled (1 bit) (DNSEC)
        :param rcode: response-code error (4 bits)
        """
        self.qr                  = qr
        self.op                  = op
        self.authorative         = aa
        self.truncated           = tc
        self.recursion_desired   = rd
        self.recursion_available = ra
        self.authentic           = ad
        self.checking_disabled   = cd
        self.rcode               = rcode

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert header object into bytes"""
        validate_int('rcode', self.rcode.value, bits=4)
        ctx._idx += 2 # inrement index for two bytes encoded
        return bytes([
        (
            self.qr.value                |
            self.op.value                |
            (int(self.authorative) << 2) |
            (int(self.truncated)   << 1) |
            int(self.recursion_desired)
        ),
        (
            (int(self.recursion_available) << 7) |
            (int(self.authentic)           << 5) |
            (int(self.checking_disabled)   << 4) |
            self.rcode.value
        )
        ])

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'Flags':
        """convert raw-bytes into new class instance"""
        ctx._idx += 2 # increment index for two bytes decoded
        (byte1, byte2) = (raw[0], raw[1])
        return cls(
            qr=QR(byte1 & 0b10000000),
            op=OpCode(byte1 & 0b01111000),
            aa=(byte1 & 0b00000100) > 0,
            tc=(byte1 & 0b00000010) > 0,
            rd=(byte1 & 0b00000001) > 0,
            ra=(byte2 & 0b10000000) > 0,
            ad=(byte2 & 0b00100000) > 0,
            cd=(byte2 & 0b00010000) > 0,
            rcode=RCode(byte2 & 0b00001111)
        )
