"""
"""
from ..const import SerialCtx

#** Variables **#
__all__ = ['DNSKeyFlags']

#** Classes **#

class DNSKeyFlags:

    def __init__(self,
        zone_key:    bool = False,
        revoked:     bool = False,
        signing_key: bool = False,
    ):
        """
        :param zone_key:    true if key is assigned to zone
        :param revoked:     true if key is revoked
        :param signing_key: true if dns-key holds key of secure entry point
        """
        self.zone_key    = zone_key
        self.revoked     = revoked
        self.signing_key = signing_key

    def to_bytes(self, ctx: SerialCtx) -> bytes:
        """convert dnskey-flags into raw-bytes"""
        ctx._idx += 2
        return bytes([
            self.zone_key,
            (self.revoked << 7) | self.signing_key
        ])

    @classmethod
    def from_bytes(cls, raw: bytes, ctx: SerialCtx) -> 'DNSKeyFlags':
        """convert raw-bytes into dnskey-flags object"""
        ctx._idx += 2
        zone_key, other = (raw[0], raw[1])
        return cls(
            zone_key=bool(zone_key),
            revoked=bool(other & 0b10000000),
            signing_key=bool(other & 0b00000001),
        )
