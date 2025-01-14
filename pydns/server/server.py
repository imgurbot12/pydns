"""
Simple and Extensible DNS Server Implementation
"""
from enum import IntEnum
from logging import Logger, getLogger
from typing import Optional

from pyserve import Address, Writer
from pyserve import Session as BaseSession
from pyderive import dataclass, field

from .backend import Backend
from ..enum import QR, OpCode, RType, RCode
from ..message import Message
from ..edns import EdnsAnswer
from ..exceptions import DnsError, NotImplemented

#** Variables **#
__all__ = ['Server']

#** Classes **#

class Mode(IntEnum):
    """allowed runtime modes to run dns server"""
    SYNC           = 1
    ASYNC          = 2
    THREADED       = 3
    THREADED_ASYNC = 4

@dataclass
class Server(BaseSession):
    """
    Extendable Implementation of DNS Server Session Manager for PyServe
    """
    backend: Backend
    logger:  Logger = field(default_factory=lambda: getLogger('pydns'))

    ### DNS Handlers

    def process_query(self, msg: Message):
        """
        process questions in query message and append answers found
        """
        # process questions include in message
        for q in msg.questions:
            # check if server is authority on domain and retrieve basic answers
            is_authority = self.backend.is_authority(q.name)
            msg.flags.authorative = msg.flags.authorative or is_authority
            answers, source = self.backend.get_answers(q.name, q.qtype)
            # include SOA if authorative and not already included
            if is_authority and q.qtype != RType.SOA and \
                not any(a.name == q.name for a in msg.authority):
                more, _ = self.backend.get_answers(q.name, RType.SOA)
                answers  = answers.copy()
                answers += more
            # report and assign answers
            self.logger.info(
                f'{self.addr_str} | {q.name} {q.qtype.name} '
                f'answers={len(answers)} src={source}')
            for answer in answers:
                if answer.rtype == RType.SOA:
                    msg.authority.append(answer)
                else:
                    msg.answers.append(answer)

    def process_status(self, msg: Message):
        """
        process dns status request
        """
        raise NotImplemented

    def process_notify(self, msg: Message):
        """
        process dns notify request
        """
        raise NotImplemented

    def process_update(self, msg: Message):
        """
        process dns update request
        """
        raise NotImplemented

    ### Standard Handlers

    def connection_made(self, addr: Address, writer: Writer):
        """
        handle session initialization on connection-made
        """
        self.addr     = addr
        self.writer   = writer
        self.addr_str = '%s:%d' % self.addr
        self.logger.debug(f'{self.addr_str} | connection-made')

    def data_recieved(self, data: bytes):
        """
        parse raw packet-data and process request
        """
        self.logger.debug(f'{self.addr_str} | recieved {len(data)} bytes')
        msg = Message.unpack(data)
        # ignore request if not a request
        if msg.flags.qr != QR.Question:
            return
        # update flags for response
        msg.flags.qr = QR.Response
        msg.flags.recursion_available = self.backend.recursion_available
        try:
            # add standard empty EDNS response when present
            if any(a.rtype == RType.OPT for a in msg.additional):
                msg.additional = []
                msg.additional.append(EdnsAnswer())
            # reject request if not a query
            if msg.flags.op in (OpCode.Query, OpCode.InverseQuery):
                self.process_query(msg)
            elif msg.flags.op == OpCode.Status:
                self.process_status(msg)
            elif msg.flags.op == OpCode.Notify:
                self.process_notify(msg)
            elif msg.flags.op == OpCode.Update:
                self.process_update(msg)
            else:
                raise NotImplementedError(f'Unsupported OpCode: {msg.flags.op}')
        except DnsError as e:
            msg.flags.rcode = e.rcode
        except Exception as e:
            msg.flags.rcode = RCode.ServerFailure
            raise e
        finally:
            # send response
            data = msg.pack()
            self.logger.debug(f'{self.addr_str} | sent {len(data)} bytes')
            self.writer.write(data)

    def connection_lost(self, err: Optional[Exception]):
        """
        debug log connection lost
        """
        self.logger.debug(f'{self.addr_str} | connection-lost err={err}')
