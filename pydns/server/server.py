"""
Simple and Extensible DNS Server Implementation
"""
import asyncio
from logging import Logger, getLogger
from typing import Optional

from pyserve import Address, Writer
from pyserve import AsyncSession
from pyderive import dataclass, field

from .backend import Backend
from ..enum import QR, OpCode, RType, RCode
from ..message import Message
from ..edns import EdnsAnswer
from ..exceptions import DnsError, NotImplemented

#** Variables **#
__all__ = ['Server']

#** Classes **#

@dataclass
class Server(AsyncSession):
    """
    Extendable Implementation of DNS Server Session Manager for PyServe
    """
    backend: Backend
    logger:  Logger = field(default_factory=lambda: getLogger('pydns'))

    ### DNS Handlers

    async def process_query(self, msg: Message):
        """
        Process DNS query request
        """
        # process questions include in message
        for q in msg.questions:
            # check if server is authority on domain and retrieve basic answers
            is_authority = await self.backend.is_authority(q.name)
            msg.flags.authorative = msg.flags.authorative or is_authority
            answers = await self.backend.get_answers(q.name, q.qtype)
            # include SOA if authoritative and not already included
            if is_authority and q.qtype != RType.SOA and \
                not any(a.name == q.name for a in msg.authority):
                more = await self.backend.get_answers(q.name, RType.SOA)
                answers.answers = [*answers.answers, *more.answers]
            # report and assign answers
            src  = answers.source_label or answers.source
            code = f' code={answers.rcode.name}' if answers.rcode else ''
            self.logger.info(
                f'{self.addr_str} | {q.name!r} {q.qtype.name} '
                f'answers={len(answers.answers)} src={src}{code}')
            for answer in answers.answers:
                if answer.rtype == RType.SOA:
                    msg.authority.append(answer)
                else:
                    msg.answers.append(answer)
            # break loop if rcode is not standard
            if answers.rcode is not None:
                msg.flags.rcode = answers.rcode
                break

    async def process_status(self, msg: Message):
        """
        Process DNS status request
        """
        raise NotImplemented

    async def process_notify(self, msg: Message):
        """
        Process DNS notify request
        """
        raise NotImplemented

    async def process_update(self, msg: Message):
        """
        Process DNS update request
        """
        raise NotImplemented

    ### Standard Handlers

    async def connection_made(self, addr: Address, writer: Writer):
        """
        Handle session initialization on connection-made
        """
        self.addr     = addr
        self.writer   = writer
        self.addr_str = '%s:%d' % self.addr
        self.logger.debug(f'{self.addr_str} | connection-made')

    async def data_received(self, data: bytes):
        """
        Parse raw packet-data and process request
        """
        self.logger.debug(f'{self.addr_str} | recieved {len(data)} bytes')
        msg = Message.unpack(data)
        # ignore request if not a request
        if msg.flags.qr != QR.Question:
            return
        # update flags for response
        msg.flags.qr = QR.Response
        msg.flags.recursion_available = self.backend.recursion_available()
        try:
            # add standard empty EDNS response when present
            if any(a.rtype == RType.OPT for a in msg.additional):
                msg.additional = []
                msg.additional.append(EdnsAnswer())
            # reject request if not a query
            if msg.flags.op in (OpCode.Query, OpCode.InverseQuery):
                await self.process_query(msg)
            elif msg.flags.op == OpCode.Status:
                await self.process_status(msg)
            elif msg.flags.op == OpCode.Notify:
                await self.process_notify(msg)
            elif msg.flags.op == OpCode.Update:
                await self.process_update(msg)
            else:
                raise NotImplementedError(f'Unsupported OpCode: {msg.flags.op}')
        except DnsError as e:
            msg.flags.rcode = e.rcode
            self.logger.exception(f'{self.addr_str} | captured dns-error')
        except TimeoutError as e:
            msg.flags.rcode = RCode.ServerFailure
            error = e.args[0] if e.args else repr(e)
            self.logger.error(f'{self.addr_str} | {error}')
        except Exception as e:
            msg.flags.rcode = RCode.ServerFailure
            self.logger.exception(f'{self.addr_str} | captured exception')
        finally:
            # send response
            data = msg.pack()
            self.logger.debug(f'{self.addr_str} | sent {len(data)} bytes')
            self.writer.write(data)

    async def connection_lost(self, err: Optional[Exception]):
        """
        debug log connection lost
        """
        self.logger.debug(f'{self.addr_str} | connection-lost err={err}')
