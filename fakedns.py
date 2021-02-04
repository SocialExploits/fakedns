#!/usr/bin/env python3

# Copyright 2021 Social Exploits LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Simulates a DNS server, useful for reverse engineering.

Rerwrite based on fakedns.py from remnux

Mike Murr (mike@socialexploits.com, https://socialexploits.com)
"""

import argparse
import codecs
import ctypes
import enum
import ipaddress
import logging
import socket
import sys
import textwrap
import traceback

import netifaces

__all__ = [
    # Enumerations
    "QTYPE", "QCLASS", "RCODE", "OPCODE",

    # DNS related classes
    "DNSMessage", "Question", "ResourceRecord", "DNSMessageSerializer",

    # DNS server related classes
    "FakeDnsServer"
]

# Make a global logger
_logger = logging.getLogger("fakedns")
_logger.setLevel(logging.INFO)
_formatter = logging.Formatter(
    fmt="{name}[{levelname}]: {message}",
    style="{"
)
_handler = logging.StreamHandler(stream=sys.stdout)
_handler.setFormatter(_formatter)
_logger.addHandler(_handler)


class CtypesDNSMessageHeader(ctypes.BigEndianStructure):
    """Ctypes structure to represent the header from an DNS message."""

    _fields_ = [
        ("id", ctypes.c_uint16),
        ("qr", ctypes.c_uint8, 1),
        ("opcode", ctypes.c_uint8, 4),
        ("aa", ctypes.c_uint8, 1),
        ("tc", ctypes.c_uint8, 1),
        ("rd", ctypes.c_uint8, 1),
        ("ra", ctypes.c_uint8, 1),
        ("z", ctypes.c_uint8, 1),
        ("ad", ctypes.c_uint8, 1),
        ("cd", ctypes.c_uint8, 1),
        ("rcode", ctypes.c_uint8, 4),
        ("qdcount", ctypes.c_uint16),
        ("ancount", ctypes.c_uint16),
        ("nscount", ctypes.c_uint16),
        ("arcount", ctypes.c_uint16),
    ]
# end class CtypesDNSMessageHeader

class QTYPE(enum.IntEnum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAPPTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    EID = 31
    NIMLOC = 32
    SRV = 33
    ATMA = 34
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    SINK = 40
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    SPF = 99
    UINFO = 100
    UID = 101
    GID = 102
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ALL = 255
    URI = 256
    CAA = 257
    DOA = 259
    TA = 32768
    DKV = 32769
# end class QTYPE

class QCLASS(enum.IntEnum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4
    ANY = 255
# end class QCLASS

class RCODE(enum.IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    YXDOMAIN = 6
    YXRRSET = 7
    NXRRSET = 8
    NOTAUTH = 9
    NOTZONE = 10
    RESERVED11 = 11
    RESERVED12 = 12
    RESERVED13 = 13
    RESERVED14 = 15
    RESERVED15 = 15
# end class RCODE

class OPCODE(enum.IntEnum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
# end class OPCODE


class DNSMessage:
    """Base class for all DNS messages.

    Attributes:
        id (int): The transaction identifier.
        qr (int): 0 for query message, 1 for response message.
        opcode (int): Specifies the kind of query.
        aa (bool): If the answer is authoriative.
        tc (bool): If the message was truncated.
        rd (bool): If recursion is desired.
        ra (bool): If recursive query support is available.
        z (int): Reserved (should be 0)
        ad (bool): If the data is authentiacted.
        cd (bool): If checking data authenticity is disabled.
        rcode (int): Response code.
        question (list): A list of :class:`Question`s.
        answer (list): A list of :class:`ResourceRecords` in the answer
            section.
        authority (list): A list of name server :class:`ResourceRecord`s.
        additional (list): A list of additional :class:`ResourceRecord`s.
    """

    _defaults = {
        "id": 0,
        "qr": 0,
        "opcode": OPCODE.QUERY.value,
        "aa": True,
        "tc": False,
        "rd": False,
        "ra": True,
        "z": 0,
        "ad": False,
        "cd": False,
        "rcode": RCODE.NOERROR.value,
    }

    def __init__(self, **kwargs):
        """Initializes a DNSMessage object.

        Args:
            id (int): The transaction id.
            qr (int): 0 for query, 1 for response.
            opcode (int): The kind of query.
            aa (bool): If the answer is authoritative.
            tc (bool): If the message is truncated.
            rd (bool): If recursion is desired.
            ra (bool): If recursive query support is enabled.
            z (int): Reserved, must be 0.
            ad (bool): If the data is authenticated.
            cd (bool): If checking data authenticity is disabled.
            rcode (int): The response code.
            question (list): A list of :class:`Question` objects.
            answer (list): A list of :class:`ResourceRecords` answering the
                questions.
            authority (list): A list of name server :class:`ResourceRecord`s.
            additional (list): A list of additional :class:`ResourceRecord`s.
        """

        for attr_name in self._defaults:
            if attr_name in kwargs:
                setattr(self, attr_name, kwargs[attr_name])
            else:
                setattr(self, attr_name, self._defaults[attr_name])
            # end if
        # end for

        for section in ["question", "answer", "authority", "additional"]:
            if section in kwargs:
                setattr(self, section, kwargs[section])
            else:
                setattr(self, section, list())
            # end if
        # end for
    # end def __init__

    def __str__(self):
        # Try to get a human-friendly name for opcode
        try:
            opcode = OPCODE(self.opcode).name
        except ValueError:
            opcode = self.opcode
        # end try

        # Try to get a human-friendly name for rcode
        try:
            rcode = RCODE(self.rcode).name
        except ValueError:
            rcode = self.rcode
        # end try

        return "DNSMessage(" \
            f"id={self.id}, " \
            f"qr={self.qr}, " \
            f"opcode={opcode}, " \
            f"aa={self.aa}, " \
            f"tc={self.tc}, " \
            f"rd={self.rd}, " \
            f"ra={self.ra}, " \
            f"z={self.z}, " \
            f"ad={self.ad}, " \
            f"cd={self.cd}, " \
            f"rcode={rcode})"
    # end def __str__

    def __repr__(self):
        return "DNSMessage(" \
            f"id={self.id}, " \
            f"qr={self.qr}, " \
            f"opcode={self.opcode}, " \
            f"aa={self.aa}, " \
            f"tc={self.tc}, " \
            f"rd={self.rd}, " \
            f"ra={self.ra}, " \
            f"z={self.z}, " \
            f"ad={self.ad}, " \
            f"cd={self.cd}, " \
            f"rcode={self.rcode}, " \
            f"question={self.question}, " \
            f"answer={self.answer}, " \
            f"authority={self.authority}, " \
            f"additional={self.additional})"
    # end def __repr__
# end class DNSMessage

class DNSMessageSerializer:
    """(De)Serializes a DNS Message (from)to Python bytes."""

    @staticmethod
    def message_from_bytes(data, offset=0):
        """Creates a DNSMessage from Python bytes.

        Notes:
            For now this only extracts questions.

        Args:
            data (bytes): The raw python bytes.
            offset (int): The start of the DNS message in data.

        Returns:
            DNSMessage: A newly-minted DNSMessage.
        """

        hdr = CtypesDNSMessageHeader.from_buffer_copy(data, offset)
        cls_args = {}
        cls_args["id"] = hdr.id
        cls_args["qr"] = hdr.qr
        cls_args["opcode"] = hdr.opcode
        cls_args["aa"] = bool(hdr.aa)
        cls_args["tc"] = bool(hdr.tc)
        cls_args["rd"] = bool(hdr.rd)
        cls_args["ra"] = bool(hdr.ra)
        cls_args["z"] = hdr.z
        cls_args["ad"] = bool(hdr.ad)
        cls_args["cd"] = bool(hdr.cd)
        cls_args["rcode"] = hdr.rcode

        serializer = DNSMessageSerializer
        offset = 12

        question, size = serializer.question_from_bytes(
            data,
            hdr.qdcount,
            offset
        )
        cls_args["question"] = question
        offset += size

        answer, size = serializer.section_from_bytes(
            data,
            hdr.ancount,
            offset
        )
        cls_args["answer"] = answer
        offset += size

        authority, size = serializer.section_from_bytes(
            data,
            hdr.nscount,
            offset
        )
        cls_args["authority"] = authority
        offset += size

        additional, size = serializer.section_from_bytes(
            data,
            hdr.arcount,
            offset
        )
        cls_args["additional"] = additional

        return DNSMessage(**cls_args)
    # end def message_from_bytes

    @staticmethod
    def question_from_bytes(data, count, start_offset=12):
        """Extracts the questions from the question section.

        Args:
            data (bytes): The entire DNS packet.
            count (int): The number of questions.
            start_offset (int): The start of the questions in the packet.

        Returns:
            tuple: A tuple of two elements. The first element is a list of
                :class:`Question` objects, and the second is the size of the
                question section.
        """
        question = []
        cur_question = 0
        cur_offset = start_offset
        data_len = len(data)
        serializer = DNSMessageSerializer

        while (cur_question < count) and (cur_offset < data_len):
            args = {}
            label_parts, size = serializer.label_from_bytes(data, cur_offset)
            cur_offset += size
            args["qname"] = ".".join(label_parts)

            if cur_offset > (data_len - 4):
                raise ValueError("Incomplete question section")
            # end if

            args["qtype"] = int.from_bytes(
                data[cur_offset:cur_offset+2],
                byteorder="big"
            )
            args["qclass"] = int.from_bytes(
                data[cur_offset+2:cur_offset+4],
                byteorder="big"
            )

            cur_offset += 4

            question.append(Question(**args))
            cur_question += 1
        # end while

        return (question, (cur_offset - start_offset))
    # end def question_from_bytes

    @staticmethod
    def label_from_bytes(data, start_offset):
        """Extracts a label from a DNS message.
        
        Args:
            data (bytes): The entire raw DNS message.
            start_offset (int): The offset of the label in the DNS message.
            
        Returns:
            tuple: A tuple of two elements. The first element is a list of the
                label parts, the second element is the size of the label in
                the message (which would include any length octets).
        """

        label_parts = []
        cur_offset = start_offset
        data_len = len(data)
        serializer = DNSMessageSerializer

        while cur_offset < data_len:
            if data[cur_offset] & 0xC0:
                # It's a "compressed" label
                label_offset = data[cur_offset:cur_offset+2]
                label_offset = int.from_bytes(label_offset, byteorder="big")
                label_offset = label_offset & 0x3F
                cur_offset += 2

                parts = serializer.label_from_bytes(data, label_offset)[0]
                label_parts.extend(parts)
                break
            elif data[cur_offset] == 0:
                # We've hit the null label, so consume the length byte and
                # exit
                cur_offset += 1
                break
            else:
                label_len = data[cur_offset]
                cur_offset += 1

                label = data[cur_offset:cur_offset+label_len]
                cur_offset += label_len

                label = codecs.decode(label, "ascii")
                label_parts.append(label)
        # end while

        return (label_parts, cur_offset - start_offset)
    # end def label_from_bytes

    @staticmethod
    def section_from_bytes(data, count, start_offset):
        """Extracts the entries for a section from a DNS message.

        Args:
            data (bytes): The entire raw DNS message.
            count (int): The number of entries in the section.
            start_offset (int): The offset of the start of the section in the
                DNS message.

        Returns:
            tuple: A tuple of two elements. The first element is a list of
                :class:`ResourceRecord` objects, the second element is the
                size of the section in bytes.
        """

        serializer = DNSMessageSerializer
        records = []
        cur_offset = start_offset
        data_len = len(data)
        cur_record = 0

        while (cur_record < count) and (cur_offset < data_len):
            args = {}
            name, size = serializer.label_from_bytes(data, cur_offset)
            cur_offset += size
            args["name"] = ".".join(name)

            # Make sure we've got a valid section
            if cur_offset > (data_len - 10):
                raise ValueError("Incomplete section")
            # end if

            rtype = data[cur_offset:cur_offset+2]
            cur_offset += 2
            args["rtype"] = int.from_bytes(rtype, byteorder="big")

            rclass = data[cur_offset:cur_offset+2]
            cur_offset += 2
            args["rclass"] = int.from_bytes(rclass, byteorder="big")

            ttl = data[cur_offset:cur_offset+4]
            cur_offset += 4
            args["ttl"] = int.from_bytes(ttl, byteorder="big")

            rdlength = data[cur_offset:cur_offset+2]
            cur_offset += 2
            rdlength = int.from_bytes(rdlength, byteorder="big")

            args["rdata"] = data[cur_offset:cur_offset + rdlength]
            cur_offset += rdlength

            records.append(ResourceRecord(**args))
            cur_record += 1
        # end while

        return (records, cur_offset - start_offset)
    # end def section_from_bytes

    @staticmethod
    def message_to_bytes(dns_msg):
        """Turns a DNSMessage into Python bytes.

        Args:
            dns_msg (:class:`DNSMessage`): The message object.

        Returns:
            bytes: The message in byte form.
        """

        serializer = DNSMessageSerializer

        dns_hdr = CtypesDNSMessageHeader()
        dns_hdr.id = dns_msg.id
        dns_hdr.qr = dns_msg.qr
        dns_hdr.opcode = dns_msg.opcode
        dns_hdr.aa = dns_msg.aa
        dns_hdr.tc = dns_msg.tc
        dns_hdr.rd = dns_msg.rd
        dns_hdr.ra = dns_msg.ra
        dns_hdr.z = dns_msg.z
        dns_hdr.aa = dns_msg.aa
        dns_hdr.cd = dns_msg.cd
        dns_hdr.rcode = dns_msg.rcode
        dns_hdr.qdcount = len(dns_msg.question)
        dns_hdr.ancount = len(dns_msg.answer)
        dns_hdr.nscount = len(dns_msg.authority)
        dns_hdr.arcount = len(dns_msg.additional)
        hdr_bytes = bytes(dns_hdr)

        cur_msg_len = 12
        label_cache = dict()

        question_bytes = serializer.question_to_bytes(
            dns_msg.question,
            cur_msg_len,
            label_cache
        )
        cur_msg_len += len(question_bytes)

        answer_bytes = serializer.section_to_bytes(
            dns_msg.answer,
            cur_msg_len,
            label_cache
        )
        cur_msg_len += len(answer_bytes)

        authority_bytes = serializer.section_to_bytes(
            dns_msg.authority,
            cur_msg_len,
            label_cache
        )
        cur_msg_len += len(authority_bytes)

        additional_bytes = serializer.section_to_bytes(
            dns_msg.additional,
            cur_msg_len,
            label_cache
        )
        cur_msg_len += len(additional_bytes)

        return b"".join([
            hdr_bytes,
            question_bytes,
            answer_bytes,
            authority_bytes,
            additional_bytes
        ])
    # end def message_to_bytes

    @staticmethod
    def question_to_bytes(question, start_offset, label_cache=None):
        """Serializes a DNS question section to Python bytes.

        Args:
            question (list): A list of :class:`Question` objects to serialize.
            start_offset (int): The offset of the start of the first Question
                (used for computing label offsets)
            label_cache (dict): A dictionary used to keep track of labels and
                their offsets (for message compression).

        Returns:
            bytes: The question as Python bytes.
        """

        if label_cache is None:
            label_cache = dict()
        # end if

        question_bytes = []
        cur_query_offset = start_offset

        for query in question:
            label_bytes = DNSMessageSerializer.label_to_bytes(
                query.qname,
                cur_query_offset,
                label_cache
            )

            question_bytes.extend([
                label_bytes,
                query.qtype.to_bytes(2, byteorder="big"),
                query.qclass.to_bytes(2, byteorder="big"),
            ])

            cur_query_offset += len(label_bytes) + 4
        # end for

        return b"".join(question_bytes)
    # end def question_to_bytes

    @staticmethod
    def section_to_bytes(section, start_offset, label_cache=None):
        """Serializes a DNS section to Python bytes.

        Args:
            section (list): A list of :class:`ResourceRecord`s in the section.
            start_offset (int) The offset of the start of the section in the
                DNS message (used to compute label offsets).
            label_cache (dict): Used to cache offsets of labels for message
                compression.

        Returns:
            bytes: The section as Python bytes.
        """

        if label_cache is None:
            label_cache = dict()
        # end if

        serializer = DNSMessageSerializer
        cur_rr_offset = start_offset
        section_bytes = []

        for rsrc_rec in section:
            label_bytes = serializer.label_to_bytes(
                rsrc_rec.name,
                cur_rr_offset,
                label_cache
            )
            section_bytes.extend([
                label_bytes,
                rsrc_rec.rtype.to_bytes(2, byteorder="big"),
                rsrc_rec.rclass.to_bytes(2, byteorder="big"),
                rsrc_rec.ttl.to_bytes(4, byteorder="big"),
                len(rsrc_rec.rdata).to_bytes(2, byteorder="big"),
                rsrc_rec.rdata
            ])

            cur_rr_offset += len(label_bytes) + 10 + len(rsrc_rec.rdata)
        # end for

        return b"".join(section_bytes)
    # end def section_to_bytes

    @staticmethod
    def label_to_bytes(label, start_offset, label_cache=None):
        """Serializes a label to Python bytes.

        Args:
            label (str): The label (e.g. "www.google.com")
            start_offset (int): The start of the label in the DNS message
                (used to compute label offsets).
            label_cache (dict): A dictionary of labels and offsets, used for
                message compression.

        Returns:
            bytes: The label as Python bytes.
        """

        if label_cache is None:
            label_cache = dict()
        # end if

        label_bytes = []
        part_offset = start_offset

        label_parts = label.split(".")
        while label_parts:
            cache_key = ".".join(label_parts).lower()

            if cache_key in label_cache:
                cache_offset = \
                    label_cache[cache_key].to_bytes(1, byteorder="big")
                label_bytes.extend([b"\xC0", cache_offset])

                part_offset += 2

                # Since we've gotten a cache hit on part.part...tld, exit the
                # loop.
                break
            else:
                cur_label = codecs.encode(label_parts.pop(0), "ascii")
                cur_label_len = len(cur_label).to_bytes(1, byteorder="big")
                label_bytes.extend([cur_label_len, cur_label])

                # Save the label offset in the cache
                label_cache[cache_key] = part_offset

                part_offset += 1 + cur_label_len[0] # Size + label_len
            # end if
        else:
            # If we got through the whole loop without a break (i.e. no
            # compression) then add the NULL label
            label_bytes.append(b"\x00")
        # end while

        return b"".join(label_bytes)
    # end def label_to_bytes
# end class DNSMessageSerializer

class Question:
    """Represents a question from a DNS message.
    
    Attributes:
        qname (str): The domain name.
        qtype (int): The type of query.
        qclass (int): The class of the query.
    """

    _defaults = {
        "qname": "",
        "qtype": QTYPE.A.value,
        "qclass": QCLASS.IN.value,
    }

    def __init__(self, **kwargs):
        """Initializes a Question object.

        Args:
            qname (str): The domain name.
            qtype (int): The type of query.
            qclass (int): The class of the query.
        """

        for attr_name in self._defaults:
            if attr_name in kwargs:
                setattr(self, attr_name, kwargs[attr_name])
            else:
                setattr(self, attr_name, self._defaults[attr_name])
            # end if
        # end for
    # end def __init__

    def __str__(self):
        # Try to get a human-friendly name for qtype
        try:
            qtype = QTYPE(self.qtype).name
        except ValueError:
            qtype = self.qtype
        # end try

        # Try to get a human-friendly name for qclass
        try:
            qclass = QCLASS(self.qclass).name
        except ValueError:
            qclass = self.qclass
        # end try

        return "Question(" \
            f"qname='{self.qname}', " \
            f"qtype={qtype}, " \
            f"qclass={qclass})"
    # end def __str__

    def __repr__(self):
        return "Question(" \
            f"qname='{self.qname}', " \
            f"qtype={self.qtype}, " \
            f"qclass={self.qclass})"
    # end def __repr__
# end class Question

class ResourceRecord:
    """Represents a DNS resource record.
    
    Attributes:
        name (str): The relevant (domain) name.
        rtype (int): The resource record type code.
        rclass (int): The class of data.
        ttl (int): How long the record should be cached. (managed)
        data (bytes): The record data. (managed)
        _ttl (int): Used to manage access and validate :attr:`ttl`.
        _rdata (bytes):  Used to manage access and validate :attr:`rdata`
    """

    _defaults = {
        "name": "",
        "rtype": QTYPE.A.value,
        "rclass": QCLASS.IN.value,
        "ttl": 0x3C,
        "rdata": b"",
    }

    def __init__(self, **kwargs):
        """Initializes a ResourceRecord object.
        
        Args:
            name (str): The relevant (domain) name.
            rtype (int): The resource record type code.
            rclass (int): The class of data.
            ttl (int): How long the record should be cached.
            rdata (bytes): The record data
        """

        for attr_name in self._defaults:
            if attr_name in kwargs:
                setattr(self, attr_name, kwargs[attr_name])
            else:
                setattr(self, attr_name, self._defaults[attr_name])
            # end if
        # end for
    # end def __init__

    @property
    def ttl(self):
        return self._ttl
    # end def ttl

    @ttl.setter
    def ttl(self, value):
        if 0 <= value <= 0xFFFFFFFF:
            self._ttl = value
            return
        # end if

        raise ValueError(f"Invalid value for TTL: {value}")
    # end def ttl

    @property
    def rdata(self):
        return self._rdata
    # end def rdata

    @rdata.setter
    def rdata(self, value):
        if len(value) > 0xFFFF:
            raise ValueError(f"rdata too big {len(value)}")
        # end if

        self._rdata = value
    # end def rdata

    def __str__(self):
        # Try to get a human-friendly name for rtype
        try:
            rtype = QTYPE(self.rtype).name
        except ValueError:
            rtype = self.rtype
        # end try

        # Try to get a human-friendly name for rclass
        try:
            rclass = QCLASS(self.rclass).name
        except ValueError:
            rclass = self.rclass
        # end try

        return "ResourceRecord(" \
            f"name='{self.name}', " \
            f"rtype={rtype}, " \
            f"rclass={rclass}, " \
            f"ttl={self.ttl})"
    # end def __str__

    def __repr__(self):
        return "ResourceRecord(" \
            f"name='{self.name}', " \
            f"rtype={self.rtype}, " \
            f"rclass={self.rclass}, " \
            f"ttl={self.ttl}, " \
            f"rdata={repr(self.rdata)})"
    # end def __repr__
# end class ResourceRecord

class FakeDnsServer:
    """Fake DNS server to respond to DNS requests for reversing purposes.

    Attributes:
        logger (Logger): The logging mechanism.
        ignore (list): List of Domains (and subdomains) and FQDNs to ignore.
        resolve (dict): Domains (and subdomains) and FQDNs to resolve to a
            specific IP address.
        default_ip (IPv4Address): The default IP address to respond with.
        bind_ip (IPv4Address): The IP address of the network interface to bind
            to.
        bind_port (int): The port to bind to.
        debug (bool): True if debugging output should be displayed.
        quit (bool): Set this to true to tell the server to exit (or hit
            Ctrl-c).
        _debug (bool): Used internally to enable on-the-fly debug output
            switching.
    """

    _defaults = {
        "logger": _logger,
        "resolve": dict(),
        "default_ip": ipaddress.IPv4Address("0.0.0.0"),
        "bind_ip": ipaddress.IPv4Address("0.0.0.0"),
        "bind_port": 53,
        "_debug": False,
    }

    def __init__(self, **kwargs):
        """Initializes a FakeDnsServer.

        Note:
            All arguments are optional.

        Args:
            ignore (list): Domains (and subdomains) and FQDNs to ignore.
            resolve (dict): Domains (and subdomains) and FQDNs to resolve to
                a specific IP address.
            default_ip (IPv4Address): The default address to respond with.
            interface_ip (IPv4Address): The IP address of the network
                interface to bind to.
            debug (bool): True if debugging output should be displayed.
        """

        for attr_name in self._defaults.keys():
            if attr_name in kwargs:
                attr_value = kwargs[attr_name]
            else:
                attr_value = self._defaults[attr_name]
            # end if

            setattr(self, attr_name, attr_value)
        # end for

        if "ignore" in kwargs:
            self.ignore = kwargs["ignore"]
        else:
            self.ignore = list()
        # end if

        if "debug" in kwargs:
            debug = bool(kwargs["debug"])
        else:
            debug = bool(self._defaults["debug"])
        # end if

        self._debug = debug

        if debug and self.logger:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        # end if

        self.default_ip = ipaddress.IPv4Address(self.default_ip)

        # Convert ignore list to lowercase (to be case insensitive for
        # matching).
        self.ignore = [entry.lower() for entry in self.ignore]

        # Convert resolve dict to lowercase (to be case insensitive for
        # matching).
        resolve_lower = dict()
        for key, value in self.resolve.items():
            resolve_lower[key.lower()] = ipaddress.IPv4Address(value)
        # end for
        self.resolve = resolve_lower

        if self._debug:
            self.debug_msg("Server started with following parameters")
            self.debug_msg(f" + Debug: {self.debug}")
            self.debug_msg(f" + Ignore: {self.ignore}")
            self.debug_msg(f" + Resolve: {self.resolve}")
            self.debug_msg(f" + Default IP: {self.default_ip}")
            self.debug_msg(f" + Bind IP: {self.bind_ip}")
            self.debug_msg(f" + Bind Port: {self.bind_port}")
            self.debug_msg(f" + Logger: {self.logger}")
        # end if
    # end def __init__

    @property
    def debug(self):
        return self._debug
    # end def debug

    @debug.setter
    def debug(self, enable_debug):
        enable_debug = bool(enable_debug)
        self._enable_debug = enable_debug

        if not self.logger:
            return
        # end if


        if enable_debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        # end if
    # end def debug

    def critical_msg(self, msg):
        """Logs a critical message.

        Notes:
            This is typically when some exception occurs, and the program
            should exit abnormally.

        Args:
            msgr (str): The message to log.
        """

        if not self.logger:
            return
        # end if

        self.logger.critical(msg)
    # end def critical_msg

    def error_msg(self, msg):
        """Logs an error message.

        Args:
            msg (str): The message to log.
        """

        if not self.logger:
            return
        # end if

        self.logger.error(msg)
    # end def error_msg

    def debug_msg(self, msg):
        """Logs a debug message.

        Args:
            msg (str): The message to log.
        """

        if not self.logger:
            return
        # end if

        self.logger.debug(msg)
    # end def debug_msg

    def log_msg(self, msg):
        """Logs a message.

        Args:
            msg (str): The message to log.
        """

        if not self.logger:
            return
        # end if

        self.logger.info(msg)
    # end def log_msg

    def debug_dns_msg(self, dns_msg):
        """Helper method to log a DNS message to debug output (if enabled).

        Args:
            dns_msg(:class:`DNSMessage`): The DNS message to log
        """

        if not self.logger or not self.debug:
            return
        # end if

        # Try to get print-friendly names for opcode
        try:
            opcode = OPCODE(dns_msg.opcode).name
        except ValueError:
            opcode = dns_msg.opcode
        # end try

        # Try to get a print-friendly name for rcode
        try:
            rcode = RCODE(dns_msg.rcode).name
        except ValueError:
            rcode = dns_msg.rcode
        # end try

        self.debug_msg("DNS Message:")
        self.debug_msg(f" + Transaction Id: 0x{dns_msg.id:02X}")
        self.debug_msg(f" + Query/Response: {dns_msg.qr}")
        self.debug_msg(f" + Opcode: {opcode}")
        self.debug_msg(f" + Authoritative Answer: {dns_msg.aa}")
        self.debug_msg(f" + Truncation: {dns_msg.tc}")
        self.debug_msg(f" + Recursion Desired: {dns_msg.rd}")
        self.debug_msg(f" + Recursion Available: {dns_msg.ra}")
        self.debug_msg(f" + Z: {dns_msg.z}")
        self.debug_msg(f" + Authentic Data: {dns_msg.ad}")
        self.debug_msg(f" + Checking Disabled: {dns_msg.cd}")
        self.debug_msg(f" + Response Code: {rcode}")

        self.debug_msg(f" + Questions: {len(dns_msg.question)}")
        for query in dns_msg.question:
            self.debug_msg(f"    + {str(query)}")
        # end for

        self.debug_msg(f" + Answer RRs: {len(dns_msg.answer)}")
        for rr in dns_msg.answer:
            self.debug_msg(f"    + {str(rr)}")
        # end for

        self.debug_msg(f" + Authority RRs: {len(dns_msg.authority)}")
        for rr in dns_msg.authority:
            self.debug_msg(f"    + {str(rr)}")
        # end for

        self.debug_msg(f" + Additional RRs: {len(dns_msg.additional)}")
        for rr in dns_msg.additional:
            self.debug_msg(f"    + {str(rr)}")
        # end for
    # end def debug_dns_msg

    def start(self):
        """Starts the server."""

        serializer = DNSMessageSerializer

        self.debug_msg("Starting server")
        self.log_msg(f"dom.query. 60 IN A {self.default_ip}")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock_obj:
            try:
                sock_obj.bind((self.bind_ip, self.bind_port))

            except Exception as e:
                self.critical_msg(f"{type(e).__name__}: {e}")
                summary = traceback.extract_tb(sys.exc_info()[2]).format()
                for tb_lines in summary:
                    for tb_line in tb_lines.split("\n"):
                        self.debug_msg(f"{tb_line}")
                    # end for
                # end for

                ip_port = f"{self.bind_ip}:{self.bind_port}"
                self.critical_msg(f"Unable to listen on {ip_port}")

                sys.exit(-1)
            # end try

            try:
                while True:
                    # Block until we get a request
                    data, remote = sock_obj.recvfrom(4096)
                    self.debug_msg(
                        f"Received request from {remote[0]}:{remote[1]}"
                    )

                    dns_resp = None

                    try:
                        dns_req = serializer.message_from_bytes(data)
                        self.debug_dns_msg(dns_req)

                        dns_resp = self.handle_dns_message(dns_req)

                        if dns_resp is None:
                            continue
                        # end if

                        self.debug_dns_msg(dns_resp)

                        sock_obj.sendto(
                            serializer.message_to_bytes(dns_resp),
                            remote
                        )

                    except Exception as e:
                        # Catch any errors that might occur when building
                        # a message and log them
                        err_msg = f"{type(e).__name__}: {e}"
                        self.error_msg(err_msg)

                        summary = traceback.extract_tb(sys.exc_info()[2])
                        summary = summary.format()

                        for tb_lines in summary:
                            for tb_line in tb_lines.split("\n"):
                                self.error_msg(f"{tb_line}")
                            # end for
                        # end for
                    # end try
                # end while

            except KeyboardInterrupt:
                self.debug_msg("Received KeyboardInterrupt")
                return

            except Exception as e:
                self.critical_msg(f"{type(e).__name__}: {e}")
                summary = traceback.extract_tb(sys.exc_info()[2]).format()

                for tb_lines in summary:
                    for tb_line in tb_lines:
                        self.critical_msg(tb_line)
                return
            # end try
        # end with
    # end def start

    def handle_dns_message(self, dns_req):
        """Handles a DNS message.

        Args:
            dns_req (:class:`DNSMessage`): The DNS message to handle.

        Returns:
            :class:`DNSMessage`-or-None: Either a DNS message to send in
                response, or None if no response is to be sent.
        """

        if dns_req.qr != 0:
            self.debug_msg("Skipping non query")
            return
        # end if

        if not dns_req.question:
            self.debug_msg("Skipping request with no question section")
            return
        # end if

        fqdn = dns_req.question[0].qname
        dns_resp = None
        ip = None

        # Check if there is a ".", otherwise it's just a hostname with
        # no domain name
        if "." in fqdn:
            domain = "." + fqdn.split(".", maxsplit=1)[-1]
        else:
            domain = fqdn
        # end if

        fqdn_lower = fqdn.lower()
        domain_lower = domain.lower()

        self.debug_msg(f"FQDN = {fqdn}, domain = {domain}")

        # First check if the fqdn should be ignored
        if fqdn_lower in self.ignore:
            self.debug_msg(f"Found {fqdn} in ignore list (as FQDN)")
            self.log_msg(f"Ignoring request for {fqdn}")

        # Second check if the fqdn should resolve to a specific
        # IP address
        elif fqdn_lower in self.resolve:
            self.debug_msg(f"Found {fqdn} in resolve list (as FQDN)")
            ip = self.resolve[fqdn_lower]

        # Third check if the domain should be ignored
        elif domain_lower in self.ignore:
            self.debug_msg(f"Found {domain} in ignore list (as domain)")
            self.log_msg(f"Ignoring request for {domain}")

        # Fourth check if the domain should be resolved to a specific IP
        elif domain_lower in self.resolve:
            self.debug_msg(f"Found {domain} in resolve list (as domain)")
            ip = self.resolve[domain_lower]

        # Finally send back the default IP address
        else:
            self.debug_msg(f"Sending default_ip for {fqdn}")
            ip = self.default_ip
        # end if

        if ip is None:
            return
        # end if

        dns_resp = self.build_response(dns_req, ip)
        self.log_msg(f"Response: {fqdn} -> {ip}")

        return dns_resp
    # end def handle_dns_message

    def build_response(self, dns_req, ip):
        """Builds an answer to a DNS resolution request.

        Args:
            dns_req (:class:`DNSMessage`): The DNS request.
            ip (:class:`ipaddress.IPv4Address`): The IP address for the
                answer.

        Returns:
            (:class:`DNSMessage`): A DNS message to send as a response.
        """

        self.debug_msg(f"Building a DNS response for {ip}")

        dns_resp = DNSMessage()

        dns_resp.id = dns_req.id
        dns_resp.qr = 1 # This is an answer
        dns_resp.opcode = OPCODE.QUERY.value
        dns_resp.aa = False # Non authoriative answer
        dns_resp.tc = False # Not truncated
        dns_resp.rd = dns_req.rd
        dns_resp.ra = True # Recursion available
        dns_resp.z = dns_req.z
        dns_resp.ad = False
        dns_resp.cd = False
        dns_resp.rcode = RCODE.NOERROR.value
        dns_resp.question = dns_req.question

        answer = ResourceRecord(
            name=dns_req.question[0].qname,
            rtype=QTYPE.A.value,
            rclass=QCLASS.IN.value,
            ttl=0x3C,
            rdata=ip.packed
        )

        dns_resp.answer.append(answer)

        return dns_resp
    # end def build_answer
# end class FakeDnsServer


def is_valid_ip(ip):
    """Determines if an IP address is valid or not.

    Args:
        ip (str): The IP address

    Returns:
        bool: True if ip is a valid IP address, false if not.
    """

    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    # end try

    return True
# end def is_valid_ip

def parse_config_file(name):
    """Parses a configuration file.

    Args:
        name (str): The name of the config file.

    Returns:
        tuple: A tuple of (ignore, resolve) where ignore is a list of labels
            to ignore, and resolve is a dictionary of labels to resolve to a
            specific IP address.
    """

    ignore = list()
    resolve = dict()

    _logger.debug(f"Parsing config file {name}")

    try:
        with open(name, "rt") as file_obj:

            # Process each line in the file, one at a time
            for line_num, orig_line in enumerate(file_obj):

                # The octothorpe (#) is a comment, and like Python ignore from
                # the octothorpe to the end of the line
                if "#" in orig_line:
                    orig_line = orig_line[:orig_line.index("#")]
                # end if

                # Remove leading and trailing whitespace
                line = orig_line.strip()

                # Skip blank lines
                if not line:
                    _logger.debug(f"Skipping blank line {line_num}")
                    continue
                # end if

                _logger.debug(f"Processing line {line_num} '{line}'")

                # Split at whitespace
                items = line.split()

                if len(items) > 2:
                    err_msg = f"Skipping invalid line in config file (line " \
                        f"{line_num})"
                    _logger.info(err_msg)
                    continue
                # end if

                # If there is only one item in the line, it is an ignore
                if len(items) == 1:
                    _logger.debug(f"Ignoring {items[0]}")
                    ignore.append(items[0])

                else:
                    # Since it's not an ignore, it's a resolve rule

                    # First validate the IP address
                    if not is_valid_ip(items[1]):
                        _logger.error(
                            f"Error parsing config file: invalid IP " \
                            f" {items[1]} (line {line_num})"
                        )
                        sys.exit(-1)
                    # end if

                    _logger.debug(f"Resolving {items[0]} to {items[1]}")
                    resolve[items[0]] = items[1]
                # end if
            # end for
        # end with

    except FileNotFoundError:
        _logger.critical(f"Unable to open file {name}: file not found")
        sys.exit(-1)

    except PermissionError:
        _logger.critical(f"Unable to open file {name}: permission denied")
        sys.exit(-1)

    except Exception as e:
        _logger.critical(f"{type(e).__name__}: {e}")
        summary = traceback.extract_tb(sys.exc_info()[2])
        summary = summary.format()

        for tb_lines in summary:
            for tb_line in tb_lines.split("\n"):
                _logger.critical(tb_line)
            # end for
        # end for

        sys.exit(-1)
    # end try


    return (ignore, resolve)
# end def parse_config_file

def find_bind_ip():
    """Finds the first available IP address to bind to.

    Returns:
        str: The first non-loopback IP address. If no available IPs are found,
        "0.0.0.0" is returned.
    """

    _logger.debug("Finding IP address to bind to")

    # Get a list of interfaces
    interfaces = netifaces.interfaces()

    for interface in interfaces:
        _logger.debug(f"Examining interface {interface}")

        # Get the addresses for a given interface
        addresses = netifaces.ifaddresses(interface)

        # Skip if no IPv4 addresses
        if netifaces.AF_INET not in addresses:
            _logger.debug(f"No IPv4 addresses found in {interface}, skipping")
            continue
        # end if

        for address in addresses[netifaces.AF_INET]:
            _logger.debug(f"Examining address {address['addr']}")
            ip = ipaddress.IPv4Address(address['addr'])

            # Skip if loopback address
            if ip.is_loopback:
                _logger.debug(f"Skipping loopback address {ip}")
                continue
            # end if

            _logger.debug(f"Found bind ip {str(ip)}")
            return str(ip)
        # end for
    # end for

    _logger.debug("No bind ip found, using 0.0.0.0")
    return "0.0.0.0"
# end def find_bind_ip

def main():
    """Invoked when called as a standalone program."""

    epilog = textwrap.dedent(f"""\
       Configuration file format:
       
       The configuration file consists of one or more rules that instruct
       fakedns to either resolve or ignore, a given DNS query.
       
       Here is an example configuration file:
       
       .microsoft.com
       host.example.com 1.2.3.4
       .example.com
       host.company.com
       .company.com 2.3.4.5
       
       Each rule must be on a single line, and has one or two parts. Rules with
       one part instruct fakedns to ignore a DNS query. In the example shown
       above there are three ignore rules: .microsoft.com, .example.com, and
       host.company.com. Rules with two parts instruct fakedns to resolve a
       DNS query to a specific IP address. In the example shown above there are
       two resolve rules: host.example.com, and .company.com.
       
       Each rule begins with a label. If the first character of the label is a
       dot ('.'), it is considered a wildcard and the rule is applied for any
       query that matches the domain (or subdomain) specified. If the first
       character is not a dot, the label is considered a Fully Qualified
       Domain Name, and the rule is applied only if the DNS query matches
       that exact label. In the example shown above, .microsoft.com,
       .example.com, and .company.com are wildcard matches, and 
       host.example.com, and host.company.com are exact matches.
       
       Rules with two parts (resolve rules) must have an IP address that
       follows the label, separated by a single whitespace. In the example
       shown above, queries for host.example.com resolve to 1.2.3.4, and
       any query for .company.com will resolve to 2.3.4.5.
    """)

    # First parse the command line arguments, to determine configuration
    arg_parser = argparse.ArgumentParser(
        description="Fake DNS Server for reversing",
        epilog=epilog,
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    arg_parser.add_argument(
        "-a",
        metavar="IP",
        dest="default_ip",
        help="Default IP address to respond with"
    )

    arg_parser.add_argument(
        "-I",
        metavar="IP",
        dest="bind_ip",
        help= \
            "IP of interface to bind to (default: first non-loopback " \
            "interface)"
    )

    arg_parser.add_argument(
        "-p",
        metavar="PORT",
        dest="bind_port",
        default=53,
        type=int,
        help="Port to bind to (default: 53)"
    )

    arg_parser.add_argument(
        "-f",
        metavar="FILE",
        dest="config_file",
        help="Configuration file that describes names/addresses to respond " \
            "with and to ignore"
    )

    arg_parser.add_argument(
        "-d",
        action="store_true",
        default=False,
        dest="debug",
        help="Enable debugging output (default: False)"
    )

    arg_parser.add_argument(
        "--ignore",
        action="append",
        metavar="LABEL",
        dest="ignore",
        help="Domains (.domain.tld) or FQDNs (host.domain.tld) to ignore " \
             "(can be specified multiple times.)"
    )

    arg_parser.add_argument(
        "--resolve",
        action="append",
        metavar=("LABEL", "IP"),
        nargs=2,
        dest="resolve",
        help="Domains (.domain.tld) or FQDNs (host.domain.tld) to resolve " \
            "to a specific IP address (can be specified multiple times.)"
    )

    args = arg_parser.parse_args()

    # If debugging set at the command line, enable debug output now
    if args.debug:
        _logger.setLevel(logging.DEBUG)
    # end if

    ignore = list()
    resolve = dict()

    # Parse the config file if specified
    if args.config_file:
        ignore, resolve = parse_config_file(args.config_file)
    # end if

    # Merge any ignore rules from config (if any) with those from the command
    # line
    if args.ignore:
        ignore.extend(args.ignore)
    # end if

    # Merge any resolve rules form config (if any) with those from the command
    # line
    if args.resolve:
        for (label, ip) in args.resolve:

            # Validate the IP address
            if not is_valid_ip(ip):
                _logger.error(f"Invalid IP address {ip}")
                sys.exit(-1)
            # end if

            resolve[label] = ip
        # end for
    # end if

    if args.bind_ip:
        bind_ip = args.bind_ip
    else:
        bind_ip = find_bind_ip()
    # end if

    if args.default_ip:
        default_ip = args.default_ip
    else:
        default_ip = bind_ip
    # end if

    fake_dns_server = FakeDnsServer(
        default_ip=default_ip,
        bind_ip=bind_ip,
        bind_port=args.bind_port,
        ignore=ignore,
        resolve=resolve,
        debug=args.debug
    )

    fake_dns_server.start()
    _logger.info("Done")
# end def main

# Run main if we're being called as a standalone
if __name__ == "__main__":
    main()
# end if
