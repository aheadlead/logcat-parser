"""
logcat_parser
~~~~~~~~~~~~~

Provide a set of parsers to format binary logcat bytes or stream.

"""
from time import sleep

from struct import unpack
from enum import Enum, unique
from select import select

__all__ = [
    'LogcatParser',
    'LogcatStreamParser',
    'EventParser',
    'MessageParser',
    'LogcatParserError',
]


class LogcatParserError(Exception):
    """ Instantiate this class and raise when errors occured in the process of
        parsing.
    """


@unique
class EventLogType(Enum):
    """ event log payload type code
        ref: Android source /system/core/include/log/log.h:489
    """
    EVENT_TYPE_INT = 0  # 32-bit signed int
    EVENT_TYPE_LONG = 1  # 64-bit signed long
    EVENT_TYPE_STRING = 2  # one byte for length N, and follows N bytes string
    EVENT_TYPE_LIST = 3  # one byte for number of elements
    EVENT_TYPE_FLOAT = 4  # four bytes; 32-bit ieee 754

@unique
class LogId(Enum):
    """ typedef enum log_id
        ref: Android source /system/core/include/log/log.h:533
    """
    LOG_ID_MAIN = 0
    LOG_ID_RADIO = 1
    LOG_ID_EVENTS = 2
    LOG_ID_SYSTEM = 3
    LOG_ID_CRASH = 4
    LOG_ID_SECURITY = 5
    LOG_ID_KERNEL = 6


def safe_slice(sliceable, base, offset):
    """ slice a sliceable object with bounds checking

        >>> foo = '0123456789'
        >>> safe_slice(foo, 0, 10)
        '0123456789'
        >>> safe_slice(foo, 4, 3)
        '456'
        >>> safe_slice(foo, 8, 5)
        Traceback (most recent call last):
          ...
        IndexError
    """
    binary = sliceable  # alias
    valid_idx_range = range(len(binary) + 1)
    if any(idx not in valid_idx_range for idx in [base, base + offset]):
        raise IndexError()
    return binary[base:base + offset]


class LogcatParser:
    """ Parser for logcat in binary format stored in bytes object.  """

    def __init__(self, binary, version=None):
        self._result = None
        self._event = None
        self._message = None

        supported_version = [None, 3, 4]
        if version in supported_version:
            self._version = version
        else:
            msg = 'unsupported version'
            raise LogcatParserError(msg)

        self._binary = binary

        self._parse()

    def __len__(self):
        return len(self._result)

    def __iter__(self):
        return iter(self._result)

    def __getitem__(self, idx):
        return self._result[idx]

    def __str__(self):
        return str(self._result)

    def _parse(self) -> None:
        # detect logger_entry version when no version specified
        #
        # ref: /system/core/liblog/logprint.c:753
        #
        # The line 778 of logprint.c made me confused. Because
        # sizeof(logger_entry_v2) and sizeof(logger_entry_v3) are same always.
        # It is hard to understand the way Mark Salyzyn distinguish them.

        if not self._version:
            hdr_size = unpack('H', self._slice_binary(2, 2))[0]

            if hdr_size == 28:
                self._version = 4

            elif hdr_size == 24:
                self._version = 3

            elif hdr_size == 20:
                raise LogcatParserError(
                    "logcat_parser didn't support logger_entry version 1"
                )

            else:
                binary = self._binary
                raise LogcatParserError(
                    "logcat_parser can't recognize this logger_entry (hdr_size="
                    "{hdr_size}, binary={binary})".format(**locals())
                )

        if self._version == 4:
            self._parse_v4()

        elif self._version == 3:
            self._parse_v3()

    def _slice_binary(self, base, offset):
        return safe_slice(self._binary, base, offset)

    def _parse_v3(self) -> None:

        offset = 0
        self._result = list()

        try:
            while True:
                len_, hdr_size = unpack('HH', self._slice_binary(offset, 4))
                offset += 4

                if hdr_size != 0x0018:  # 0x18 == 24
                    msg = 'hdr_size {literal} should be 0x0018 in version 3,' \
                        .format(literal=hex(hdr_size))
                    msg += ' binary={binary}'.format(binary=str(self._binary))
                    raise LogcatParserError(msg)

                pid, tid, sec, nsec, lid = \
                    unpack('iIIII', self._slice_binary(offset, 20))
                offset += 20

                msg = self._slice_binary(offset, len_)
                offset += len_

                # pylint: disable=C0324
                self._result.append({
                    'len': len_,
                    'hdr_size': hdr_size,
                    'pid': pid,
                    'tid': tid,
                    'sec': sec,
                    'nsec': nsec,
                    'lid': lid,
                    'msg': msg,
                    'version': 3,
                })
        except IndexError:
            pass

    def _parse_v4(self) -> None:

        offset = 0
        self._result = list()

        try:
            while True:
                len_, hdr_size = unpack('HH', self._slice_binary(offset, 4))
                offset += 4

                if hdr_size != 0x001c:  # 0x1c == 28
                    msg = 'hdr_size {literal} should be 0x001c in version 4,' \
                        .format(literal=hex(hdr_size))
                    msg += ' binary={binary}'.format(binary=str(self._binary))
                    raise LogcatParserError(msg)

                pid, tid, sec, nsec, lid, uid = \
                    unpack('iIIIII', self._slice_binary(offset, 24))
                offset += 24

                msg = self._slice_binary(offset, len_)
                offset += len_

                # pylint: disable=C0324
                self._result.append({
                    'len': len_,
                    'hdr_size': hdr_size,
                    'pid': pid,
                    'tid': tid,
                    'sec': sec,
                    'nsec': nsec,
                    'lid': lid,
                    'uid': uid,
                    'msg': msg,
                    'version': 4,
                })

        except IndexError:
            pass

    @property
    def event(self):
        if 'msg' in self:
            if not self._event:
                self._event = EventParser(self['msg'])
        else:
            raise LogcatParserError('Invalid LogcatParser status')

        return self._event

    @property
    def message(self):
        if 'msg' in self:
            if not self._message:
                self._message = MessageParser(self['msg'])
        else:
            raise LogcatParserError('Invalid LogcatParser status')

        return self._message


class LogcatStreamParser(LogcatParser):

    def __init__(self, binary_stream, version=None, timeout=None):

        self._event_parser = None
        self._message_parser = None

        self._stream = binary_stream

        binary = self.read(4, timeout)

        len_, hdr_size = unpack('HH', binary)

        if hdr_size == 0:
            hdr_size = 20
            
        binary += self.read(len_ + hdr_size - 4, None)

        super().__init__(binary, version)

        self._parse()

    def read(self, size, timeout=None):
        """ implemented by select() for timeout support """
        rlist, _, _ = select([self._stream.fileno()], [], [], timeout)
        if rlist:
            # NOTICE: may block here if no enough bytes to read in abnormal
            # situation
            return self._stream.read(size)
        else:
            raise TimeoutError('logcat read timeout')


class MessageParser:

    def __init__(self, result: LogcatParser):

        binary = result['msg']

        # priority
        # pylint: disable=C0324
        priority_mapper = {
            b'\x00': 'unknown',
            b'\x01': 'default',
            b'\x02': 'verbose',
            b'\x03': 'debug',
            b'\x04': 'info',
            b'\x05': 'warn',
            b'\x06': 'error',
            b'\x07': 'fatal',
            b'\x08': 'slient',
        }

        priority_bytes = safe_slice(binary, 0, 1)

        if priority_bytes not in priority_mapper:
            msg = 'unknown priority bytes ' + repr(priority_bytes)
            raise LogcatParserError(msg)
        priority = priority_mapper[priority_bytes]

        # tag
        try:
            tag_terminating = binary.index(b'\x00', 1)
            tag = binary[1:tag_terminating]

        except ValueError as exc:
            if exc.args == 'subsection not found': 
                raise LogcatParserError('invalid message')
            else:
                raise

        # message
        message = binary[tag_terminating + 1:]
        # remove weird trailing empty character
        message = message.rstrip(b'\x00')

        self._priority = priority
        self._tag = tag
        self._message = message

    def __getitem__(self, key):
        mapper = {
            'priority': self._priority,
            'tag': self._tag,
            'message': self._message,
        }
        return mapper[key]

    def __str__(self):
        return "{{'priority': {priority}, 'tag': {tag}, 'message': {message}}}"\
            .format(priority=repr(self._priority),
                    tag=repr(self._tag),
                    message=repr(self._message))


# pylint: disable=too-few-public-methods
class EventParser:

    def __init__(self, result: LogcatParser, event_tag_map: bytes = None):
        self._message = None

        self._binary = result['msg']

        priority_candidate = 'info'
        if result['version'] in [3, 4]:
            if result['lid'] == LogId.LOG_ID_SECURITY:
                priority_candidate = 'warn'
        self._priority = priority_candidate

        # The param event_tag_map is a bytes object which stores the whole
        # event-log-tags file.
        #
        # The member self._event_tag_map is a dict object which stores
        # the formatted event-log-tags file.
        #
        # For the format of param event_tag_map, see /system/etc/event-log-tags
        # on any Android device.

        self._event_tag_map = dict()
        if event_tag_map:
            try:
                # remove silly linefeed
                event_tag_map = event_tag_map.decode()
                event_tag_map = event_tag_map.strip()
                event_tag_map = event_tag_map.replace('\r\n', '\n')

                for line in event_tag_map.split('\n'):
                    # rest? We have not use it variable in other codes, just
                    # keep it here for other uses in future.
                    id_, tag, *rest = line.split(' ')

                    self._event_tag_map[int(id_)] = {'tag': tag, 'rest': rest}

            except ValueError:
                # catch this exception when:
                # 1. Id is not integer
                # 2. less than two field unpacked from line
                raise LogcatParserError('invalid event-log-tags file')

        self._parse()

    def __getitem__(self, key):
        mapper = {
            'priority': self._priority,
            'tag': self._tag,
            'message': self._message,
        }
        return mapper[key]

    def __str__(self):
        return "{{'tag': {tag}, 'message': {message}}}" \
            .format(tag=repr(self._tag), message=repr(self._message))

    @property  # make it readonly
    def tag(self):
        return self._tag

    def _parse(self):
        """ parse binary data in self._binary for logcat events buffer """
        tag_id, *_ = unpack('I', safe_slice(self._binary, 0, 4))

        if tag_id in self._event_tag_map:
            self._tag = self._event_tag_map[tag_id]['tag']
        else:
            self._tag = tag_id

        _, self._message = EventParser._parse_events(self._binary[4:])

    @staticmethod
    def _parse_events(binary: bytes):

        in_count = 0

        type_in_int, *_ = unpack('B', safe_slice(binary, 0, 1))
        try:
            type_ = EventLogType(type_in_int)
        except ValueError as exc:
            raise LogcatParserError(exc.args)
        in_count += 1

        payload = binary[1:]

        if type_ == EventLogType.EVENT_TYPE_INT:
            value, *_ = unpack('i', safe_slice(payload, 0, 4))
            in_count += 4

        elif type_ == EventLogType.EVENT_TYPE_LONG:
            value, *_ = unpack('q', safe_slice(payload, 0, 8))
            in_count += 8

        elif type_ == EventLogType.EVENT_TYPE_FLOAT:
            value, *_ = unpack('f', safe_slice(payload, 0, 4))
            in_count += 4

        elif type_ == EventLogType.EVENT_TYPE_STRING:
            string_length, *_ = unpack('I', safe_slice(payload, 0, 4))
            in_count += 4

            value = safe_slice(payload, 4, string_length)
            in_count += string_length

        elif type_ == EventLogType.EVENT_TYPE_LIST:
            count, *_ = unpack('B', safe_slice(payload, 0, 1))
            value = list()
            offset = 1
            for _ in range(count):
                sub_in_count, sub_value = \
                    EventParser._parse_events(payload[offset:])
                in_count += sub_in_count
                offset += sub_in_count
                value.append(sub_value)
        else:
            raise LogcatParserError('unknown type ' + str(type_))

        return in_count, value


if __name__ == '__main__':
    # debugging only
    from sys import stdin

    event_log_tags = open('event-log-tags', 'rb').read()

    while True:
        PARSER = LogcatStreamParser(stdin.buffer)
        print(PARSER)
        MESSAGE_PARSER = MessageParser(PARSER[0])
        print(MESSAGE_PARSER)
        print()

