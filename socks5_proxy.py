import argparse
import asyncio
import base64
import ipaddress
import secrets
import socket
import struct
from urllib.parse import urlsplit


PROBES = {
    ("www.msftconnecttest.com", "/connecttest.txt"): b"Microsoft Connect Test",
    ("ipv6.msftconnecttest.com", "/connecttest.txt"): b"Microsoft Connect Test",
    ("www.msftncsi.com", "/ncsi.txt"): b"Microsoft NCSI",
    ("dns.msftncsi.com", "/ncsi.txt"): b"Microsoft NCSI",
    ("captive.apple.com", "/hotspot-detect.html"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("captive.apple.com", "/"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("www.apple.com", "/library/test/success.html"): b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
    ("detectportal.firefox.com", "/success.txt"): b"success\n",
    ("detectportal.firefox.com", "/canonical.html"): b"<meta http-equiv=\"refresh\" content=\"0; url=https://support.mozilla.org/kb/captive-portal\"/>\n",
    ("nmcheck.gnome.org", "/check_network_status.txt"): b"NetworkManager is online\n",
    ("networkcheck.kde.org", "/"): b"OK",
    ("connectivity-check.ubuntu.com", "/"): b"",
}


MUX_CONCURRENCY = 8


class H2MuxHPACK:
    static = ((b':authority', b''),
     (b':method', b'GET'),
     (b':method', b'POST'),
     (b':path', b'/'),
     (b':path', b'/index.html'),
     (b':scheme', b'http'),
     (b':scheme', b'https'),
     (b':status', b'200'),
     (b':status', b'204'),
     (b':status', b'206'),
     (b':status', b'304'),
     (b':status', b'400'),
     (b':status', b'404'),
     (b':status', b'500'),
     (b'accept-charset', b''),
     (b'accept-encoding', b'gzip, deflate'),
     (b'accept-language', b''),
     (b'accept-ranges', b''),
     (b'accept', b''),
     (b'access-control-allow-origin', b''),
     (b'age', b''),
     (b'allow', b''),
     (b'authorization', b''),
     (b'cache-control', b''),
     (b'content-disposition', b''),
     (b'content-encoding', b''),
     (b'content-language', b''),
     (b'content-length', b''),
     (b'content-location', b''),
     (b'content-range', b''),
     (b'content-type', b''),
     (b'cookie', b''),
     (b'date', b''),
     (b'etag', b''),
     (b'expect', b''),
     (b'expires', b''),
     (b'from', b''),
     (b'host', b''),
     (b'if-match', b''),
     (b'if-modified-since', b''),
     (b'if-none-match', b''),
     (b'if-range', b''),
     (b'if-unmodified-since', b''),
     (b'last-modified', b''),
     (b'link', b''),
     (b'location', b''),
     (b'max-forwards', b''),
     (b'proxy-authenticate', b''),
     (b'proxy-authorization', b''),
     (b'range', b''),
     (b'referer', b''),
     (b'refresh', b''),
     (b'retry-after', b''),
     (b'server', b''),
     (b'set-cookie', b''),
     (b'strict-transport-security', b''),
     (b'transfer-encoding', b''),
     (b'user-agent', b''),
     (b'vary', b''),
     (b'via', b''),
     (b'www-authenticate', b''))
    huffman_codes = (8184, 8388568, 268435426, 268435427, 268435428, 268435429, 268435430, 268435431, 268435432,
     16777194, 1073741820, 268435433, 268435434, 1073741821, 268435435, 268435436, 268435437, 268435438,
     268435439, 268435440, 268435441, 268435442, 1073741822, 268435443, 268435444, 268435445, 268435446,
     268435447, 268435448, 268435449, 268435450, 268435451, 20, 1016, 1017, 4090, 8185, 21, 248, 2042,
     1018, 1019, 249, 2043, 250, 22, 23, 24, 0, 1, 2, 25, 26, 27, 28, 29, 30, 31, 92, 251, 32764, 32,
     4091, 1020, 8186, 33, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
     110, 111, 112, 113, 114, 252, 115, 253, 8187, 524272, 8188, 16380, 34, 32765, 3, 35, 4, 36, 5, 37,
     38, 39, 6, 116, 117, 40, 41, 42, 7, 43, 118, 44, 8, 9, 45, 119, 120, 121, 122, 123, 32766, 2044,
     16381, 8189, 268435452, 1048550, 4194258, 1048551, 1048552, 4194259, 4194260, 4194261, 8388569,
     4194262, 8388570, 8388571, 8388572, 8388573, 8388574, 16777195, 8388575, 16777196, 16777197,
     4194263, 8388576, 16777198, 8388577, 8388578, 8388579, 8388580, 2097116, 4194264, 8388581, 4194265,
     8388582, 8388583, 16777199, 4194266, 2097117, 1048553, 4194267, 4194268, 8388584, 8388585, 2097118,
     8388586, 4194269, 4194270, 16777200, 2097119, 4194271, 8388587, 8388588, 2097120, 2097121, 4194272,
     2097122, 8388589, 4194273, 8388590, 8388591, 1048554, 4194274, 4194275, 4194276, 8388592, 4194277,
     4194278, 8388593, 67108832, 67108833, 1048555, 524273, 4194279, 8388594, 4194280, 33554412,
     67108834, 67108835, 67108836, 134217694, 134217695, 67108837, 16777201, 33554413, 524274, 2097123,
     67108838, 134217696, 134217697, 67108839, 134217698, 16777202, 2097124, 2097125, 67108840,
     67108841, 268435453, 134217699, 134217700, 134217701, 1048556, 16777203, 1048557, 2097126, 4194281,
     2097127, 2097128, 8388595, 4194282, 4194283, 33554414, 33554415, 16777204, 16777205, 67108842,
     8388596, 67108843, 134217702, 67108844, 67108845, 134217703, 134217704, 134217705, 134217706,
     134217707, 268435454, 134217708, 134217709, 134217710, 134217711, 134217712, 67108846, 1073741823)
    huffman_lengths = (13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28,
     28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6,
     6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
     7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5,
     5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23,
     24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23,
     21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
     26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21,
     21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27,
     26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30)
    huffman_tree = None

    def __init__(self):
        self.dynamic = []
        self.table_size = 4096
        self.used = 0
        if type(self).huffman_tree is None:
            tree = {}
            for symbol, (code, length) in enumerate(zip(self.huffman_codes, self.huffman_lengths)):
                node = tree
                for shift in range(length - 1, -1, -1):
                    node = node.setdefault((code >> shift) & 1, {})
                node[2] = symbol
            type(self).huffman_tree = tree

    def evict(self):
        while self.used > self.table_size:
            name, value = self.dynamic.pop()
            self.used -= len(name) + len(value) + 32

    @staticmethod
    def integer(data, offset, bits):
        if offset >= len(data):
            raise ValueError("truncated HPACK integer")
        mask = (1 << bits) - 1
        value = data[offset] & mask
        offset += 1
        if value == mask:
            shift = 0
            while True:
                if offset >= len(data) or shift > 28:
                    raise ValueError("invalid HPACK integer")
                byte = data[offset]
                offset += 1
                value += (byte & 127) << shift
                if not byte & 128:
                    break
                shift += 7
        return value, offset

    def string(self, data, offset):
        if offset >= len(data):
            raise ValueError("truncated HPACK string")
        huffman = bool(data[offset] & 128)
        size, offset = self.integer(data, offset, 7)
        end = offset + size
        if end > len(data):
            raise ValueError("truncated HPACK string")
        value = data[offset:end]
        if huffman:
            result = bytearray()
            root = self.huffman_tree
            node = root
            tail = 0
            padding = 0
            for byte in value:
                for shift in range(7, -1, -1):
                    bit = (byte >> shift) & 1
                    node = node.get(bit)
                    if node is None:
                        raise ValueError("invalid HPACK Huffman code")
                    tail = (tail << 1) | bit
                    padding += 1
                    symbol = node.get(2)
                    if symbol is not None:
                        if symbol == 256:
                            raise ValueError("HPACK Huffman EOS")
                        result.append(symbol)
                        node = root
                        tail = 0
                        padding = 0
            if padding > 7 or tail != (1 << padding) - 1:
                raise ValueError("invalid HPACK Huffman padding")
            value = bytes(result)
        return value, end

    def entry(self, index):
        if index <= 0 or index > len(self.static) + len(self.dynamic):
            raise ValueError("invalid HPACK index")
        if index <= len(self.static):
            return self.static[index - 1]
        return self.dynamic[index - len(self.static) - 1]

    def decode(self, data):
        result = []
        offset = 0
        total = 0
        while offset < len(data):
            byte = data[offset]
            if byte & 128:
                index, offset = self.integer(data, offset, 7)
                name, value = self.entry(index)
            elif byte & 32 and not byte & 64:
                if result:
                    raise ValueError("late HPACK table update")
                size, offset = self.integer(data, offset, 5)
                if size > 4096:
                    raise ValueError("HPACK table too large")
                self.table_size = size
                self.evict()
                continue
            else:
                indexed = bool(byte & 64)
                index, offset = self.integer(data, offset, 6 if indexed else 4)
                if index:
                    name = self.entry(index)[0]
                else:
                    name, offset = self.string(data, offset)
                value, offset = self.string(data, offset)
                if indexed:
                    self.dynamic.insert(0, (name, value))
                    self.used += len(name) + len(value) + 32
                    self.evict()
            total += len(name) + len(value) + 32
            if total > 65536 or not name or name.lower() != name:
                raise ValueError("invalid H2Mux headers")
            result.append((name.decode("ascii"), value.decode("utf-8")))
        return result

    @staticmethod
    def encode(headers):
        def integer(value):
            if value < 127:
                return bytes([value])
            result = bytearray([127])
            value -= 127
            while value >= 128:
                result.append((value & 127) | 128)
                value >>= 7
            result.append(value)
            return bytes(result)

        result = bytearray()
        for name, value in headers:
            name = name.encode("ascii")
            value = str(value).encode("utf-8")
            result.extend(b"\x00" + integer(len(name)) + name + integer(len(value)) + value)
        return bytes(result)


class H2MuxStream:
    def __init__(self, stream_id, headers, window):
        self.stream_id = stream_id
        self.headers = headers
        self.reader = asyncio.StreamReader(limit=65535)
        self.send_window = window
        self.receive_window = 65535
        self.send_ready = asyncio.Event()
        self.send_ready.set()
        self.remote_writer = None
        self.task = None
        self.input_ended = False
        self.output_ended = False


class H2Mux:
    def __init__(self, reader, writer, username=None, password=None, authenticated=False, first=b""):
        self.reader = reader
        self.writer = writer
        self.username = username
        self.password = password
        self.authenticated = authenticated
        self.first = first
        self.streams = {}
        self.last_stream = 0
        self.peer_window = 65535
        self.peer_frame_size = 16384
        self.write_lock = asyncio.Lock()
        self.decoder = H2MuxHPACK()
        self.closed = False

    async def read_frame(self):
        prefix = self.first
        self.first = b""
        raw = prefix + await self.reader.readexactly(9 - len(prefix))
        size = int.from_bytes(raw[:3], "big")
        if size > 16384:
            raise ValueError("H2Mux frame too large")
        return raw[3], raw[4], int.from_bytes(raw[5:], "big") & 0x7fffffff, await self.reader.readexactly(size)

    async def send_frame(self, kind, flags=0, stream_id=0, data=b""):
        async with self.write_lock:
            if self.closed:
                raise ConnectionError("H2Mux closed")
            self.writer.write(len(data).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream_id) + data)
            await self.writer.drain()

    async def send_headers(self, stream, headers, end=False):
        await self.send_frame(1, 4 | int(end), stream.stream_id, H2MuxHPACK.encode(headers))
        if end:
            stream.output_ended = True

    async def send_data(self, stream, data, end=False):
        offset = 0
        while offset < len(data):
            while stream.send_window <= 0:
                stream.send_ready.clear()
                await stream.send_ready.wait()
            size = min(len(data) - offset, stream.send_window, self.peer_frame_size)
            stream.send_window -= size
            await self.send_frame(0, 0, stream.stream_id, data[offset:offset + size])
            offset += size
        if end and not stream.output_ended:
            await self.send_frame(0, 1, stream.stream_id)
            stream.output_ended = True

    async def reset(self, stream_id, code):
        stream = self.streams.pop(stream_id, None)
        if stream is not None:
            stream.reader.feed_eof()
            stream.send_ready.set()
            close_writer(stream.remote_writer)
            if stream.task is not None and stream.task is not asyncio.current_task():
                stream.task.cancel()
                await asyncio.gather(stream.task, return_exceptions=True)
        await self.send_frame(3, 0, stream_id, struct.pack("!I", code))

    def settings(self, payload, handshake=False):
        if len(payload) % 6:
            raise ValueError("invalid H2Mux settings")
        values = dict(struct.iter_unpack("!HI", payload))
        if handshake and values.get(0x42db) != 0xa2e43c8b:
            raise ValueError("invalid H2Mux client magic")
        if 4 in values:
            window = values[4]
            if window > 0x7fffffff:
                raise ValueError("invalid H2Mux window")
            delta = window - self.peer_window
            self.peer_window = window
            for stream in self.streams.values():
                stream.send_window += delta
                if stream.send_window > 0:
                    stream.send_ready.set()
        if 5 in values:
            size = values[5]
            if not 16384 <= size <= 16777215:
                raise ValueError("invalid H2Mux frame size")
            self.peer_frame_size = min(size, 65536)

    async def handshake(self):
        settings = b"".join(struct.pack("!HI", key, value) for key, value in (
            (0x42db, 0x1088ebf9), (0xff20, 0), (3, MUX_CONCURRENCY),
        ))
        await self.send_frame(4, data=settings)
        kind, flags, stream_id, payload = await self.read_frame()
        if kind != 4 or flags or stream_id:
            raise ValueError("expected H2Mux settings")
        self.settings(payload, handshake=True)
        await self.send_frame(4, 1)
        kind, flags, stream_id, payload = await self.read_frame()
        if (kind, flags, stream_id, payload) != (4, 1, 0, b""):
            raise ValueError("expected H2Mux settings acknowledgement")

    async def headers(self, flags, stream_id, payload):
        if not stream_id or not stream_id & 1 or stream_id <= self.last_stream:
            raise ValueError("invalid H2Mux stream ID")
        self.last_stream = stream_id
        end = bool(flags & 1)
        if flags & 8:
            if not payload or payload[0] >= len(payload):
                raise ValueError("invalid H2Mux padding")
            payload = payload[1:len(payload) - payload[0]]
        if flags & 32:
            if len(payload) < 5:
                raise ValueError("invalid H2Mux priority")
            payload = payload[5:]
        block = bytearray(payload)
        while not flags & 4:
            kind, flags, next_id, payload = await self.read_frame()
            if kind != 9 or next_id != stream_id:
                raise ValueError("expected H2Mux continuation")
            block.extend(payload)
            if len(block) > 65536:
                raise ValueError("H2Mux header block too large")
        headers = self.decoder.decode(bytes(block))
        if len(self.streams) >= MUX_CONCURRENCY:
            await self.reset(stream_id, 7)
            return
        stream = H2MuxStream(stream_id, headers, self.peer_window)
        self.streams[stream_id] = stream
        if end:
            stream.input_ended = True
            stream.reader.feed_eof()
        stream.task = asyncio.create_task(multiplexer(self, stream))

    async def receive_data(self, flags, stream_id, payload):
        if not stream_id:
            raise ValueError("invalid H2Mux DATA stream")
        stream = self.streams.get(stream_id)
        if stream is None:
            await self.reset(stream_id, 5)
            return
        if stream.input_ended:
            await self.reset(stream_id, 5)
            return
        size = len(payload)
        stream.receive_window -= size
        if stream.receive_window < 0:
            await self.reset(stream_id, 3)
            return
        if flags & 8:
            if not payload or payload[0] >= len(payload):
                raise ValueError("invalid H2Mux DATA padding")
            padding = payload[0] + 1
            payload = payload[1:len(payload) - payload[0]]
            stream.receive_window += padding
            await self.send_frame(8, 0, stream_id, struct.pack("!I", padding))
        if payload:
            stream.reader.feed_data(payload)
        if flags & 1:
            stream.input_ended = True
            stream.reader.feed_eof()

    async def run(self):
        try:
            await asyncio.wait_for(self.handshake(), timeout=10)
            while True:
                kind, flags, stream_id, payload = await self.read_frame()
                if kind == 0:
                    await self.receive_data(flags, stream_id, payload)
                elif kind == 1:
                    await self.headers(flags, stream_id, payload)
                elif kind == 3:
                    if not stream_id or len(payload) != 4:
                        raise ValueError("invalid H2Mux reset")
                    stream = self.streams.pop(stream_id, None)
                    if stream is not None:
                        stream.task.cancel()
                        await asyncio.gather(stream.task, return_exceptions=True)
                elif kind == 4:
                    if stream_id or flags & 1 and payload:
                        raise ValueError("invalid H2Mux settings")
                    if not flags & 1:
                        self.settings(payload)
                        await self.send_frame(4, 1)
                elif kind == 6:
                    if stream_id or len(payload) != 8:
                        raise ValueError("invalid H2Mux ping")
                    if not flags & 1:
                        await self.send_frame(6, 1, data=payload)
                elif kind == 7:
                    if stream_id or len(payload) < 8:
                        raise ValueError("invalid H2Mux GOAWAY")
                    break
                elif kind == 8:
                    if not stream_id or len(payload) != 4:
                        raise ValueError("invalid H2Mux window update")
                    increment = int.from_bytes(payload, "big") & 0x7fffffff
                    if not increment:
                        raise ValueError("empty H2Mux window update")
                    stream = self.streams.get(stream_id)
                    if stream is not None:
                        if stream.send_window + increment > 0x7fffffff:
                            await self.reset(stream_id, 3)
                        else:
                            stream.send_window += increment
                            stream.send_ready.set()
                elif kind != 2:
                    raise ValueError("unsupported H2Mux frame")
        except (asyncio.IncompleteReadError, ConnectionError, OSError, TimeoutError):
            pass
        except (ValueError, UnicodeError, struct.error):
            try:
                await self.send_frame(7, data=struct.pack("!II", self.last_stream, 1))
            except (ConnectionError, OSError):
                pass
        finally:
            self.closed = True
            tasks = [stream.task for stream in self.streams.values() if stream.task is not None]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.streams.clear()
            close_writer(self.writer)


async def multiplexer(mux, stream):
    remote_writer = None
    tasks = []
    try:
        headers = {}
        regular = False
        for name, value in stream.headers:
            if name.startswith(":"):
                if regular or name in headers:
                    raise ValueError("invalid H2Mux pseudo-header")
            else:
                regular = True
            headers[name] = value
        if mux.username is not None and not mux.authenticated:
            expected = "Basic " + base64.b64encode(f"{mux.username}:{mux.password}".encode()).decode()
            if not secrets.compare_digest(headers.get("proxy-authorization", ""), expected):
                await mux.send_headers(stream, [(':status', '407'), ('proxy-authenticate', 'Basic realm="proxy"')], end=True)
                return
        method = headers.get(":method", "")
        target = headers.get(":authority", headers.get("host", ""))
        if method in ("GET", "HEAD"):
            host, port = split_host_port(target, 80)
            path = headers.get(":path", "/").split("?", 1)[0]
            body = PROBES.get((host.lower(), path))
            if body is None:
                await mux.send_headers(stream, [(":status", "404")], end=True)
                return
            await mux.send_headers(stream, [(":status", "200"), ("content-type", "text/plain; charset=utf-8"), ("content-length", str(len(body))), ("cache-control", "no-cache")])
            await mux.send_data(stream, b"" if method == "HEAD" else body, end=True)
            return
        if method != "CONNECT" or not target:
            await mux.send_headers(stream, [(":status", "400")], end=True)
            return
        host, port = split_host_port(target, 443)
        if not host or not 1 <= port <= 65535:
            raise ValueError("invalid H2Mux target")
        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=20)
        except (OSError, TimeoutError):
            await mux.send_headers(stream, [(":status", "502")], end=True)
            return
        stream.remote_writer = remote_writer
        await mux.send_headers(stream, [(":status", "200")])

        async def upstream():
            while True:
                data = await stream.reader.read(16384)
                if not data:
                    if remote_writer.can_write_eof():
                        remote_writer.write_eof()
                        await remote_writer.drain()
                    break
                remote_writer.write(data)
                await remote_writer.drain()
                stream.receive_window += len(data)
                await mux.send_frame(8, 0, stream.stream_id, struct.pack("!I", len(data)))

        async def downstream():
            while True:
                data = await remote_reader.read(16384)
                if not data:
                    await mux.send_data(stream, b"", end=True)
                    break
                await mux.send_data(stream, data)

        tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
        await asyncio.gather(*tasks)
    except (ConnectionError, OSError, ValueError):
        if not mux.closed:
            try:
                await mux.reset(stream.stream_id, 2)
            except (ConnectionError, OSError):
                pass
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if mux.streams.get(stream.stream_id) is stream:
            mux.streams.pop(stream.stream_id, None)
        close_writer(remote_writer)
        if remote_writer is not None:
            try:
                await remote_writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def h2mux(reader, writer, username=None, password=None, authenticated=False, first=b""):
    await H2Mux(reader, writer, username, password, authenticated, first).run()


def probe_response(host, path):
    clean_host = host.strip().lower().split(":")[0].strip("[]")
    clean_path = path.split("?")[0] or "/"
    if clean_path.endswith("/generate_204") or clean_path.endswith("/gen_204"):
        return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    body = PROBES.get((clean_host, clean_path))
    if body is None and clean_host == "connectivity-check.ubuntu.com":
        return b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    if body is None:
        return None
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
        + body
    )


def encode_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode("idna")
        return b"\x03" + bytes([len(raw)]) + raw + struct.pack("!H", port)
    if ip.version == 4:
        return b"\x01" + ip.packed + struct.pack("!H", port)
    return b"\x04" + ip.packed + struct.pack("!H", port)


async def read_address(reader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 3:
        size = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(size)).decode("idna")
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ValueError("bad atyp")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return host, port


def parse_udp_address(data, offset):
    atyp = data[offset]
    offset += 1
    if atyp == 1:
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 3:
        size = data[offset]
        offset += 1
        host = data[offset:offset + size].decode("idna")
        offset += size
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError("bad atyp")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return host, port, offset + 2


def close_writer(writer):
    try:
        writer.close()
    except Exception:
        pass


async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError, asyncio.CancelledError):
        pass
    finally:
        close_writer(writer)


async def pipe(client_reader, client_writer, remote_reader, remote_writer):
    first = asyncio.create_task(relay(client_reader, remote_writer))
    second = asyncio.create_task(relay(remote_reader, client_writer))
    done, pending = await asyncio.wait({first, second}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    close_writer(client_writer)
    close_writer(remote_writer)


class UdpPeer(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner
        self.transport = None
        self.client_addr = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.owner.transport is None or self.client_addr is None:
            return
        packet = b"\x00\x00\x00" + encode_address(addr[0], addr[1]) + data
        self.owner.transport.sendto(packet, self.client_addr)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.transport = None


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, expected_ip):
        self.expected_ip = expected_ip
        self.transport = None
        self.peers = {}
        self.lock = asyncio.Lock()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.expected_ip and addr[0] != self.expected_ip:
            local = {"127.0.0.1", "::1"}
            if addr[0] not in local or self.expected_ip not in local:
                return
        if len(data) < 4 or data[0:2] != b"\x00\x00" or data[2] != 0:
            return
        asyncio.ensure_future(self.forward(data, addr))

    async def forward(self, data, client_addr):
        loop = asyncio.get_running_loop()
        try:
            host, port, offset = parse_udp_address(data, 3)
            payload = data[offset:]
            infos = await loop.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM)
            if not infos:
                return
            infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
            family = infos[0][0]
            sockaddr = infos[0][4]
            key = (sockaddr[0], sockaddr[1])
            async with self.lock:
                peer = self.peers.get(key)
                if peer is None or peer[0].is_closing():
                    transport, protocol = await loop.create_datagram_endpoint(
                        lambda: UdpPeer(self), family=family, remote_addr=sockaddr
                    )
                    peer = (transport, protocol)
                    self.peers[key] = peer
            peer[1].client_addr = client_addr
            peer[0].sendto(payload)
        except Exception:
            pass

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.transport = None

    def close(self):
        for transport, protocol in list(self.peers.values()):
            try:
                transport.close()
            except Exception:
                pass
        self.peers.clear()
        if self.transport is not None:
            try:
                self.transport.close()
            except Exception:
                pass
            self.transport = None


async def socks_reply(writer, rep, host="0.0.0.0", port=0):
    writer.write(b"\x05" + bytes([rep, 0]) + encode_address(host, port))
    await writer.drain()


def socks_error_code(exc):
    if isinstance(exc, socket.gaierror):
        return 4
    if isinstance(exc, ConnectionRefusedError):
        return 5
    if isinstance(exc, TimeoutError):
        return 4
    return 1


async def handle_udp_associate(reader, writer):
    loop = asyncio.get_running_loop()
    peer = writer.get_extra_info("peername")
    sockname = writer.get_extra_info("sockname")
    relay_protocol = UdpRelay(peer[0] if peer else None)
    transport, protocol = await loop.create_datagram_endpoint(lambda: relay_protocol, local_addr=("0.0.0.0", 0))
    bound = transport.get_extra_info("sockname")
    bind_host = sockname[0] if sockname and sockname[0] not in ("0.0.0.0", "::") else bound[0]
    try:
        await socks_reply(writer, 0, bind_host, bound[1])
        while await reader.read(4096):
            pass
    finally:
        relay_protocol.close()
        close_writer(writer)


async def handle_socks5(reader, writer, username, password):
    try:
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        wanted = 2 if username is not None else 0
        if wanted not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(bytes([5, wanted]))
        await writer.drain()
        if wanted == 2:
            auth_ver = (await reader.readexactly(1))[0]
            ulen = (await reader.readexactly(1))[0]
            user = (await reader.readexactly(ulen)).decode("utf-8", "ignore")
            plen = (await reader.readexactly(1))[0]
            passwd = (await reader.readexactly(plen)).decode("utf-8", "ignore")
            if auth_ver != 1 or user != username or passwd != password:
                writer.write(b"\x01\x01")
                await writer.drain()
                return
            writer.write(b"\x01\x00")
            await writer.drain()
        header = await reader.readexactly(3)
        if header[0] != 5:
            return
        cmd = header[1]
        host, port = await read_address(reader)
        if cmd == 3:
            await handle_udp_associate(reader, writer)
            return
        if cmd != 1:
            await socks_reply(writer, 7)
            return
        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=20)
        except Exception as exc:
            await socks_reply(writer, socks_error_code(exc))
            return
        bound = remote_writer.get_extra_info("sockname")
        if bound:
            await socks_reply(writer, 0, bound[0], bound[1])
        else:
            await socks_reply(writer, 0)
        await pipe(reader, writer, remote_reader, remote_writer)
    except (asyncio.IncompleteReadError, ConnectionError, OSError, ValueError):
        pass
    finally:
        close_writer(writer)


async def read_chunked(reader):
    body = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            break
        size = int(line.split(b";")[0].strip() or b"0", 16)
        if size == 0:
            while True:
                trailer = await reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        body.extend(await reader.readexactly(size))
        await reader.readexactly(2)
    return bytes(body)


def http_error(writer, code, text, extra=b""):
    body = text.encode()
    writer.write(
        f"HTTP/1.1 {code} {text}\r\n".encode()
        + b"Content-Type: text/plain\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\nConnection: close\r\n"
        + extra
        + b"\r\n"
        + body
    )


def split_host_port(value, default_port):
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        host = value[1:end]
        rest = value[end + 1:]
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:] else default_port
    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        return host, int(raw_port) if raw_port else default_port
    return value, default_port


async def handle_http(reader, writer, first, username, password):
    try:
        raw = first + await reader.readuntil(b"\r\n\r\n")
        text = raw.decode("iso-8859-1")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 2:
            http_error(writer, 400, "Bad Request")
            await writer.drain()
            return
        method = parts[0].upper()
        target = parts[1]
        headers = []
        lookup = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
            lookup[name.strip().lower()] = value.strip()
        if username is not None:
            expected = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
            if lookup.get("proxy-authorization") != expected:
                http_error(writer, 407, "Proxy Authentication Required", b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n")
                await writer.drain()
                return
        if method == "CONNECT":
            host, port = split_host_port(target, 443)
            try:
                remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=20)
            except Exception:
                http_error(writer, 502, "Bad Gateway")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await pipe(reader, writer, remote_reader, remote_writer)
            return
        if "://" in target:
            parsed = urlsplit(target)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            host, port = split_host_port(lookup.get("host", ""), 80)
            path = target or "/"
        if not host:
            http_error(writer, 400, "Bad Request")
            await writer.drain()
            return
        if lookup.get("upgrade", "").lower() == "h2mux":
            tokens = {value.strip().lower() for value in lookup.get("connection", "").split(",")}
            key = (host.lower(), path.split("?", 1)[0])
            if method != "GET" or "upgrade" not in tokens or key not in PROBES or lookup.get("content-length", "0") != "0" or "transfer-encoding" in lookup:
                http_error(writer, 400, "Bad Request")
                await writer.drain()
                return
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2mux\r\nCache-Control: no-cache\r\n\r\n")
            await writer.drain()
            await h2mux(reader, writer, username, password, authenticated=True)
            return
        if method in ("GET", "HEAD"):
            probe = probe_response(host, path)
            if probe is not None:
                writer.write(probe)
                await writer.drain()
                return
        if "chunked" in lookup.get("transfer-encoding", "").lower():
            body = await read_chunked(reader)
        elif lookup.get("content-length"):
            body = await reader.readexactly(int(lookup["content-length"]))
        else:
            body = b""
        skipped = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length"}
        out = [f"{method} {path} HTTP/1.1\r\n".encode()]
        has_host = False
        for name, value in headers:
            if name.lower() in skipped:
                continue
            if name.lower() == "host":
                has_host = True
            out.append(f"{name}: {value}\r\n".encode("iso-8859-1"))
        if not has_host:
            out.append(f"Host: {host}:{port}\r\n".encode() if port != 80 else f"Host: {host}\r\n".encode())
        if body or method in ("POST", "PUT", "PATCH"):
            out.append(f"Content-Length: {len(body)}\r\n".encode())
        out.append(b"Connection: close\r\n\r\n")
        out.append(body)
        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=20)
        except Exception:
            http_error(writer, 502, "Bad Gateway")
            await writer.drain()
            return
        remote_writer.write(b"".join(out))
        await remote_writer.drain()
        await relay(remote_reader, writer)
        close_writer(remote_writer)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError, ValueError):
        pass
    finally:
        close_writer(writer)


async def handle_client(reader, writer, username, password):
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout=30)
    except Exception:
        close_writer(writer)
        return
    if first == b"\x05":
        await handle_socks5(reader, writer, username, password)
    elif first == b"\x00":
        await h2mux(reader, writer, username, password, first=first)
    elif first.isalpha():
        await handle_http(reader, writer, first, username, password)
    else:
        close_writer(writer)


async def run(args):
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, args.username, args.password),
        args.host,
        args.port,
    )
    print(f"SOCKS5/HTTP proxy listening on {args.host}:{args.port}", flush=True)
    async with server:
        await server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    if (args.username is None) != (args.password is None):
        parser.error("--username and --password must be used together")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
