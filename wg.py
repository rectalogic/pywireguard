import base64
import hashlib
import heapq
import logging
import os
import selectors
import socket
import struct
import time
from collections import namedtuple
from typing import Callable

from cryptography.exceptions import InvalidTag, InvalidSignature, InvalidKey
from cryptography.hazmat.backends.openssl import aead, backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC

logger = logging.getLogger('wg')


class ChaCha20Poly1305Unsafe:
    """ChaCha20Poly1305 mod for single thread usage, not safe to work in multi-thread environment."""
    def __init__(self, key: bytes):
        self.cipher = ChaCha20Poly1305(key)
        self.ctx = aead._aead_create_ctx(backend, self.cipher, key)
        if aead._is_evp_aead_supported_cipher(backend, self.cipher):
            self._encrypt = aead._evp_aead_encrypt
            self._decrypt = aead._evp_aead_decrypt
        else:
            self._encrypt = aead._evp_cipher_encrypt
            self._decrypt = aead._evp_cipher_decrypt

    def encrypt(self, nonce: bytes, data: bytes, auth: bytes) -> bytes:
        return self._encrypt(backend, self.cipher, nonce, data, [auth], 16, self.ctx)

    def decrypt(self, nonce: bytes, data: bytes, auth: bytes) -> bytes:
        return self._decrypt(backend, self.cipher, nonce, data, [auth], 16, self.ctx)


def dh(private_key: bytes, public_key: bytes) -> bytes:
    private = X25519PrivateKey.from_private_bytes(private_key)
    public = X25519PublicKey.from_public_bytes(public_key)
    return private.exchange(public)


def dh_public(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


def dh_generate() -> tuple[bytes, bytes]:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    return private.private_bytes_raw(), public.public_bytes_raw()


def hmac(key: bytes, input_: bytes) -> bytes:
    h = HMAC(key, hashes.BLAKE2s(32))
    h.update(input_)
    return h.finalize()


def mac(key: bytes, input_: bytes) -> bytes:
    h = hashlib.blake2s(key=key, digest_size=16)
    h.update(input_)
    return h.digest()


def hash(input_: bytes) -> bytes:
    h = hashes.Hash(hashes.BLAKE2s(32))
    h.update(input_)
    return h.finalize()


def kdf1(key: bytes, input_: bytes) -> bytes:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    return t1


def kdf2(key: bytes, input_: bytes) -> tuple[bytes, bytes]:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    t2 = hmac(t0, t1 + b'\x02')
    return t1, t2


def kdf3(key: bytes, input_: bytes) -> tuple[bytes, bytes, bytes]:
    t0 = hmac(key, input_)
    t1 = hmac(t0, b'\x01')
    t2 = hmac(t0, t1 + b'\x02')
    t3 = hmac(t0, t2 + b'\x03')
    return t1, t2, t3


CONSTRUCTION = 'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'.encode()
IDENTIFIER = 'WireGuard v1 zx2c4 Jason@zx2c4.com'.encode()
LABEL_MAC1 = 'mac1----'.encode()
LABEL_COOKIE = 'cookie--'.encode()
REKEY_AFTER_MESSAGES = 2**60
REJECT_AFTER_MESSAGES = 2**64 - 2**13 - 1
REKEY_AFTER_TIME = 120
REJECT_AFTER_TIME = 180
REKEY_ATTEMPT_TIME = 90
REKEY_TIMEOUT = 5
KEEPALIVE_TIMEOUT = 10
MIN_HANDSHAKE_INTERVAL = 0.05   # 50ms
EMPTY_NONCE = b'\x00' * 12


def tai64n(now: float) -> bytes:
    seconds = int(now)
    nanoseconds = int((now - seconds) * 1000000000)
    seconds = seconds + (2 ** 62) + 10  # last 10 are leap seconds
    return seconds.to_bytes(8, 'big') + nanoseconds.to_bytes(4, 'big')


class TimerTask:
    def __init__(self, delay: float, interval: float, callback, timer: 'Timer'):
        self.delay = delay
        self.interval = interval
        self.callback = callback
        self.timer = timer
        self.next_tick = time.time() + delay
        self.enabled = True

    def __lt__(self, other):
        """override < operator to make TimerTask comparable against next_tick timestamp."""
        return self.next_tick < other.next_tick

    def _trigger(self) -> None:
        if not self.enabled:
            return
        self.callback()
        if self.interval > 0:
            self.next_tick = time.time() + self.interval
        else:
            self.enabled = False

    def reset(self) -> None:
        """reset the next_tick of this timer task with delay and interval unchanged."""
        self.update(self.delay, self.interval)

    def update(self, delay: float, interval: float) -> None:
        """update the delay and interval of this timer task."""
        self.delay = delay
        self.interval = interval
        self.next_tick = time.time() + delay
        heapq.heapify(self.timer.tasks)

    def cancel(self) -> None:
        """cancel this timer task."""
        self.enabled = False


class Timer:
    def __init__(self):
        self.tasks = []

    def next_tick(self) -> float | None:
        """time to trigger the next nearest timer task, or None if there are no any tasks."""
        if not self.tasks:
            return None
        return self.tasks[0].next_tick

    def tick(self) -> None:
        """trigger the next tick, or do nothing there is no expired task."""
        if not self.tasks:
            return
        task = heapq.heappop(self.tasks)
        if not task.enabled:
            return
        if task.next_tick > time.time():
            heapq.heappush(self.tasks, task)
        else:
            task._trigger()
            if task.enabled:
                heapq.heappush(self.tasks, task)

    def schedule(self, initial_delay: float, interval: float, callback) -> TimerTask:
        """schedule a timer task."""
        assert initial_delay > 0
        task = TimerTask(initial_delay, interval, callback, self)
        heapq.heappush(self.tasks, task)
        return task


timer = Timer()


# utility to serialize/deserialize wireguard messages(handshake init/handshake response/data)
# xx_format are for struct.pack/unpack
# HandshakeInit/HandshakeResponse/DataMessage are namedtuples for ease of message manipulating
handshake_init_prefix_format = '<I4s32s48s28s'
handshake_init_message_format = handshake_init_prefix_format + '16s16s'
HandshakeInit = namedtuple('HandShakeInit', 'type sender_index unencrypted_ephemeral encrypted_static encrypted_timestamp mac1 mac2')   # noqa
handshake_response_prefix_format = '<I4s4s32s16s'
handshake_response_message_format = handshake_response_prefix_format + '16s16s'
HandshakeResponse = namedtuple('HandShakeResponse', 'type sender_index receiver_index unencrypted_ephemeral encrypted_nothing mac1 mac2')   # noqa
data_message_header_format = '<I4s8s'
DataMessage = namedtuple('DataMessageHeader', 'type receiver_index counter encrypted')


class WgTransportKeyPair:
    key_pair_count = 0

    def __init__(self, local_id: bytes, peer_id: bytes, send_key: bytes,
                 recv_key: bytes, establish_time: float, is_initiator: bool):
        WgTransportKeyPair.key_pair_count += 1
        self.number = WgTransportKeyPair.key_pair_count
        self.local_id = local_id
        self.peer_id = peer_id
        self.send_cipher = ChaCha20Poly1305Unsafe(send_key)
        self.recv_cipher = ChaCha20Poly1305Unsafe(recv_key)
        self.establish_time = establish_time
        self.is_initiator = is_initiator
        self.send_count = 0
        self.max_recv_count = 0
        self.recv_window = 0  # 32-bitmap as a rolling window for received packets

    def __str__(self):
        return f'keypair {self.number}'

    def encrypt_data(self, data: bytes | memoryview) -> DataMessage:
        count_bytes = self.send_count.to_bytes(8, 'little')
        nonce = (self.send_count << 32).to_bytes(12, 'little')
        encrypted = self.send_cipher.encrypt(nonce, data, b'')
        message = DataMessage(4, self.peer_id, count_bytes, encrypted)
        self.send_count += 1
        return message

    def decrypt_data(self, message: DataMessage) -> bytes | None:
        count = int.from_bytes(message.counter, 'little')
        # check if this packet is too old or has been received before, if so, discard it
        # this rolling window algorithm is borrowed from  page 57 of https://www.rfc-editor.org/rfc/rfc2401.txt
        diff = count - self.max_recv_count
        if diff >= 32:
            self.max_recv_count = count
            self.recv_window = 1
        elif diff > 0:
            self.max_recv_count = count
            # python int is unbounded, we have to keep it 32-bit wide
            self.recv_window = (self.recv_window << diff) & 0xffffffff
            self.recv_window |= 1   # set the bit for current count
        else:
            offset = -diff
            if diff >= 32:
                # this packet is too old, discard it
                return None
            mask = 1 << offset
            if self.recv_window & mask != 0:
                # this packet has been received before
                return None
            # mark this packet as received
            self.recv_window |= mask
        try:
            nonce = (count << 32).to_bytes(12, 'little')
            return self.recv_cipher.decrypt(nonce, message.encrypted, b'')
        except (InvalidKey, InvalidTag, InvalidSignature):
            return None


class WgHandshake:
    def __init__(self, req: HandshakeInit, on_response: Callable[[HandshakeResponse], WgTransportKeyPair]):
        self.start_time = time.time()
        self.expire_time = self.start_time + REKEY_ATTEMPT_TIME
        self.resend_time = [self.start_time + 5, self.start_time + 15, self.start_time + 35]
        self.req = req
        self.on_response = on_response


class WgPeer:
    def __init__(self, endpoint: tuple[str, int], public: bytes, node: 'WgNode', psk: bytes):
        self.logger = logging.getLogger(f'wg.{endpoint}')
        self.endpoint = endpoint
        self.public = public
        self.node = node
        self.psk = psk
        self.prev_session: WgTransportKeyPair | None = None
        self.cur_session: WgTransportKeyPair | None = None
        self.handshake: WgHandshake | None = None
        self.last_received_handshake_init_tai64n = b'\x00' * 12
        self.send_queue = []
        self.expire_all_sessions_timer = None
        self.keep_alive_timer = None
        self.last_addr = None
        self.last_received_time = None

    def send_data(self, data: bytes | memoryview):
        new_session_reason = ''
        cur = self.cur_session
        if not cur:
            new_session_reason = 'NO_SESSION'
        elif cur.send_count >= REJECT_AFTER_MESSAGES:
            new_session_reason = 'REJECT_AFTER_MESSAGES'
        elif cur.establish_time + REKEY_AFTER_TIME < time.time():
            new_session_reason = 'REKEY_AFTER_TIME'

        if new_session_reason:
            if len(self.send_queue) >= 32:
                self.send_queue.pop(0)
            self.send_queue.append(bytes(data))
            self._handshake(new_session_reason)
        else:
            data_msg = self.cur_session.encrypt_data(data)
            self.node.write_udp(data_msg, self.last_addr)
            self.keep_alive_timer.reset()

    def _handshake(self, reason: str):
        if self.handshake:
            now = time.time()
            if now > self.handshake.expire_time:
                logger.warning('last handshake failed within %s seconds', REKEY_ATTEMPT_TIME)
                self.handshake = None
            else:
                if self.handshake.resend_time and now > self.handshake.resend_time[0]:
                    self.logger.info('retransmitting handshake for timeout')
                    self.node.write_udp(self.handshake.req, self.last_addr or self.endpoint)
                    self.handshake.last_send_time = now
                    self.handshake.resend_time.pop(0)
                return
        self.logger.info('initiating handshake for: %s', reason)
        handshake = self.node.init_handshake(self)
        addr = self.last_addr or self.endpoint
        self.node.write_udp(handshake.req, addr)
        self.handshake = handshake

    def decrypt_data(self, message: DataMessage) -> bytes | None:
        if not self.cur_session:
            return None
        if message.receiver_index == self.cur_session.local_id:
            session = self.cur_session
        elif self.prev_session and message.receiver_index == self.prev_session.local_id:
            session = self.prev_session
        else:
            return None
        return session.decrypt_data(message)

    def _expire_all_sessions(self):
        self.prev_session, self.cur_session, self.handshake = None, None, None
        self.logger.info(f'all sessions expired')
        self.expire_all_sessions_timer = None

    def _send_keepalive(self):
        self.logger.info('sending keep alive.')
        self.send_data(b'')

    def set_cur_session(self, session: WgTransportKeyPair):
        self.prev_session, self.cur_session, self.handshake = self.cur_session, session, None
        self.logger.info(f'session rotated (prev, cur) = {self.prev_session}, {self.cur_session}')
        if self.expire_all_sessions_timer:
            self.expire_all_sessions_timer.reset()
        else:
            self.expire_all_sessions_timer = timer.schedule(REJECT_AFTER_TIME * 3, 0, self._expire_all_sessions)
        for data in self.send_queue:
            self.node.write_udp(session.encrypt_data(data), self.last_addr)
        self.send_queue.clear()
        if self.keep_alive_timer:
            self.keep_alive_timer.reset()
        else:
            self.keep_alive_timer = timer.schedule(KEEPALIVE_TIMEOUT, KEEPALIVE_TIMEOUT, self._send_keepalive)


class WgNode:
    def __init__(self, listen_ip: str = '0.0.0.0', listen_port: int = 9000, private_password: str = 'test'):
        self.listen_ip, self.listen_port = listen_ip, listen_port
        self.sock: socket.socket = None
        self.sock_write_queue: list[tuple[bytes, tuple[str, int]]] = []
        self.private = hashlib.blake2s(private_password.encode()).digest()
        self.public = dh_public(self.private)
        self.mac1_auth = hash(LABEL_MAC1 + self.public)
        self.peers: list[WgPeer] = []
        logger.info('Listening on %s:%d PublicKey: %s', listen_ip, listen_port, base64.b64encode(self.public).decode())

    def _setup_udp_sock(self):
        self.sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.listen_ip, self.listen_port))

    def _setup_selector(self):
        self.sock.setblocking(False)
        selector = selectors.DefaultSelector()
        selector.register(self.sock, selectors.EVENT_READ)
        return selector

    def serve(self):
        self._setup_udp_sock()
        selector = self._setup_selector()
        while True:
            next_tick = timer.next_tick()
            if next_tick is None:
                timeout = None
            else:
                timeout = next_tick - time.time()
                if timeout <= 0:
                    timer.tick()
                    continue
            events = selector.select(timeout)
            if next_tick and next_tick < time.time():
                timer.tick()
            udp_ready = False
            for key, mask in events:
                if key.fileobj is self.sock:
                    udp_ready = True
            while udp_ready or self.sock_write_queue:
                if udp_ready:
                    try:
                        data, addr = self.sock.recvfrom(65535)
                    except BlockingIOError:
                        udp_ready = False
                    else:
                        self.on_udp_read(data, addr)
                if self.sock_write_queue:
                    data, addr = self.sock_write_queue[0]
                    try:
                        self.sock.sendto(data, addr)
                        self.sock_write_queue.pop(0)
                    except BlockingIOError:
                        pass

    def on_udp_read(self, data: bytes, addr: tuple[str, int]):
        """called when data read from udp(aka. wireguard handshake messages or encrypted ip packets)"""
        if len(data) < 4:
            return
        msg_type = int.from_bytes(data[0:4], 'little', signed=False)
        if msg_type == 1:
            message = HandshakeInit._make(struct.unpack(handshake_init_message_format, data))
            if message.mac1 != mac(self.mac1_auth, data[:116]):
                logger.warning('invalid mac1 of handshake init from %s', addr)
                return
            try:
                self.respond_to_handshake(addr, message)
            except (InvalidKey, InvalidTag, InvalidSignature):
                logger.warning('invalid handshake init from %s', addr)
        elif msg_type == 2:
            message = HandshakeResponse._make(struct.unpack(handshake_response_message_format, data))
            if message.mac1 != mac(self.mac1_auth, data[:60]):
                logger.warning('invalid mac1 of handshake response from %s', addr)
                return
            if peer := self.get_peer(handshake_session_id=message.receiver_index):
                try:
                    keypair = peer.handshake.on_response(message)
                except (InvalidKey, InvalidTag, InvalidSignature, AssertionError):
                    logger.warning('invalid handshake response from %s', addr)
                    return
                peer.last_addr = addr
                peer.set_cur_session(keypair)
            else:
                logger.warning('handshake response from %s have no corresponding handshake init', addr)
        elif msg_type == 4:
            message_format = data_message_header_format + f'{len(data) - 16}s'
            message = DataMessage._make(struct.unpack(message_format, data))
            if peer := self.get_peer(session_id=message.receiver_index):
                if decrypted := peer.decrypt_data(message):
                    peer.last_addr = addr
                    peer.last_received_time = time.time()

    def init_handshake(self, peer: WgPeer) -> WgHandshake:
        """called by initiator: initiate a wireguard handshake with responder's public key.

        :param peer: responder
        :return: (handshake init message to be read by responder, callback to process response from responder)
        """
        si_priv, si_pub, sr_pub = self.private, self.public, peer.public

        ck = hash(CONSTRUCTION)
        h = hash(ck + IDENTIFIER)
        h = hash(h + sr_pub)
        ei_priv, ei_pub = dh_generate()
        ck = kdf1(ck, ei_pub)
        h = hash(h + ei_pub)
        ck, k = kdf2(ck, dh(ei_priv, sr_pub))
        encrypted_static = ChaCha20Poly1305Unsafe(k).encrypt(EMPTY_NONCE, si_pub, h)
        h = hash(h + encrypted_static)
        ck, k = kdf2(ck, dh(si_priv, sr_pub))
        encrypted_timestamp = ChaCha20Poly1305Unsafe(k).encrypt(EMPTY_NONCE, tai64n(time.time()), h)
        h = hash(h + encrypted_timestamp)

        sender_index = os.urandom(4)
        mac1 = mac(hash(LABEL_MAC1 + sr_pub), struct.pack(handshake_init_prefix_format, 1, sender_index,
                                                          ei_pub, encrypted_static, encrypted_timestamp))
        mac2 = b'\x00' * 16

        def on_response(resp: HandshakeResponse) -> WgTransportKeyPair:
            """called by initiator: process handshake response from responder."""
            nonlocal ck, h
            er_pub = resp.unencrypted_ephemeral

            ck = kdf1(ck, er_pub)
            h = hash(h + er_pub)
            ck = kdf1(ck, dh(ei_priv, er_pub))
            ck = kdf1(ck, dh(si_priv, er_pub))
            ck, tao, key_nothing = kdf3(ck, peer.psk)
            h = hash(h + tao)
            nothing = ChaCha20Poly1305Unsafe(key_nothing).decrypt(EMPTY_NONCE, resp.encrypted_nothing, h)
            assert nothing == b''
            send_key, recv_key = kdf2(ck, b'')
            return WgTransportKeyPair(local_id=sender_index, peer_id=resp.sender_index,
                                      send_key=send_key, recv_key=recv_key, establish_time=time.time(),
                                      is_initiator=True)

        req = HandshakeInit(1, sender_index, ei_pub, encrypted_static, encrypted_timestamp, mac1, mac2)
        return WgHandshake(req, on_response)

    def respond_to_handshake(self, addr: tuple[str, int], msg: HandshakeInit):
        """called by responder: compose response message and generate keypair.

        :param addr: from which address is msg sent from
        :param msg: handshake init message
        """
        sr_priv, sr_pub = self.private, self.public

        ck = hash(CONSTRUCTION)
        h = hash(ck + IDENTIFIER)
        h = hash(h + sr_pub)
        er_priv, er_pub = dh_generate()
        ei_pub = msg.unencrypted_ephemeral
        ck = kdf1(ck, ei_pub)
        h = hash(h + ei_pub)
        ck, k = kdf2(ck, dh(sr_priv, ei_pub))
        si_pub = ChaCha20Poly1305Unsafe(k).decrypt(EMPTY_NONCE, msg.encrypted_static, h)
        peer = self.get_peer(peer_public=si_pub)

        if not peer:
            logger.warning('handshake init from %s - adding peer', addr)
            peer = WgPeer(addr, si_pub, node=self, psk=b'\x00' * 32)
            self.peers.append(peer)
        if peer.cur_session and time.time() - peer.cur_session.establish_time < MIN_HANDSHAKE_INTERVAL:
            logger.warning('handshake init from %s is too frequent', addr)
            return

        h = hash(h + msg.encrypted_static)
        ck, k = kdf2(ck, dh(sr_priv, si_pub))
        timestamp = ChaCha20Poly1305Unsafe(k).decrypt(EMPTY_NONCE, msg.encrypted_timestamp, h)
        if peer.last_received_handshake_init_tai64n >= timestamp:
            logger.warning('handshake init from %s is replayed', addr)
            return

        h = hash(h + msg.encrypted_timestamp)
        ck = kdf1(ck, er_pub)
        h = hash(h + er_pub)
        ck = kdf1(ck, dh(er_priv, ei_pub))
        ck = kdf1(ck, dh(er_priv, si_pub))
        ck, tao, k = kdf3(ck, peer.psk)
        h = hash(h + tao)
        encrypted_nothing = ChaCha20Poly1305Unsafe(k).encrypt(EMPTY_NONCE, b'', h)
        recv_key, send_key = kdf2(ck, b'')

        encrypted_nothing = encrypted_nothing
        sender_index = os.urandom(4)
        receiver_index = msg.sender_index
        unencrypted_ephemeral = er_pub
        mac1 = mac(hash(LABEL_MAC1 + si_pub), struct.pack(handshake_response_prefix_format, 2, sender_index,
                                                          receiver_index, unencrypted_ephemeral, encrypted_nothing))
        mac2 = b'\x00' * 16
        keypair = WgTransportKeyPair(local_id=sender_index, peer_id=receiver_index,
                                     send_key=send_key, recv_key=recv_key,
                                     establish_time=time.time(), is_initiator=False)
        response = HandshakeResponse(2, sender_index, receiver_index, unencrypted_ephemeral,
                                     encrypted_nothing, mac1, mac2)
        self.write_udp(response, addr)
        peer.last_addr = addr
        peer.last_received_handshake_init_tai64n = timestamp
        peer.set_cur_session(keypair)

    def write_udp(self, message: HandshakeInit | HandshakeResponse | DataMessage, addr: tuple[str, int]):
        if isinstance(message, HandshakeInit):
            message_format = handshake_init_message_format
        elif isinstance(message, HandshakeResponse):
            message_format = handshake_response_message_format
        else:
            message_format = data_message_header_format + f'{len(message.encrypted)}s'
        data = struct.pack(message_format, *message)
        self.sock_write_queue.append((data, addr))

    def get_peer(self, peer_public: bytes | None = None,
                 handshake_session_id: bytes | None = None, session_id: bytes | None = None) -> WgPeer | None:
        for peer in self.peers:
            if peer.public == peer_public:
                return peer
            if session_id:
                if peer.cur_session and peer.cur_session.local_id == session_id:
                    return peer
                if peer.prev_session and peer.prev_session.local_id == session_id:
                    return peer
            if handshake_session_id:
                if peer.handshake and peer.handshake.req.sender_index == handshake_session_id:
                    return peer
        return None


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    WgNode().serve()
