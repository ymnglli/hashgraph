from collections import namedtuple
from nacl import encoding, hash
from nacl.signing import SigningKey
from nacl.bindings.utils import sodium_memcmp
from nacl.exceptions import BadSignatureError
from pickle import dumps, loads
from time import time
from termcolor import colored
from utils import topological_sort
import random

N = 4
HASHER = hash.sha256

Event = namedtuple('Event', 'pk timestamp transactions parents signature')

class Node:
    def __init__(self, kp):
        self.sk, self.pk = kp
        self.hg = {}
        self.remote_sync = {}
        self.transactions = []
        self.head = None

    def create_event(self, transactions, parents):
        t = time()
        signed = self.sk.sign(dumps((self.pk, t, transactions, parents)))
        event = Event(self.pk, t, transactions, parents, signed)
        return HASHER(dumps(event), encoder=encoding.HexEncoder), event

    def validate_event(self, event, hash):
        try:
            hash_to_verify = HASHER(dumps(event), encoder=encoding.HexEncoder)
            assert sodium_memcmp(hash, hash_to_verify), "Hash is invalid."
            assert event.pk.verify(event.signature)
            if event.parents != ():
                assert len(event.parents) == 2, "Invalid number of parents."
                assert event.parents[0] in self.hg and event.parents[1] in self.hg, "Parents are not in hashgraph."
                assert self.hg[event.parents[0]].pk == event.pk, "First parent is not self-parent."
                assert self.hg[event.parents[1]].pk != event.pk, "Second parent is not other-parent."
        except (AssertionError, BadSignatureError) as msg:
            print(colored(msg, "red"))

    def add_event(self, event, hash):
        self.validate_event(event, hash)
        self.hg[hash] = event
        if event.pk == self.pk:
            self.head = hash

    def push(self):
        choices = [pk for pk in self.remote_sync.keys() if pk != self.pk]
        assert len(choices) > 0
        remote_pk = random.choice(choices)
        data = self.sk.sign(dumps((self.head, self.hg)))
        self.remote_sync[remote_pk](self.pk, data)

    def pull(self, remote_pk, data):
        verified = remote_pk.verify(data)
        remote_head, remote_hg = loads(verified)
        unknown_events = topological_sort(list(remote_hg.keys() - self.hg.keys()), remote_hg)
        for h in unknown_events:
            self.add_event(remote_hg[h], h)
        hash, event = self.create_event([], (self.head, remote_head))
        self.add_event(event, hash)

def main():
    signing_keys = [SigningKey.generate() for n in range(N)]
    public_keys = [sk.verify_key for sk in signing_keys]
    nodes = [Node((signing_keys[i], public_keys[i])) for i in range(N)]
    remote_sync = {public_keys[i] : nodes[i].pull for i in range(N)}
    for n in nodes:
        hash, event = n.create_event([], ())
        n.add_event(event, hash)
        n.remote_sync = remote_sync
    for i in range(10):
        choice = random. randint(0, 3)
        nodes[choice].push()
main()