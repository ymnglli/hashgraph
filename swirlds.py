from collections import namedtuple, defaultdict
from nacl import encoding, hash
from nacl.signing import SigningKey
from nacl.bindings.utils import sodium_memcmp
from nacl.exceptions import BadSignatureError
from pickle import dumps, loads
from time import time
from termcolor import colored
from utils import topological_sort, bfs, dfs
import random

N = 4
C = 10
HASHER = hash.sha256

Event = namedtuple('Event', 'pk timestamp transactions parents signature')

class Node:
    def __init__(self, kp):
        self.sk, self.pk = kp
        self.hg = {}
        self.remote_sync = {}
        self.transactions = []
        self.head = None
        # round -> {pk -> event hash}
        self.witnesses = defaultdict(dict)
        # hash -> famous
        self.famous = {}
        # hash -> {hash -> bool}
        # the key event stores its vote for another event
        self.votes = defaultdict(dict)
        # hash -> round
        self.rounds = {}

    def create_event(self, transactions, parents):
        t = time()
        signed = self.sk.sign(dumps((self.pk, t, transactions, parents)))
        event = Event(self.pk, t, transactions, parents, signed)
        if parents != ():
            assert self.hg[parents[0]].pk == self.pk
            assert self.hg[parents[1]].pk != self.pk
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
        self.divide_rounds(unknown_events + [hash])
        self.decide_fame()
        self.find_order()

    def divide_rounds(self, events):
        for h in events:
            p = self.hg[h].parents
            r = 1 if p == () else max(self.rounds[p[0]], self.rounds[p[1]])
            num_strongly_seen = 0
            for w in self.witnesses[r].values():
                if num_strongly_seen > 2 * N / 3:
                    break
                if self.strongly_see(h, w):
                    num_strongly_seen += 1
            if num_strongly_seen > 2 * N / 3:
                self.rounds[h] = r + 1
            else:
                self.rounds[h] = r
            if p == () or self.rounds[h] > self.rounds[p[0]]:
                self.witnesses[self.rounds[h]][self.hg[h].pk] = h
    
    def decide_fame(self):
        def get_strongly_seeable(voter, round):
            s = set()
            for w in self.witnesses[round].values():
                if self.strongly_see(voter, w):
                    s.add(w)
            return s

        def get_majority_vote(voters, w):
            votes = [0, 0]
            for v in voters:
                if w not in self.votes[v]:
                    continue
                if self.votes[v][w] == True:
                    votes[0] += 1
                else:
                    votes[1] += 1
            if votes[0] >= votes[1]:
                return True, votes[0]
            return False, votes[1]

        max_round = max(self.witnesses)
        for r in range(1, max_round+1):
            undecided = set(self.witnesses[r].values() - self.famous.keys())
            for w in undecided:
                voters = []
                for vr in range(r+1, max_round+1):
                    voters += list(self.witnesses[vr].values() - self.famous.keys())
                for voter in voters:
                    d = self.rounds[voter] - r
                    s = get_strongly_seeable(voter, self.rounds[voter]-1)
                    v, t = get_majority_vote(s, w)
                    if d == 1:
                        self.votes[voter][w] = bfs(voter, w, self.hg)
                    else:
                        if d % C > 0:
                            if t > (2 * N / 3):
                                self.famous[w] = v
                                self.votes[voter][w] = v
                                break
                            else:
                                self.votes[voter][w] = v
                        else:
                            if t > (2 * N / 3):
                                self.votes[voter][w] = v
                            else:
                                # coin round
                                print("stub")
                                #signature = self.hg[voter].signature
                                #num_bits = signature.bit_length()
                                #self.votes[voter][w] = bool(signature[num_bits / 2])
    # stub
    def find_order(self):
        return
    
    def strongly_see(self, event, witness):
        seen = defaultdict(lambda:False)
        path = [event]
        dfs(event, witness, self.hg, path, seen, 2 * N / 3)
        if sum(1 for v in seen.values()) > 2 * N / 3:
            return True
        return False

def main():
    signing_keys = [SigningKey.generate() for n in range(N)]
    public_keys = [sk.verify_key for sk in signing_keys]
    nodes = [Node((signing_keys[i], public_keys[i])) for i in range(N)]
    remote_sync = {public_keys[i] : nodes[i].pull for i in range(N)}

    for n in nodes:
        hash, event = n.create_event([], ())
        n.add_event(event, hash)
        n.remote_sync = remote_sync
        n.rounds[hash] = 1
        n.witnesses[1][n.pk] = hash
    
    for i in range(30):
        choice = random.randint(0, 3)
        nodes[choice].push()

main()