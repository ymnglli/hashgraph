import unittest
from swirlds import *

class TestHashgraph(unittest.TestCase):
    def setUp(self):
        signing_keys = [SigningKey.generate() for n in range(N)]
        self.public_keys = [sk.verify_key for sk in signing_keys]
        kp = [((signing_keys[i], self.public_keys[i])) for i in range(N)]
        nodes = [Node(kp[i]) for i in range(N)]
        remote_sync = {self.public_keys[i] : nodes[i].pull for i in range(N)}
        for n in nodes:
            n.remote_sync = remote_sync
            n.rounds[hash] = 1
            n.witnesses[1][n.pk] = hash
        self.Alice = nodes[0]
        self.Bob = nodes[1]
        self.Carol = nodes[2]
        self.Dave = nodes[3]

    def test_create_event(self):
        h_a0, a0 = self.Alice.create_event([1, 2, 4, 8], ())
        self.assertEqual(HASHER(dumps(a0), encoder=encoding.HexEncoder), h_a0)

        self.Alice.add_event(a0, h_a0)
        self.assertEqual(self.Alice.hg[h_a0], a0)
    
    def test_sync_one(self):
        h_a0, a0 = self.Alice.create_event([], ())
        h_b0, b0 = self.Bob.create_event([], ())
        self.Alice.add_event(a0, h_a0)
        self.Bob.add_event(b0, h_b0)

        self.assertEqual(len(self.Bob.hg), 1)
        self.assertEqual(self.Bob.hg[h_b0], b0)

        to_add = list(self.Alice.hg.keys() - self.Bob.hg.keys())
        sorted = topological_sort(to_add, self.Alice.hg)

        for e in sorted:
            self.Bob.add_event(self.Alice.hg[e], e)
        
        self.assertEqual(len(self.Bob.hg), 2)
        self.assertEqual(self.Bob.hg[h_b0], b0)
        self.assertEqual(self.Bob.hg[h_a0], a0)

    def test_sync_multiple(self):
        h_a0, a0 = self.Alice.create_event([], ())
        h_b0, b0 = self.Bob.create_event([], ())
        h_c0, c0 = self.Carol.create_event([], ())
        h_d0, d0 = self.Dave.create_event([], ())
        self.Alice.add_event(a0, h_a0)
        self.Bob.add_event(b0, h_b0)
        self.Carol.add_event(c0, h_c0)
        self.Dave.add_event(d0, h_d0)
        
        h_d1, d1, d1_evs, dave = self.Bob.push(self.Dave.pk)
        to_add = list(self.Dave.hg.keys() - self.Alice.hg.keys())
        sorted = topological_sort(to_add, self.Dave.hg)
        self.assertTrue(sorted.index(h_d1) > sorted.index(h_d0))
        self.assertTrue(sorted.index(h_d1) > sorted.index(h_b0))

        for e in sorted:
            self.Alice.add_event(self.Dave.hg[e], e)
        
        self.assertEqual(len(self.Alice.hg), 4)
        self.assertEqual(self.Alice.hg[h_d0], d0)
        self.assertEqual(self.Alice.hg[h_b0], b0)
        self.assertEqual(self.Alice.hg[h_d1], d1)

    def test_sync_complex(self):
        h_a0, a0 = self.Alice.create_event([], ())
        h_b0, b0 = self.Bob.create_event([], ())
        h_c0, c0 = self.Carol.create_event([], ())
        h_d0, d0 = self.Dave.create_event([], ())
        self.Alice.add_event(a0, h_a0)
        self.Bob.add_event(b0, h_b0)
        self.Carol.add_event(c0, h_c0)
        self.Dave.add_event(d0, h_d0)
        
        h_d1, d1, d1_evs, dave = self.Bob.push(self.Dave.pk)
        h_b1, b1, b1_evs, bob = self.Dave.push(self.Bob.pk)
        h_a1, a1, a1_evs, alice = self.Bob.push(self.Alice.pk)
        # Alice gossips to Dave
        to_add = list(self.Alice.hg.keys() - self.Dave.hg.keys())
        sorted = topological_sort(to_add, self.Alice.hg)

        for e in sorted:
            self.Dave.add_event(self.Alice.hg[e], e)
        
        self.assertEqual(len(self.Dave.hg), 6)
        self.assertEqual(self.Dave.hg[h_a0], a0)
        self.assertEqual(self.Dave.hg[h_b1], b1)
        self.assertEqual(self.Dave.hg[h_a1], a1)
        self.assertEqual(self.Dave.head, h_d1)

    def test_divide_rounds(self):
        return

if __name__ == '__main__':
    unittest.main()