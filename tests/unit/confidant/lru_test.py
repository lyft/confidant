import unittest

from confidant.utils import lru


class LruTest(unittest.TestCase):
    def test_lru(self):
        cache = lru.LRUCache(1)
        cache['test'] = 'data we set'
        self.assertEquals(cache['test'], 'data we set')
        cache['test2'] = 'data we set'
        self.assertEquals(cache['test2'], 'data we set')
        self.assertTrue('test' not in cache)
