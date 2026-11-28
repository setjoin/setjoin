"""Public route-inventory contract for the three Compliance tickets."""
import json
from pathlib import Path
import unittest

class SliceMap(unittest.TestCase):
    def test_every_f04_route_has_exactly_one_owner(self):
        inventory = Path(__file__).resolve().parents[3] / 'bins/gateway/route-inventory.json'
        routes = [r for r in json.loads(inventory.read_text())['routes'] if r['family'] == 'F04']
        counts = {'ediscovery': 0, 'retention-audit': 0, 'chat-compliance': 0}
        keys = set()
        for route in routes:
            key = route['method'], route['path']
            self.assertNotIn(key, keys)
            keys.add(key)
            path = route['path']
            owner = 'ediscovery' if path.startswith('/admin/ediscovery') else 'chat-compliance' if path.startswith('/admin/chat-') else 'retention-audit'
            self.assertEqual(route['slice'], owner, key)
            counts[owner] += 1
        self.assertEqual(counts, {'ediscovery': 12, 'retention-audit': 14, 'chat-compliance': 13})

if __name__ == '__main__':
    unittest.main()
