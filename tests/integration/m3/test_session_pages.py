import unittest

from session_pages import collect_session_pages


class SessionPagingTests(unittest.TestCase):
    def test_new_flows_after_a_full_first_page_are_not_lost(self):
        old = [{'session_id': 'old-' + str(index)} for index in range(100)]
        current = [{'session_id': 'current-' + str(index)} for index in range(4)]
        calls = []

        def fetch(query):
            calls.append(query)
            return {'items': old if query['page'] == 1 else current, 'has_more': query['page'] == 1}

        result = collect_session_pages(fetch, {'page_size': 100, 'source_ip': '192.168.10.10'}, 50000)
        self.assertEqual(len(result), 104)
        self.assertEqual(result[-4:], current)
        self.assertEqual([value['page'] for value in calls], [1, 2])
        self.assertTrue(all(value['source_ip'] == '192.168.10.10' for value in calls))

    def test_repeated_ids_during_page_changes_do_not_duplicate_a_flow(self):
        result = collect_session_pages(lambda q: {'items': [{'session_id': 'same'}], 'has_more': q['page'] == 1}, {'page_size': 2}, 10)
        self.assertEqual(result, [{'session_id': 'same'}])

    def test_nonprogressing_backend_is_bounded(self):
        with self.assertRaisesRegex(RuntimeError, 'capacity'):
            collect_session_pages(lambda q: {'items': [{'session_id': str(q['page'])}], 'has_more': True}, {'page_size': 2}, 4)
        with self.assertRaisesRegex(RuntimeError, 'empty'):
            collect_session_pages(lambda q: {'items': [], 'has_more': True}, {'page_size': 2}, 4)


if __name__ == '__main__':
    unittest.main()
