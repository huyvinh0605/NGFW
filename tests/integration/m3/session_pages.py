"""Read complete bounded session results, including flows beyond page one."""


def collect_session_pages(fetch_page, query, max_sessions, record_page=None):
    size = int(query.get('page_size', 100))
    if not 1 <= size <= 200 or max_sessions < 1:
        raise ValueError('invalid session pagination bounds')
    maximum_pages = (max_sessions + size - 1) // size + 1
    sessions = {}
    for number in range(1, maximum_pages + 1):
        page = fetch_page({**query, 'page': number, 'page_size': size})
        if record_page:
            record_page(number, page)
        items = page.get('items') or []
        if not isinstance(items, list):
            raise RuntimeError('session page items is not an array')
        for item in items:
            sessions[item['session_id']] = item
        if not page.get('has_more', False):
            return list(sessions.values())
        if not items:
            raise RuntimeError('empty session page advertised more results')
    raise RuntimeError('session pagination exceeded configured runtime capacity')
