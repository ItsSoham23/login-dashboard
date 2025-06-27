# utils/fetch.py
import requests
def make_api_request(url, headers, params=None, return_raw=False):
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.text if return_raw else response.json()
    except requests.exceptions.RequestException as e:
        print(f"⚠️ API Request failed: {e}")
        return None


def fetch_paginated_data(url_base, headers, extra_params=None):
    results = []
    page = 1
    per_page = 100
    while True:
        params = {'page': page, 'per_page': per_page}
        if extra_params:
            params.update(extra_params)
        data = make_api_request(url_base, headers, params)
        if not data:
            break
        results.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return results