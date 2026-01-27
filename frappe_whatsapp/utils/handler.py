SCREEN_DEFINITIONS = {
    "APPOINTMENT": {
        "screen": "APPOINTMENT",
        "data": {
            "department": [],
            "location": [],
            "date": [],
            "time": [],
            "is_location_enabled": False,
            "is_date_enabled": False,
            "is_time_enabled": False,
        }
    },
    "DETAILS": {
        "screen": "DETAILS",
        "data": {}
    },
    "SUMMARY": {
        "screen": "SUMMARY",
        "data": {}
    },
    "TERMS": {
        "screen": "TERMS",
        "data": {}
    },
    "SUCCESS": {
        "screen": "SUCCESS",
        "data": {
            "extension_message_response": {
                "params": {
                    "flow_token": "REPLACE_FLOW_TOKEN",
                    "some_param_name": "PASS_CUSTOM_VALUE",
                },
            },
        },
    }
}


def load_departments():
    return [
        {"id": "shopping", "title": "Shopping & Groceries TS"},
        {"id": "clothing", "title": "Clothing & Apparel"},
        {"id": "home", "title": "Home Goods & Decor"},
        {"id": "electronics", "title": "Electronics & Appliances"},
        {"id": "beauty", "title": "Beauty & Personal Care"},
    ]


def load_locations(department):
    return [
        {"id": "1", "title": "King’s Cross, London"},
        {"id": "2", "title": "Oxford Street, London"},
    ]


def load_dates():
    return [
        {"id": "2024-01-01", "title": "Mon Jan 01 2024"},
        {"id": "2024-01-02", "title": "Tue Jan 02 2024"},
    ]


def load_times():
    return [
        {"id": "10:30", "title": "10:30"},
        {"id": "11:00", "title": "11:00", "enabled": False},
        {"id": "11:30", "title": "11:30"},
    ]


def screens(action, payload=None):
    payload = payload or {}

    # INIT → load departments only
    if action == "INIT":
        response = SCREEN_DEFINITIONS["APPOINTMENT"].copy()
        response["data"] = {
            **response["data"],
            "department": load_departments(),
            "is_location_enabled": False,
            "is_date_enabled": False,
            "is_time_enabled": False,
        }
        return response

    if action == "data_exchange":
        action = payload.get('data').get('trigger')
    # Department selected
    if action == "department_selected":
        response = SCREEN_DEFINITIONS["APPOINTMENT"].copy()
        response["data"] = {
            **response["data"],
            "department": load_departments(),
            "location": load_locations(payload.get("department")),
            "is_location_enabled": True,
        }
        return response

    # Location selected
    if action == "location_selected":
        response = SCREEN_DEFINITIONS["APPOINTMENT"].copy()
        response["data"] = {
            **response["data"],
            "department": load_departments(),
            "location": load_locations(payload.get("department")),
            "date": load_dates(),
            "is_date_enabled": True,
        }
        return response

    # Date selected
    if action == "date_selected":
        response = SCREEN_DEFINITIONS["APPOINTMENT"].copy()
        response["data"] = {
            **response["data"],
            "department": load_departments(),
            "location": load_locations(payload.get("department")),
            "date": load_dates(),
            "time": load_times(),
            "is_time_enabled": True,
        }
        return response

    if payload.get('screen') == "DETAILS":
        return {
            **SCREEN_DEFINITIONS["SUCCESS"],
            "data": {
                "extension_message_response": {
                    "params": {
                        "flow_token": payload.get('flow_token')
                    }
                }
            }
        }

    return {}
