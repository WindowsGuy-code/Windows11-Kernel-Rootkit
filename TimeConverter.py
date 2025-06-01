import re

def time_to_seconds(time_str):
    time_units = {
        'day': 86400,
        'days': 86400,
        'hour': 3600,
        'hours': 3600,
        'minute': 60,
        'minutes': 60,
        'min': 60,
        'mins': 60,
        'second': 1,
        'seconds': 1,
        'sec': 1,
        'secs': 1
    }

    pattern = r'(\d+)\s*(days?|hours?|minutes?|mins?|seconds?|secs?)'
    matches = re.findall(pattern, time_str, re.IGNORECASE)

    total_seconds = 0
    for value, unit in matches:
        unit = unit.lower()
        if unit in time_units:
            total_seconds += int(value) * time_units[unit]
    return total_seconds

if __name__ == "__main__":
    print("This is a Time converter converting any time to seconds\n")
    print("Please enter in this format: days hours minutes seconds, ofcourse if you have no days for instance just say dont write it.\n")
    print("e.g 2 days 30 minutes\n")
    user_input = input("Enter time: ")
    seconds = time_to_seconds(user_input)
    print(f"In seconds: {seconds}")