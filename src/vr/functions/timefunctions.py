import datetime
from dateutil import tz


def return_datetime_now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def return_local_time_from_utc(date_obj: datetime, local_tz: str) -> datetime:
    if local_tz:
        if isinstance(date_obj, str):
            date_obj = datetime.datetime.strptime(date_obj, "%Y-%m-%d %H:%M:%S")

        to_zone = tz.gettz(local_tz)
        from_zone = tz.gettz('UTC')
        old_tz = date_obj.replace(tzinfo=from_zone)
        local_tz_start = old_tz.astimezone(to_zone)
    else:
        local_tz_start = date_obj
    return local_tz_start


def return_utc_from_local_time(date_obj: datetime, local_tz: str) -> datetime:
    if local_tz:
        from_zone = tz.gettz(local_tz)
        to_zone = tz.gettz('UTC')
        old_tz = date_obj.replace(tzinfo=from_zone)
        utc_tz_start = old_tz.astimezone(to_zone)
    else:
        utc_tz_start = date_obj
    return utc_tz_start


def convert_row_list_to_local_time(index_list: list, local_tz: str, raw_row_list: list) -> list:
    row_list = []
    for i in raw_row_list:
        i_list = []
        for j in i:
            i_list.append(j)
        for ind in index_list:
            if i[ind]:
                i_list[ind] = return_local_time_from_utc(i_list[ind], local_tz)
            else:
                i_list[ind] = None
        row_list.append(i_list)
    return row_list


def return_all_day_times():
    all_times = [
        '12:00am',
        '12:30am',
        '1:00am',
        '1:30am',
        '2:00am',
        '2:30am',
        '3:00am',
        '3:30am',
        '4:00am',
        '4:30am',
        '5:00am',
        '5:30am',
        '6:00am',
        '6:30am',
        '7:00am',
        '7:30am',
        '8:00am',
        '8:30am',
        '9:00am',
        '9:30am',
        '10:00am',
        '10:30am',
        '11:00am',
        '11:30am',
        '12:00pm',
        '12:30pm',
        '1:00pm',
        '1:30pm',
        '2:00pm',
        '2:30pm',
        '3:00pm',
        '3:30pm',
        '4:00pm',
        '4:30pm',
        '5:00pm',
        '5:30pm',
        '6:00pm',
        '6:30pm',
        '7:00pm',
        '7:30pm',
        '8:00pm',
        '8:30pm',
        '9:00pm',
        '9:30pm',
        '10:00pm',
        '10:30pm',
        '11:00pm',
        '11:30pm'
    ]
    return all_times
