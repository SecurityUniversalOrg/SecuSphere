


def load_table(joblist_dict, direction=None, aggregate_field=False):
    page = 1
    per_page = 25
    orderby_dict = joblist_dict
    if aggregate_field:
        if direction:
            orderby = joblist_dict['sort_field'] + f' {direction}'
        else:
            orderby = joblist_dict['sort_field'] + f' asc'
    else:
        if direction:
            orderby = joblist_dict['db_name'] + '.' + joblist_dict['sort_field'] + f' {direction}'
        else:
            orderby = joblist_dict['db_name'] + '.' + joblist_dict['sort_field'] + f' asc'
    return page, per_page, orderby_dict, orderby

def update_table(request, new_dict, direction=None, aggregate_field=False):
    field_name = request.form.get('field_name')
    if direction:
        new_dir = direction
    else:
        new_dir = request.form.get('new_dir')
    cur_page = request.form.get('cur_page')
    new_page = request.form.get('new_page')
    cur_per_page = request.form.get('cur_per_page')
    new_per_page = request.form.get('new_per_page')
    cur_orderby = request.form.get('cur_orderby').split('.')[1] if '.' in request.form.get('cur_orderby') else request.form.get('cur_orderby')
    cur_field = cur_orderby.split()[0]
    cur_dir = cur_orderby.split()[1]
    new_field = False
    if field_name:
        new_field = True
        if cur_field == field_name:
            new_field = False
    new_dict, new_dir = _set_field_name(new_field, new_dir, new_dict, cur_dir, cur_field, field_name)
    page, per_page, orderby_dict, orderby = load_table(new_dict, direction=new_dir, aggregate_field=aggregate_field)
    if new_page and cur_page != new_page:
        page = int(new_page)
    if new_per_page and new_per_page != per_page:
        if new_per_page == 'All':
            per_page = 1000000
        else:
            per_page = int(new_per_page)
    elif cur_per_page != per_page:
        per_page = int(cur_per_page)
    return page, per_page, orderby_dict, orderby


def _set_field_name(new_field, new_dir, new_dict, cur_dir, cur_field, field_name):
    if new_field and new_dir == 'dynamic':
        new_dict['sort_field'] = field_name
        new_dir = 'asc'
    elif new_dir == 'dynamic':
        if cur_dir == 'asc':
            new_dir = 'desc'
        elif cur_dir == 'desc':
            new_dir = 'asc'
        if cur_field:
            new_dict['sort_field'] = cur_field
    elif new_field and new_dir:
        new_dict['sort_field'] = field_name
    return new_dict, new_dir
