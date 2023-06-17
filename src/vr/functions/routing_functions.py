


def check_entity_permissions(is_admin):
    if is_admin:
        permitted = True
    else:
        permitted = False
    return permitted
