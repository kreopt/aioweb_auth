import re


def sub_phone(phone):
    if phone is None:
        return None
    r = re.sub('[^0-9]', '', phone)[-10:]
    if not len(r):
        return None
    if re.match("^((?!95[4-79]|99[08]|907|94[^0]|336)([348]\d|9[0-6789]|7[0247])\d{8}|\+?(99[^4568]\d{7,11}|994\d{9}|9955\d{8}|996[57]\d{8}|9989\d{8}|380[34569]\d{8}|375[234]\d{8}|372\d{7,8}|37[0-4]\d{8}))$", '7{}'.format(r)):
        return r
    return None


def sub_email_or_phone(raw):
    username = re.sub('[^A-Za-z0-9-_@.]', '', raw)

    if '@' not in username:
        return sub_phone(username)

    return username
