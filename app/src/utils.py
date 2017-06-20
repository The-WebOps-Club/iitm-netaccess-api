#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: utils.py
# Author: Shahidh K Muhammed <shahidhkmuhammed@gmail.com>
# Date: 19.06.2017
# Last Modified: 19.06.2017

def get_user(request):
    return {
        'id': int(request.headers.get('x-hasura-user-id')),
        'role': request.headers.get('x-hasura-user-role')
    }
