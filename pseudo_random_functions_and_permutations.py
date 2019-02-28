import os
import re
import hashlib
import random
import cPickle as pickle
import math
import array
import string
from Crypto.Cipher import AES


def f(K, keyword):
    """
    f: {0, 1}^k * {0, 1}^l -> {0, 1}^(k + log2(s))
    :param K: with the length of k
    :param keyword: with the length of l
    :return: the bits with the length of (k + log2(s))
    """
    pass
