# coding=utf-8
import os
import hashlib
import math
from Crypto.Cipher import AES
import scanner
import pickle

# todo for a test
import sse_client


def byte_alignment(length):
    """
    对于长度length不为8的整数倍的情况，将length改威8的整数倍，以实现字节对齐
    :param length:
    :return:
    """
    return int(math.ceil(length / 8)) * 8


def num2byte(num, byte_string_len):
    """
    将数字num转化成长度为byte_string_len的字节串
    :param num:
    :param byte_string_len:
    :return:
    """
    return num.to_bytes(byte_string_len, byteorder="big")


def byte2num(byte_string):
    """
    将byte字符串转化成int类型的数字num
    :param byte_string:
    :return:
    """
    return int.from_bytes(byte_string, byteorder="big")


def str2byte(string):
    """
    将str类型字符串转换成byte字符串
    :param string:
    :param byte_string_len:
    :return:
    """
    return bytes(string, encoding='UTF-8')


def extend_bytes_len(byte_str, target_length):
    """
    扩充byte串的长度到target_length
    :param byte_str:
    :param target_length: integer 目标长度
    :return: 扩展长度后的byte串
    """
    if len(byte_str) >= target_length:
        return byte_str
    return int.from_bytes(byte_str, byteorder="big").to_bytes(target_length, byteorder="big")


def proj_exists(proj_name):
    return os.path.isdir(proj_name)


class SSEServer:
    def __init__(self, proj_name):
        self.proj_name = proj_name
        self.proj_dir_path = self.proj_name + '/'

        self.k, self.l, self.s = self.load_config()

        self.T = [None] * (2 ** self.l)

        # self.D = None
        self.distinct_word_set = None
        self.D_ = None

        # EncK(D) step3. initialize a global counter ctr = 1
        self.ctr = 1

        self.A = [None] * (2 ** self.s)
        self.entry_size_of_A = -1
        self.load_encrypted_index()

        self.addrA = {}  # 组织成dict结构，用于获取每个链表第一个节点对应于A的位置
        self.k0_for_each_keyword = {}

        self.file_cnt = scanner.get_file_count()
        self.file_cnt_byte = int(math.ceil(math.log2(self.file_cnt) / 8))

    def load_config(self):
        """
        读取配置文件
        :return: k, l, s
        """
        with open(self.proj_dir_path + 'config', 'rb') as f:
            return pickle.load(f)

    def f(self, K, data):
        """
        f: {0, 1}^k * {0, 1}^l -> {0, 1}^(k + log2(s))
        :param K: with the length of k
        :param data: with the length of l
        :return: the bits with the length of (k + log2(s))
        """
        # 扩充长度
        if len(data) < int(math.ceil(self.l / 8)):
            # data = int.from_bytes(data, byteorder="big").to_bytes(int(math.ceil(self.l / 8)), byteorder="big")
            data = extend_bytes_len(data, int(math.ceil(self.l / 8)))

        hash_val = hashlib.sha256(K + data)
        f = hash_val.digest()
        # while int(math.ceil((self.k + math.log2(self.s)) / 8)) > len(f):
        while int(math.ceil((self.k + self.s) / 8)) > len(f):  # update: 参数s已经被log了，下同
            hash_val.update(K)
            f += hash_val.digest()
        tmp = int.from_bytes(f, byteorder="big")
        # tmp = tmp >> (len(f) * 8 - int(math.ceil(self.k + math.log2(self.s))))
        tmp = tmp >> (len(f) * 8 - int(math.ceil(self.k + self.s)))
        # return tmp.to_bytes(int(math.ceil((self.k + math.log2(self.s)) / 8)), byteorder="big")
        return tmp.to_bytes(int(math.ceil((self.k + self.s) / 8)), byteorder="big")

    def pi(self, K, data):
        """
        π: {0, 1}^k * {0, 1}^l -> {0, 1}^l
        :param K: with the length of k
        :param data: with the length of l
        :return: the bits with the length of l
        """
        # 扩充长度
        if len(data) < int(math.ceil(self.l / 8)):
            # data = (int.from_bytes(data, byteorder="big").to_bytes(int(math.ceil(self.l / 8)), byteorder="big"))
            data = extend_bytes_len(data, int(math.ceil(self.l / 8)))

        hash_val = hashlib.sha256(K + data)
        pi = hash_val.digest()
        while int(math.ceil(self.l / 8)) > len(data):
            pi += hash_val.update(K).digest()
        tmp = int.from_bytes(pi, byteorder="big")
        tmp = tmp >> (len(pi) * 8 - self.l)
        return tmp.to_bytes(int(math.ceil(self.l / 8)), byteorder="big")

    def mu(self, K, data):
        """
        ψ: {0, 1}^k * {0, 1}^log22(s) -> {0, 1}^log22(s)
        :param K: with the length of k
        :param data: with the length of log22(s)
        :return: the bits with the length of log22(s)
        """
        # 扩充长度
        # if len(data) < int(math.ceil(math.log2(self.s) / 8)):
        if len(data) < int(math.ceil(self.s / 8)):
            # data = (int.from_bytes(data, byteorder="big").to_bytes(int(math.ceil(self.s / 8)), byteorder="big"))
            data = extend_bytes_len(data, int(math.ceil(self.s / 8)))

        hash_val = hashlib.sha256(K + data)
        mu = hash_val.digest()
        # while int(math.ceil(math.log2(self.s))) > len(data):
        while int(math.ceil(self.s / 8)) > len(data):
            mu += hash_val.update(K).digest()
        tmp = int.from_bytes(mu, byteorder="big")
        # tmp = tmp >> (len(mu) * 8 - int(math.ceil(math.log2(self.s))))
        tmp = tmp >> (len(mu) * 8 - int(math.ceil(self.s)))
        # return tmp.to_bytes(int(math.ceil(math.log2(self.s) / 8)), byteorder="big")
        return tmp.to_bytes(int(math.ceil(self.s / 8)), byteorder="big")

    def xor(self, a, b):
        """
        calculate a xor b
        :param a: byte string
        :param b: byte string
        :return: byte string
        """
        res = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
        return res.to_bytes(len(a), byteorder="big")

    def SKEEnc(self, K, plaintext):
        iv = os.urandom(AES.block_size)
        cryptor = AES.new(K, AES.MODE_CFB, iv)
        cipher = cryptor.encrypt(plaintext)
        return iv + cipher

    def SKEDec(self, K, ciphertext):
        iv = ciphertext[:AES.block_size]
        cipher = ciphertext[AES.block_size:]
        cryptor = AES.new(K, AES.MODE_CFB, iv)
        plaintext = cryptor.decrypt(cipher)
        return plaintext

    def search(self, t):
        """
        todo I should be a parameter
        :param t:
        :return:
        """
        # step1. parse t as (γ, η), set θ <- T[γ]
        gamma, tau = t
        theta = self.T[gamma]
        # step2. if θ ≠ ⊥, then parse θ ⊕ η as <α||K'> and continue, otherwise return ⊥ todo
        tmp = self.xor(theta, tau)
        alpha, k = tmp[:-int(math.ceil(self.k / 8))], tmp[-int(math.ceil(self.k / 8)):]
        # step3. use the key K' to decrypt the list L starting with the node stored at address α in A
        res = []
        while True:
            tmp = self.A[int.from_bytes(alpha, byteorder="big")]
            tmp = self.SKEDec(k, tmp)
            id_Dij = tmp[0:self.file_cnt_byte]
            id_Dij = byte2num(id_Dij)
            if id_Dij >= self.file_cnt:  # 如果解密出来得到的文档id大于等于实际文档数目，意味着该关键词并不存在
                return []

            # k = tmp[self.file_cnt_byte:-math.ceil(math.log2(self.s) / 8)]
            k = tmp[self.file_cnt_byte:-int(math.ceil(self.s / 8))]
            # alpha = tmp[-math.ceil(math.log2(self.s) / 8):]
            alpha = tmp[-int(math.ceil(self.s / 8)):]
            res.append(id_Dij)  # 将其转换成integer类型
            # if alpha == b"\x00" * math.ceil(math.log2(self.s) / 8):
            if alpha == b"\x00" * int(math.ceil(self.s / 8)):
                break
        return res

    def load_encrypted_index(self):
        with open(self.proj_dir_path + 'index.enc', 'rb') as f:
            itemlist = pickle.load(f)
            self.A, self.T = itemlist


def test():
    client = sse_client.SSEClient(256, 16, 'test')
    trapdoor = client.Trpdr_K('Xi')
    server = SSEServer('test')
    res = server.search(trapdoor)
    print(res)


if __name__ == '__main__':
    test()
