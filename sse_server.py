# coding=utf-8
import os
import re
import hashlib
import random
import math
import array
import string
from Crypto.Cipher import AES
from Crypto import Random
import scanner
import printer
import sys
import base64
import pickle


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


class SSEClient:
    def __init__(self, k, l):
        # 检查参数，进行必要的错误或警告报告
        if k != 128 and k != 192 and k != 256:
            printer.print_error('The key length of AES must be 128, 192 or 256 bits.')
            sys.exit(1)
        if l % 8 != 0:
            printer.print_warning('The length of the parameter l is not an integer multiple of 8.')

        self.k = k
        self.k = byte_alignment(self.k)

        self.s = scanner.get_s()
        self.s = byte_alignment(self.s)

        self.l = l  # 在论文中，参数l需要指定
        self.l = byte_alignment(self.l)

        self.T = [None] * (2 ** self.l)
        self.k1, self.k2, self.k3, self.k4 = None, None, None, None

        # self.D = None
        self.distinct_word_set = None
        self.D_ = None

        # EncK(D) step3. initialize a global counter ctr = 1
        self.ctr = 1

        self.A = [None] * (2 ** self.s)
        self.entry_size_of_A = -1
        self.addrA = {}  # 组织成dict结构，用于获取每个链表第一个节点对应于A的位置
        self.k0_for_each_keyword = {}

        self.file_cnt = scanner.get_file_count()
        self.file_cnt_byte = int(math.ceil(math.log2(self.file_cnt) / 8))

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

    def enc_doc(self, index, k):
        with open('plain_text/' + str(index) + '.txt', encoding='UTF-8') as src:
            with open('cipher_text/' + str(index) + '.enc', 'wb') as dst:
                iv = os.urandom(AES.block_size)
                cryptor = AES.new(k, AES.MODE_CFB, iv)
                cipher = cryptor.encrypt(bytes(src.read(), encoding='UTF-8'))
                dst.write(iv + cipher)

    def dec_doc(self, index, k):
        with open('cipher_text/' + str(index) + '.enc', 'rb') as src:
            with open(str(index) + '.dec', 'w', encoding='UTF-8') as dst:
                cipher = src.read()
                iv = cipher[:AES.block_size]
                cipher = cipher[AES.block_size:]
                cryptor = AES.new(k, AES.MODE_CFB, iv)
                plain = cryptor.decrypt(cipher)
                dst.write(plain.decode('UTF-8'))

    def gen(self):
        """
        Gen步骤，用于生成四个密钥
        :param k: parameter
        :return: (K1, K2, K3, K4)
        """
        self.k1 = Random.new().read(int(math.ceil(self.k / 8)))
        self.k2 = Random.new().read(int(math.ceil(self.k / 8)))
        self.k3 = Random.new().read(int(math.ceil(self.k / 8)))
        # 对于k4,， 也使用同样的方法
        self.k4 = Random.new().read(int(math.ceil(self.k / 8)))
        return self.k1, self.k2, self.k3, self.k4

    def enc(self, docs):
        def initialization():
            # step1. scan D and generate the set of distinct keywords δ(D)
            self.distinct_word_set = scanner.generate_the_set_of_distinct_keywords_for_docs()[1]
            # step2. for all w ∈ δ(D), generate D(w)
            self.D_ = scanner.generate_Dw_for_each_keyword()
            # step3. initialize a global counter ctr = 1 ---> see __init__()

        def building_the_array_A():
            # step4. for 1<=i<=|δ(D)|, build a list Li with nodes Ni,j and store it in array A as follows:
            for i in range(1, len(self.distinct_word_set) + 1):
                keyword = self.distinct_word_set[i - 1]  # 在这里注意论文中的i和程序中的i不同，应当减一
                Ki = [None] * (len(self.D_[keyword]) + 1)
                Ni = [None] * (len(self.D_[keyword]) + 1)
                # sample a key Ki,0 <-$- {0, 1}^k
                Ki[0] = Random.new().read(int(self.k / 8))
                self.k0_for_each_keyword[keyword] = Ki[0]
                # for 1<=j<=|D(wi)|-1
                j = 0
                for j in range(1, len(self.D_[keyword])):
                    # let id(Di,j) be the jth identifier in D(wi)
                    id_Dij = self.D_[keyword][j - 1]  # todo
                    # generate a key Ki,j <- SKE1.Gen(1^k)
                    Ki[j] = Random.new().read(int(self.k / 8))
                    # if j == 1:
                    #    self.k0_for_each_keyword[keyword] = Ki[j]
                    # Ni[j] = str(id_Dij) + "|||" + str(Ki[j]) + "|||" + self.mu(Ki[j - 1], Ni[j])
                    Ni[j] = id_Dij.to_bytes(self.file_cnt_byte, byteorder="big") + Ki[j] + self.mu(self.k1, num2byte(
                        self.ctr + 1, int(self.s / 8)))
                    index = self.mu(self.k1, num2byte(self.ctr, int(self.s / 8)))
                    if j == 1:
                        self.addrA[keyword] = index  # 保存头节点的地址到dict里面去
                    index = int.from_bytes(index, byteorder="big")
                    self.A[index] = self.SKEEnc(Ki[j - 1], Ni[j])

                    if self.entry_size_of_A == -1:
                        self.entry_size_of_A = len(self.A[index])

                    self.ctr += 1
                # for the last node of Li
                # set the address of the next node to NULL: Ni,|D(wi)| = <id(Di,|D(wi)|) || 0^k || NULL>
                j += 1  # ...
                id_Dij = self.D_[keyword][len(self.D_[keyword]) - 1]
                Ni[len(self.D_[keyword])] = id_Dij.to_bytes(self.file_cnt_byte, byteorder="big") + b"\x00" * int(
                    self.k / 8) + b"\x00" * int(math.ceil(self.s / 8))  # todo
                index = self.mu(self.k1, num2byte(self.ctr, int(self.s / 8)))

                if j == 1:
                    self.addrA[keyword] = index  # 保存头节点的地址到dict里面去
                    # self.k0_for_each_keyword[keyword] = Ki[j]

                index = int.from_bytes(index, byteorder="big")
                self.A[index] = self.SKEEnc(Ki[j - 1], Ni[len(self.D_[keyword])])

                # encrypt the node Ni,|D(wi)| under the key Ki,|D(wi)-1| and store it in A
                self.ctr += 1

            # step5. set the remaining s - s' entries of A to random values of the same size
            # as the existing s' entries of A
            for i in range(len(self.A)):
                if self.A[i] is None:
                    self.A[i] = Random.new().read(self.entry_size_of_A)

        def building_the_look_up_table_T():
            size = -1  # size为look-up table 中元素的长度，用于第7个步骤

            # step6. for all wi ∈ δ(D), set T[π_K3(wi)] = <addr_A(N_i,1 || K_i,0)> ⊕ f_K2(wi)
            for w in self.distinct_word_set:
                index = self.pi(self.k3, str2byte(w))
                index = int.from_bytes(index, byteorder="big")
                self.T[index] = self.xor(self.addrA[w] + self.k0_for_each_keyword[w],
                                         self.f(self.k2, str2byte(w)))
                if size == -1:
                    size = len(self.T[index])

            # step7. if |δ(D)| < |△|, then set the remaining |△| - |δ(D)| entries of T to random values of the
            # same size as the existing |δ(D)| entries of T
            for i in range(2 ** self.l):
                if self.T[i] is None:
                    self.T[i] = Random.new().read(size)

        def enc_docs():
            # step8. for 1 <= i <= n, let ci <- SKE2.Enc_K4(Di)
            DIR = 'plain_text'
            file_count = len([name for name in os.listdir(DIR) if os.path.isfile(os.path.join(DIR, name))])
            for i in range(file_count):
                self.enc_doc(i, self.k4)

        printer.print_info('创建索引中...')
        initialization()

        printer.print_info('加密索引中...')
        building_the_array_A()
        building_the_look_up_table_T()

        printer.print_info('加密文档中...')
        enc_docs()
        printer.print_success('已就绪.')
        # step9. output
        return self.A, self.T

    def Trpdr_K(self, w):
        """
        output t = (πK3(w), fK2(w))
        :param w:
        :return:
        """
        index = self.pi(self.k3, str2byte(w))
        index = int.from_bytes(index, byteorder="big")
        return index, self.f(self.k2, str2byte(w))

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

    def Dec_K(self, cipher_index):
        return self.dec_doc(cipher_index, self.k4)

    def save_encrypted_index(self):
        """
        保存加密后的索引数据
        :return:
        """
        with open('index.enc', 'wb') as f:
            pickle.dump([self.A, self.T], f)

    # 下面为外部调用接口
    def generate_keys(self):
        """
        生成密钥(k1,k2,k3,k4)
        :return:
        """
        k1, k2, k3, k4 = self.gen()
        print('========THE KEY========')
        print('{}\n{}\n{}\n{}'.format(base64.b64encode(k1).decode(encoding='UTF-8'),
                                      base64.b64encode(k2).decode(encoding='UTF-8'),
                                      base64.b64encode(k3).decode(encoding='UTF-8'),
                                      base64.b64encode(k4).decode(encoding='UTF-8')))
        print('========THE KEY========')

    def encrypt(self):
        """
        生成索引、加密索引和加密文档
        :return:
        """
        printer.print_info('检查明文目录下文件名格式是否符合要求...')
        if not scanner.check_filename_format():
            printer.print_info('不符合文件命名格式，请问是否需要执行自动格式化文件名操作? (Y/N)')
            ok = input()
            if ok == 'y' or ok == 'Y':
                scanner.reformat_filename()
                printer.print_success('格式化文件名成功!')
            else:
                printer.print_error('软件终止...请自行更改文件名以满足要求!')
        else:
            printer.print_success('检查完毕，文件名符合要求!')

    def load_encrypted_index(self):
        with open('index.enc', 'rb') as f:
            itemlist = pickle.load(f)
            self.A, self.T = itemlist

    def save_keys(self):
        """
        保存密钥K到本地
        :return:
        """
        with open('xxx.key', 'wb') as f:
            pickle.dump([self.k1, self.k2, self.k3, self.k4], f)

    def load_keys(self):
        """
        读取密钥本地文件
        :return:
        """
        with open('xxx.key', 'rb') as f:
            self.k1, self.k2, self.k3, self.k4 = pickle.load(f)


if __name__ == '__main__':
    client = SSEClient(256, 16)
    client.load_keys()
    client.load_encrypted_index()
    while True:
        keyword = input('Input the keyword: ')
        tmp = client.Trpdr_K(keyword)
        tmp = client.search(tmp)
        print(tmp)
