# coding=utf-8
import os
import hashlib
import math
from Crypto.Cipher import AES
from Crypto import Random
import scanner
import printer
import sys
import base64
import pickle
import shutil
import getopt
import upload_manager
import search_manager
import download_manager


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


def get_status_by_bits(bits):
    """
    根据状态比特，判断出当前proj的状态
    约定:(按以下顺序检测，左侧数字为返回值)
    2: 项目不存在 --> 目录不存在
    3: 明文集不存在 --> 如果项目目录和子目录plain_text都为空 --> 既没有明文，又没有密钥文件 --> & 01010 == 0
    4: 未执行gen()方法 --> 不存在密钥文件 --> & 00010 == 0
    5: 未执行enc()方法 --> 存在明文集和密钥文件，但不存在密文集和加密后的索引文件 --> & 01110 == 01010 -> 10
    6: 未执行上传操作 --> 如果存在密文集 --> & 00100 == 00100 -> 4
    7: 哈希不一致
    1: 成功

    第一位 --> 是否存在项目文件夹
    第二位 --> 是否存在密钥文件
    第三位 --> 是否存在密文集
    第四位 --> 是否存在明文集
    第五位 --> 哈希对比是否一致 todo
    :param bits: integer
    :return:
    """
    if bits & 1 == 0:
        return 2
    if bits & 10 == 0:
        return 3
    if bits & 2 == 0:
        return 4
    if bits & 14 == 10:
        return 5
    if bits & 4 == 4:  # fix
        return 6
    # todo hash
    # ----------

    return 1


class SSEClient:
    def __init__(self, proj_name, k=0, l=0):
        self.proj_name = proj_name
        self.proj_dir_path = proj_name + '/'

        if os.path.isdir(self.proj_dir_path):  # 如果项目已经存在，不需要指定k和l，直接读取参数文件
            self.k, self.l = self.load_config()[:2]
        else:
            # 检查参数，进行必要的错误或警告报告
            if k != 128 and k != 192 and k != 256:
                printer.print_error('The key length of AES must be 128, 192 or 256 bits.')
                sys.exit(1)
            if l % 8 != 0:
                printer.print_warning('The length of the parameter l is not an integer multiple of 8.')

            self.k = k
            self.k = byte_alignment(self.k)

            self.l = l  # 在论文中，参数l需要指定
            self.l = byte_alignment(self.l)

        self.s = scanner.get_s(self.proj_dir_path)  # todo
        self.s = byte_alignment(self.s)

        # 状态信息变量
        self.exists_plain_texts = False  # 是否存在明文集
        self.exists_cipher_texts = False  # 是否存在密文集
        self.exists_key_file = False  # 是否存在密钥文件
        self.exists_proj_dir = False  # 是否存在项目文件夹

        # 第一位 --> 是否存在项目文件夹
        # 第二位 --> 是否存在密钥文件
        # 第三位 --> 是否存在密文集
        # 第四位 --> 是否存在明文集
        self.status_bits = 0
        self.set_status_bits()  # 判断当前proj的状态

        self.T = [None] * (2 ** self.l)

        self.k1, self.k2, self.k3, self.k4 = None, None, None, None
        self.load_keys()

        # self.D = None
        self.distinct_word_set = None
        self.D_ = None

        # EncK(D) step3. initialize a global counter ctr = 1
        self.ctr = 1

        self.A = [None] * (2 ** self.s)
        self.entry_size_of_A = -1
        self.addrA = {}  # 组织成dict结构，用于获取每个链表第一个节点对应于A的位置
        self.k0_for_each_keyword = {}

        self.file_cnt = scanner.get_file_count(self.proj_dir_path)
        if self.file_cnt == 0:
            self.file_cnt_byte = 0
        else:
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
        with open(self.proj_dir_path + 'plain_text/' + str(index) + '.txt', encoding='UTF-8') as src:
            with open(self.proj_dir_path + 'cipher_text/' + str(index) + '.enc', 'wb') as dst:
                iv = os.urandom(AES.block_size)
                cryptor = AES.new(k, AES.MODE_CFB, iv)
                cipher = cryptor.encrypt(bytes(src.read(), encoding='UTF-8'))
                dst.write(iv + cipher)

    def dec_doc_given_index(self, index, k):
        with open(self.proj_dir_path + 'cipher_text/' + str(index) + '.enc', 'rb') as src:
            with open(self.proj_dir_path + str(index) + '.dec', 'w', encoding='UTF-8') as dst:
                cipher = src.read()
                iv = cipher[:AES.block_size]
                cipher = cipher[AES.block_size:]
                cryptor = AES.new(k, AES.MODE_CFB, iv)
                plain = cryptor.decrypt(cipher)
                dst.write(plain.decode('UTF-8'))

    def dec_doc_given_cipher(self, cipher, k):
        """
        给定密文和密钥，返回明文数据
        :param cipher: 密文
        :param k: 解密密钥
        :return:
        """
        iv = cipher[:AES.block_size]
        cipher = cipher[AES.block_size:]
        cryptor = AES.new(k, AES.MODE_CFB, iv)
        plain = cryptor.decrypt(cipher)
        return plain

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

    def enc(self):
        def initialization():
            # step1. scan D and generate the set of distinct keywords δ(D)
            self.distinct_word_set = scanner.generate_the_set_of_distinct_keywords_for_docs(self.proj_dir_path)[1]
            # step2. for all w ∈ δ(D), generate D(w)
            self.D_ = scanner.generate_Dw_for_each_keyword(self.proj_dir_path)
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
        return self.dec_doc_given_index(cipher_index, self.k4)

    def save_encrypted_index(self):
        """
        保存加密后的索引数据
        :return:
        """
        with open(self.proj_dir_path + 'index.enc', 'wb') as f:
            pickle.dump([self.A, self.T], f)

    def save_keys(self):
        """
        保存密钥K到本地
        :return:
        """
        with open(self.proj_dir_path + self.proj_name + '.key', 'wb') as f:
            pickle.dump([self.k1, self.k2, self.k3, self.k4], f)

    def load_keys(self):
        """
        读取密钥本地文件
        :return:
        """
        # 不存在密钥文件，直接返回，无需读取
        if not os.path.isfile(self.proj_dir_path + self.proj_name + '.key'):
            return

        with open(self.proj_dir_path + self.proj_name + '.key', 'rb') as f:
            self.k1, self.k2, self.k3, self.k4 = pickle.load(f)

    def set_status_bits(self):
        """
        检查当前proj中，是否已经存在明文集？是否存在密钥文件？是否存在密文集（意味着没有上传到服务器）？服务器上的密文集是否有损坏？
        以位的方式表示出来

        第一位 --> 是否存在项目文件夹
        第二位 --> 是否存在密钥文件
        第三位 --> 是否存在密文集
        第四位 --> 是否存在明文集
        第五位 --> 哈希对比是否一致 todo

        -- 用于初始化函数调用
        :return:
        """
        if os.path.isdir(self.proj_dir_path):
            self.status_bits = self.status_bits | 1
        if os.path.isfile(self.proj_dir_path + self.proj_name + '.key'):
            self.status_bits = self.status_bits | 2
        if os.path.isdir(self.proj_dir_path + 'cipher_text') and os.listdir(self.proj_dir_path + 'cipher_text'):
            self.status_bits = self.status_bits | 4
        if os.path.isdir(self.proj_dir_path + 'plain_text') and os.listdir(self.proj_dir_path + 'plain_text'):
            self.status_bits = self.status_bits | 8
        # todo 哈希对比

    def load_config(self):
        """
        读取配置文件
        :return: k, l, s
        """
        with open(self.proj_dir_path + 'config', 'rb') as f:
            return pickle.load(f)

    # 下面为外部调用接口
    def status(self):
        """
        获取当前项目的状态
        2: 项目不存在 --> 目录不存在
        3: 明文集不存在 --> 如果项目目录和子目录plain_text都为空 --> 既没有明文，又没有密钥文件 --> & 01010 == 0
        4: 未执行gen()方法 --> 不存在密钥文件 --> & 00010 == 0
        5: 未执行enc()方法 --> 存在明文集和密钥文件，但不存在密文集和加密后的索引文件 --> & 01110 == 01010 -> 10
        6: 未执行上传操作 --> 如果存在密文集 --> & 00100 == 0
        7: 哈希不一致
        1: 成功
        :return: None
        """
        status_details_dict = {
            1: "当前项目已经可以进行加密搜索。",
            2: "项目不存在。",
            3: "明文集不存在。",
            4: "该项目未执行gen方法生成密钥。",
            5: "该项目未执行enc方法进行加密操作。",
            6: "该项目已经在本地部署完毕，但仍未上传到服务器。",
            7: "该项目似乎在服务器遭到破坏，请重新生成"
        }
        status_id = get_status_by_bits(self.status_bits)
        printer.print_info(status_details_dict[status_id])

    def init(self):
        """
        初始化proj，即新建目录，并在该目录下新建明文和密文目录
        :return: None
        """

        def init_action():
            if os.path.isdir(self.proj_name):  # 如果已经存在项目目录，就需要递归删除该目录
                # os.removedirs(self.proj_name)
                shutil.rmtree(self.proj_name)
            os.mkdir(self.proj_name)
            os.mkdir(self.proj_dir_path + 'plain_text')
            os.mkdir(self.proj_dir_path + 'cipher_text')

            # 接下来，还要保存配置文件
            with open(self.proj_dir_path + 'config', 'wb') as f:
                pickle.dump([self.k, self.l, self.s, self.file_cnt], f)

        if os.path.isdir(self.proj_name):
            printer.print_warning("发现已经存在同名目录，是否需要清除该目录下所有内容? (Y/N)")
            ok = input()
            if ok == 'Y' or ok == 'y':
                printer.print_info("正在清空并初始化中...")
                init_action()
                printer.print_success("清空完成!")
            else:
                printer.print_info("用户已拒绝操作，程序退出...")
                return
        else:
            printer.print_info("正在初始化项目中...")
            init_action()
            printer.print_success("初始化项目完成!")

    def generate_keys(self):
        """
        生成密钥(k1,k2,k3,k4)
        :return:
        """

        def generate_keys_action():
            k1, k2, k3, k4 = self.gen()
            print('========THE KEY========')
            print('{}\n{}\n{}\n{}'.format(base64.b64encode(k1).decode(encoding='UTF-8'),
                                          base64.b64encode(k2).decode(encoding='UTF-8'),
                                          base64.b64encode(k3).decode(encoding='UTF-8'),
                                          base64.b64encode(k4).decode(encoding='UTF-8')))
            print('========THE KEY========')
            # 保存密钥
            self.save_keys()
            printer.print_success('密钥文件已保存至本地.')

        if 2 <= get_status_by_bits(self.status_bits) < 4 or get_status_by_bits(self.status_bits) == 7:  # 前面的步骤没有完成时
            printer.print_error('操作失败，理由: ')
            self.status()
            return
        if get_status_by_bits(self.status_bits) == 6 or get_status_by_bits(self.status_bits) == 1:
            # 如果之前已经有了密文集或者已经上传到了服务器
            # 需要告知用户谨慎生成密钥文件
            printer.print_warning('已发现使用旧密钥加密后的密文集和索引，重新生成密钥需要重新自行执行enc和upload方法进行同步更新.\n'
                                  '是否需要继续? (Y/N)')
            ok = input()
            if ok == 'Y' or ok == 'y':
                generate_keys_action()
            else:
                printer.print_info('程序没有进行任何操作，退出...')

        generate_keys_action()

    def encrypt(self):
        """
        生成索引、加密索引和加密文档
        :return:
        """

        def encrypt_action():
            printer.print_info('检查明文目录下文件名格式是否符合要求...')
            if not scanner.check_filename_format(self.proj_dir_path):
                printer.print_info('不符合文件命名格式，请问是否需要执行自动格式化文件名操作? (Y/N)')
                ok = input()
                if ok == 'y' or ok == 'Y':
                    scanner.reformat_filename(self.proj_dir_path)
                    printer.print_success('格式化文件名成功!')
                else:
                    printer.print_error('软件终止...请自行更改文件名以满足要求!')
            else:
                printer.print_success('检查完毕，文件名符合要求!')
            printer.print_info('开始加密索引和文档...')
            self.enc()
            self.save_encrypted_index()  # 记得保存索引
            printer.print_success('加密索引和文档成功')

        def delete_local_plain_texts():
            """
            加密操作成功后，删除本地上的明文文件
            :return:
            """
            shutil.rmtree(self.proj_dir_path + 'plain_text')

        if 2 <= get_status_by_bits(self.status_bits) < 5 or get_status_by_bits(self.status_bits) == 7:
            printer.print_error('操作失败，理由: ')
            self.status()
            return

        encrypt_action()
        delete_local_plain_texts()

    def upload(self):
        """
        上传密文、加密后的索引、配置文件到服务器上
        :return:
        """

        def upload_action():
            return upload_manager.upload_to_server(self.proj_name, 'Y')

        def delete_local_cipher():
            """
            如果上传完毕，删除本地上的密文集和加密索引
            :return:
            """
            shutil.rmtree(self.proj_dir_path + 'cipher_text')
            os.remove(self.proj_dir_path + 'index.enc')

        if 2 <= get_status_by_bits(self.status_bits) < 6:
            printer.print_error('操作失败，理由: ')
            self.status()
            return
        res = upload_action()
        if res != 'success':
            printer.print_error('上传失败！服务器返回信息如下：')
            printer.print_error(res)
        else:
            printer.print_success('上传成功!')
            delete_local_cipher()

    def find(self, keyword):
        """
        执行搜索操作
        :param keyword: 待搜索的关键词
        :return:
        """

        def save_result():
            try:
                if not os.path.isdir(self.proj_dir_path + 'search_results'):
                    os.mkdir(self.proj_dir_path + 'search_results')

                DIR = self.proj_dir_path + 'search_results/' + keyword
                if not os.path.isdir(DIR):
                    os.mkdir(DIR)
                    DIR += '/'
                    for index in res:
                        tmp = download_manager.download_from_server_given_client_and_decrypt(self, index)
                        printer.print_info(tmp[0])  # 打印出相应的标题
                        with open(DIR + tmp[0], 'w', encoding='UTF-8') as f:
                            f.write(tmp[1])
                printer.print_info('搜索结果已经保存在目录 ' + DIR + ' 中。')
            except OSError:
                printer.print_error('由于系统限制，指定的关键词无法搜索!')

        def search_action():
            return search_manager.search_once_from_server(self, keyword)

        if get_status_by_bits(self.status_bits) != 1:
            printer.print_error('操作失败，理由: ')
            self.status()
            return
        res = search_action()
        printer.print_info('搜索结果如下:')
        save_result()


def test():
    client = SSEClient('test', 256, 16)
    client.generate_keys()
    client.save_keys()
    client.encrypt()
    client.enc()
    client.save_encrypted_index()
    while True:
        keyword = input('Input the keyword: ')
        tmp = client.Trpdr_K(keyword)
        tmp = client.search(tmp)
        print(tmp)


def search_multiple_times(client):
    keyword = input('>>> ')
    while keyword is not None:
        keyword = keyword.strip()
        client.find(keyword)
        keyword = input('>>>')


def parse_args():
    opts, args = getopt.getopt(sys.argv[1:], '-s-p:-i-g-e-u-f:',
                               ['status', 'project', 'init', 'gen', 'enc', 'upload', 'find='])
    client = None
    # 先初始化SSEClient对象
    for opt_name, opt_val in opts:
        if opt_name in ('-p', '--project'):
            client = SSEClient(opt_val, 256, 16)
            break

    if client is None:
        printer.print_error('请指定项目名! (使用参数-p <项目名> 或 --project <项目名>)')
        sys.exit(1)

    for opt_name, opt_val in opts:
        if opt_name in ('-s', '--status'):
            client.status()
        if opt_name in ('-i', '--init'):
            client.init()
        if opt_name in ('-g', '--gen'):
            client.generate_keys()
        if opt_name in ('-e', '--enc'):
            client.encrypt()
        if opt_name in ('-u', '--upload'):
            client.upload()
        if opt_name in ('-f', '--find'):
            keyword = opt_val
            if keyword != '':
                client.find(keyword)
            else:
                search_multiple_times(client)


if __name__ == '__main__':
    parse_args()
    # test()
