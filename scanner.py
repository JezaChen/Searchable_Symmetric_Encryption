# coding=utf-8
import os
import re
import math
import pickle


def generate_the_set_of_distinct_keywords_for_one_doc(doc):
    """
    针对单个文档，提取出该文档的单词（不重复）
    :param doc: 文档名
    :return: 列表，保存有该文档的单词
    """
    with open(doc, encoding='UTF-8') as f:
        words = f.read()
        words = re.split(' |\t|\n|\.|,|\?|!|:|;', words)  # 分解字符串，提取单词
        distinct_word = list(set(words))
        return distinct_word


DISTINCT_WORD_LST_OF_EACH_DOC = []
DISTINCT_WORD_LST = []


def get_file_count(proj_dir_path=''):
    """
    获取明文文档的数目
    :return:
    """
    try:
        DIR = proj_dir_path + 'plain_text'
        if not os.path.isdir(DIR):
            DIR = proj_dir_path + 'cipher_text'
            if not os.path.isdir(DIR):
                with open(proj_dir_path + 'config', 'rb') as f:
                    return pickle.load(f)[3]

        cnt = len([name for name in os.listdir(DIR) if os.path.isfile(os.path.join(DIR, name))])

        with open(proj_dir_path + 'config', 'rb') as f:
            tmp = pickle.load(f)[:3]

        with open(proj_dir_path + 'config', 'wb') as f:
            pickle.dump(tmp + [cnt], f)
        return cnt
    except (IndexError, EOFError, FileNotFoundError):
        return 0



def generate_the_set_of_distinct_keywords_for_docs(proj_dir_path=''):
    """
    针对一个文档集，提取出单词集（不重复）和各个文档的单词集
    :return:
    """
    global DISTINCT_WORD_LST_OF_EACH_DOC, DISTINCT_WORD_LST
    if DISTINCT_WORD_LST and DISTINCT_WORD_LST_OF_EACH_DOC:
        return DISTINCT_WORD_LST_OF_EACH_DOC, DISTINCT_WORD_LST

    DIR = proj_dir_path + 'plain_text'
    file_count = get_file_count(proj_dir_path)
    for i in range(file_count):
        lst = generate_the_set_of_distinct_keywords_for_one_doc(DIR + '/' + str(i) + '.txt')
        DISTINCT_WORD_LST_OF_EACH_DOC.append(list(set(lst)))
        DISTINCT_WORD_LST.extend(lst)
        DISTINCT_WORD_LST = list(set(DISTINCT_WORD_LST))
    return DISTINCT_WORD_LST_OF_EACH_DOC, DISTINCT_WORD_LST


def generate_Dw_for_each_keyword(proj_dir_path=''):
    """
    Dw: the set of identifiers of documents in D that contain keyword w ordered in lexicographic order
    :param w: 关键词w
    :return: 列表
    """
    Dw = {}  # Dw应该是一个dict，方便检索
    distinct_keyword_lst_of_each_doc, distinct_keyword_lst = generate_the_set_of_distinct_keywords_for_docs(proj_dir_path)
    for word in distinct_keyword_lst:
        for doc_index in range(len(distinct_keyword_lst_of_each_doc)):
            if word in distinct_keyword_lst_of_each_doc[doc_index]:
                if Dw.get(word, None) is None:
                    Dw[word] = []
                Dw[word].append(doc_index)
    return Dw


s = 0


def get_s(proj_dir_path=''):
    """
    s is the total size of the encrypted document collection in "min-units"
    :return:
    """
    try:
        global s
        if s != 0:
            return s

        DIR = proj_dir_path + 'plain_text'
        if not os.path.isdir(DIR):
            with open(proj_dir_path + 'config', 'rb') as f:
                return pickle.load(f)[2]

        list_dir = os.walk(DIR)
        for root, dirs, files in list_dir:
            for f in files:
                fname = os.path.join(root, f)
                with open(fname, encoding='UTF-8') as doc:
                    s += len(doc.read())
        # print(s)
        if s == 0:
            return 0

        s = int(math.ceil(math.log2(s)))

        with open(proj_dir_path + 'config', 'rb') as f:
            tmp = pickle.load(f)
        tmp[2] = s

        with open(proj_dir_path + 'config', 'wb') as f:
            pickle.dump(tmp, f)
        return s
    except FileNotFoundError:
        return 0


def check_filename_format(proj_dir_path=''):
    """
    检查plain_text目录下的文件名是否符合格式(0,1,2,...)
    :return:
    """
    DIR = proj_dir_path + 'plain_text'
    file_cnt = get_file_count(proj_dir_path)
    for i in range(file_cnt):
        if not os.path.exists(os.path.join(DIR, str(i) + '.txt')):
            return False
    return True


def reformat_filename(proj_dir_path=''):
    """
    重新命名plain_text目录下的文件名以符合格式要求(0,1,2,...)
    update 0317: 将文件名放在文件中一起保存
    :return:
    """
    DIR = proj_dir_path + 'plain_text'
    file_cnt = get_file_count()
    for root, dirs, files in os.walk(DIR):
        i = 0
        for file in files:
            file_path = os.path.join(DIR, file)
            with open(file_path, 'a+', encoding='utf-8') as f:
                f.seek(0, 0)
                f.write('\n' + file)

            os.rename(file_path, os.path.join(DIR, str(i) + '.txt'))
            i += 1


if __name__ == '__main__':
    distinct_keyword_lst_of_each_doc, distinct_keyword_lst = generate_the_set_of_distinct_keywords_for_docs("test_x/")
    Dw = generate_Dw_for_each_keyword("test_x/")
    print(Dw['China'])
