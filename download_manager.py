import requests
from sse_client import *


def download_from_server_given_proj_name(proj_name:str, index:int) -> str:
    """
    根据项目名proj_name和索引index，下载指定的加密文件
    :param proj_name: 项目名
    :param index: 索引
    :return: 加密文件的base64编码格式
    """
    param = dict()
    param['name'] = proj_name
    param['index'] = index

    return requests.post('http://127.0.0.1:8000/download', data=param).text


def download_from_server_given_client_and_decrypt(client, index) -> (str, str):
    """
    根据客户端对象client和索引index，下载指定的文件
    :param client: 客户端对象
    :param index: 索引
    :return: 指定index的明文
    """
    cipher = download_from_server_given_proj_name(client.proj_name, index)
    # 注意cipher还是处于base64编码格式，需要解码成bytes形式
    plain = client.dec_doc_given_cipher(base64.b64decode(cipher), client.k4)
    plain = str(plain, encoding='utf-8')
    title = plain[plain.rfind('\n') + 1:]
    text = plain[:plain.rfind('\n')]
    return title, text


if __name__ == '__main__':
    print(download_from_server_given_client_and_decrypt(SSEClient('test', 256, 16), 0))
