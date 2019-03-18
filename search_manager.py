import requests
from sse_client import *
import json


def search_once_from_server(client, keyword):
    """
    给出指定的客户端对象和关键字，从服务器中搜索数据
    :param client: 客户端实例
    :param keyword 关键字
    :return:
    """
    trapdoor = client.Trpdr_K(keyword)
    # POST服务器的数据中，陷门使用如下格式
    # πK3(w)为整型数，直接使用str转换即可；fK2(w)需要使用base64进行编码；两者使用句点进行分割。
    param = {'name': client.proj_name,
             'trapdoor': str(trapdoor[0]) + '.' + str(base64.b64encode(trapdoor[1]), encoding='utf-8')}
    res = requests.post('http://127.0.0.1:8000/search', data=param)
    return json.loads(res.text)


if __name__ == '__main__':
    print(search_once_from_server(SSEClient('test', 256, 16), 'China'))
