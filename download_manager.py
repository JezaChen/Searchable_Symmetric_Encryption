import requests
import base64
import scanner


def download_from_server(proj_name, index) -> str:
    """
    根据索引index，下载指定的加密文件
    :param proj_name: 项目名
    :param index: 索引
    :return: 加密文件的base64编码格式
    """
    param = {}
    param['name'] = proj_name
    param['index'] = index

    return requests.post('http://127.0.0.1:8000/download', data=param).text


if __name__ == '__main__':
    print(download_from_server('test', 0))
