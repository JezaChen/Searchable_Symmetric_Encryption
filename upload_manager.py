import requests
import base64
import scanner


def upload_to_server(proj_name, need_to_clear='N'):
    proj_dir_path = proj_name + '/'
    param = {}
    param['name'] = proj_name
    param['need_to_clear'] = need_to_clear

    with open(proj_dir_path + 'index.enc', 'rb') as index_f:
        encrypted_index = index_f.read()
        encrypted_index = base64.b64encode(encrypted_index)
        param['index'] = encrypted_index

        # fixed: upload the config (k, l, s)
        with open(proj_dir_path + 'config', 'rb') as config_f:
            config = config_f.read()
            config = base64.b64encode(config)
            param['config'] = config

        docs_num = scanner.get_file_count(proj_dir_path)
        param['num'] = str(docs_num)

        for i in range(docs_num):
            doc_f = open(proj_dir_path + 'cipher_text/' + str(i) + '.enc', 'rb')
            doc = doc_f.read()
            doc = base64.b64encode(doc)
            param[str(i)] = doc

        return requests.post('http://127.0.0.1:8000/upload', data=param).text


if __name__ == '__main__':
    upload_to_server('test')
