# coding=utf-8
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkcore.auth.credentials import StsTokenCredential

from flask import request, Flask
import subprocess
import json
import sys
import traceback
import logging


logging.getLogger('werkzeug').setLevel(logging.ERROR)

app = Flask(__name__)

REQUEST_ID_HEADER = 'x-fc-request-id'
AK_ID_HEADER = 'x-fc-access-key-id'
AK_SECRET_HEADER = 'x-fc-access-key-secret'
AK_TOKEN_HEADER = 'x-fc-security-token'


def is_acr_image(registry):
    return registry.startswith('registry') and registry.endswith('.aliyuncs.com')


@app.route("/", methods=['POST'])
def build_image():

    data = request.stream.read()
    try:
        evt = json.loads(data)
        url = evt['url']
        image = evt['image']  # 镜像名称
        repo = evt['repo'] 
        # 当然， 如果是您个人账号构建自己的镜像,也可以直接在镜像中完成 /kaniko/.docker/config.json 的创建, 下面的代码就不需要了
        # registry 默认是 dockerhub
        # 比如是阿里云的 acr， 示例 registry.cn-hangzhou.aliyuncs.com
        registry = evt.get('registry', 'registry.cn-hangzhou.aliyuncs.com')
        usr = evt.get('usr')  # 账户名
        pwd = evt.get('pwd')  # 账户密码
        if usr and pwd:  # usr 和 pwd 优先级高, 这样 ACR 可以支持跨账号
            pass
        else:
            if is_acr_image(registry):
                # use STS Token
                credentials = StsTokenCredential(
                    request.headers.get(AK_ID_HEADER), request.headers.get(AK_SECRET_HEADER), request.headers.get(AK_TOKEN_HEADER))
                region = registry.split('.')[1]
                client = AcsClient(region_id=region, credential=credentials)
                req = CommonRequest()
                req.set_accept_format('json')
                req.set_method('GET')
                req.set_protocol_type('https')  # https | http
                req.set_domain('cr.{}.aliyuncs.com'.format(region))
                req.set_version('2016-06-07')
                req.add_header('Content-Type', 'application/json')
                req.set_uri_pattern('/tokens')
                response = client.do_action_with_exception(req)
                r = json.loads(response)
                usr = r['data']['tempUserName']
                pwd = r['data']['authorizationToken']
            else:
                raise Exception("Only ACR can not pass usr and pwd")

        cmdStr = 'skopeo copy --dest-creds={}:{} docker://{}/{} docker://{}/{}/{}'.format(usr, pwd, url, image, registry, repo, image.split('/')[1])
        print(cmdStr)
        subprocess.check_call(cmdStr, shell=True)

    except Exception as e:
        exc_info = sys.exc_info()
        trace = traceback.format_tb(exc_info[2])
        errRet = {
            "message": str(e),
            "stack": trace
        }
        print(errRet)
        return errRet, 404, [("x-fc-status", "404")]
    return "OK"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9000)