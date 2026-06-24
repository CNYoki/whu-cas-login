import requests
from lxml import etree
# 加密
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64
import random


# 智慧珞珈 UA
mobile_ua = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "com.ssreader.ZhiHuiLuoJiaStudy/ChaoXingStudy_1000028_4.7.3_ios_phone_202606220833_53")


class AESEncryptor:
    """AES 加密工具类"""
    CHARS = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'

    @staticmethod
    def _random_string(length):
        return ''.join(random.choice(AESEncryptor.CHARS) for _ in range(length))

    @staticmethod
    def _encrypt_with_iv(data, key, iv):
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode('utf-8'))
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode()

    @classmethod
    def encrypt(cls, data, key):
        if not key:
            return data
        prefix = cls._random_string(64)
        iv = cls._random_string(16)
        return cls._encrypt_with_iv(prefix + data, key, iv)


class WHUCASMobileClient:

    def __init__(self, username, password, remember_me=True):
        self.username = username
        self.password = password
        self.remember_me = remember_me
        self.session = requests.Session()
        self.proxies = {"http": "", "https": ""}

    @staticmethod
    def _first(values, default=''):
        """取 xpath 结果的第一个值"""
        return values[0] if values else default

    def _get_login_params(self, login_url):
        """获取移动端账号密码登录所需的隐藏参数
        """
        # Referer 带 login_type=mobileLogin
        headers = {
            "User-Agent": mobile_ua,
            "Referer": login_url + "&login_type=mobileLogin",
        }
        start_response = self.session.get(login_url, headers=headers, proxies=self.proxies)
        start_html = etree.HTML(start_response.text, parser=etree.HTMLParser())

        form = '//div[@id="pwdLoginDiv"]//form'
        params = {
            'lt': self._first(start_html.xpath(f'{form}//input[@name="lt"]/@value')),
            'cllt': self._first(start_html.xpath(f'{form}//input[@id="cllt"]/@value'), 'userNameLogin'),
            'execution': self._first(start_html.xpath(f'{form}//input[@name="execution"]/@value'), 'e1s1'),
            '_eventId': self._first(start_html.xpath(f'{form}//input[@name="_eventId"]/@value'), 'submit'),
            'pwdEncryptSalt': self._first(start_html.xpath(f'{form}//input[@id="pwdEncryptSalt"]/@value')),
        }

        if not params['pwdEncryptSalt']:
            raise RuntimeError("未能从移动端登录页解析到 pwdEncryptSalt")

        print("params", params)
        return params

    def _do_login(self, login_url, params):
        """执行移动端登录（dllt=mobileLogin，captcha 留空）"""
        print(f"Salt: {params['pwdEncryptSalt']}")
        password_enc = AESEncryptor.encrypt(self.password, params['pwdEncryptSalt'])

        data = {
            'username': self.username,
            'password': password_enc,
            'captcha': '',
            '_eventId': params['_eventId'],
            'lt': params['lt'],
            'cllt': params['cllt'],
            'dllt': 'mobileLogin',
            'execution': params['execution'],
        }
        if self.remember_me:
            data['rememberMe'] = 'true'
        print("login data", data)

        headers = {
            "User-Agent": mobile_ua,
            "Origin": "https://cas.whu.edu.cn",
            "Referer": login_url + "&login_type=mobileLogin",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        login_response = self.session.post(
            login_url,
            data=data,
            allow_redirects=False,
            headers=headers,
            proxies=self.proxies,
        )

        print("login status", login_response.status_code)
        return login_response

    def login(self, login_url):
        """完成移动端登录，返回登录成功后的回调地址（含 ticket）"""
        try:
            params = self._get_login_params(login_url)
            login_response = self._do_login(login_url, params)
            print(login_response.text)

            # 成功为 302，Location 指向 mobile/callback?appId=...&ticket=ST-...
            redirect_url = login_response.headers.get('Location')
            if login_response.status_code != 302 or not redirect_url:
                print("登录未跳转，可能账号密码错误或需要验证码")
                return None

            print(f"Callback URL: {redirect_url}")
            print("登录后 cookies:", self.session.cookies.get_dict())
            print("是否持有 TGT(CASTGC):", self.has_tgt())
            return redirect_url

        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_ticket(self, login_url):
        """登录并从回调地址中提取 CAS ticket（ST-...）。"""
        redirect_url = self.login(login_url)
        if not redirect_url or 'ticket=' not in redirect_url:
            return None
        return redirect_url.split('ticket=')[1].split('&')[0]

    def access_service(self, service_url):
        """在已登录状态下访问受 CAS 保护的业务地址。

        无需重新输入账号密码：当前 session 已持有 CAS 的 TGT(CASTGC)，
        只需再向 CAS 申请一张针对该 service 的 ST 票据，CAS 会凭 TGT
        直接 302 回 service 并由其校验票据、种下业务会话 Cookie。

        返回业务侧最终响应（已自动跟随 CAS -> service 的跳转）。
        """
        from urllib.parse import quote
        cas_login = ("https://cas.whu.edu.cn/authserver/login?service="
                     + quote(service_url, safe=''))

        # 跟随跳转：CAS 302 -> service?ticket=ST-... -> service 校验后种 Cookie
        r = self.session.get(
            cas_login,
            headers={"User-Agent": mobile_ua},
            allow_redirects=True,
            proxies=self.proxies,
        )
        print("access status", r.status_code)
        print("session cookies", self.session.cookies.get_dict())
        return r

    # ---------- 会话保持 / 刷新 ----------

    def has_tgt(self):
        """当前会话是否还持有 CAS 的 TGT(CASTGC)。"""
        return any(c.name == 'CASTGC' for c in self.session.cookies)

    def save_session(self, path='cas_session.pkl'):
        """把 cookie 落盘，进程重启后可免登录恢复。"""
        import pickle
        with open(path, 'wb') as f:
            pickle.dump(self.session.cookies, f)
        print(f"会话已保存到 {path}")

    def load_session(self, path='cas_session.pkl'):
        """从磁盘恢复 cookie；返回是否成功且仍持有 TGT。"""
        import pickle
        import os
        if not os.path.exists(path):
            return False
        with open(path, 'rb') as f:
            self.session.cookies.update(pickle.load(f))
        return self.has_tgt()

    def refresh(self, service_url, login_url=None):
        """刷新业务会话：优先用现有 TGT 换新票，TGT 失效才整套重登。

        返回业务侧最终响应。判定标准：跳转后落点仍在业务域名、
        且没有被打回 CAS 登录页（authserver/login）。
        """
        def _ok(resp):
            return ('cas.whu.edu.cn/authserver/login' not in resp.url
                    and 'login' not in resp.url.split('?')[0].rsplit('/', 1)[-1])

        # 1) 还有 TGT，直接换票（无需密码）
        if self.has_tgt():
            resp = self.access_service(service_url)
            if _ok(resp):
                return resp
            print("TGT 已失效，转为重新登录")

        # 2) TGT 没了 → 整套重新登录后再换票
        if login_url is None:
            raise RuntimeError("TGT 失效且未提供 login_url，无法重新登录")
        if not self.login(login_url):
            raise RuntimeError("重新登录失败")
        return self.access_service(service_url)


if __name__ == '__main__':
    username = ''
    password = ''

    # 移动端回调
    login_url = ('https://cas.whu.edu.cn/authserver/login?service='
                 'https%3A%2F%2Fcas.whu.edu.cn%2Fauthserver%2Fmobile%2Fcallback%3FappId%3D13723413')

    client = WHUCASMobileClient(username, password)
    callback_url = client.login(login_url)
    print(f"Callback: {callback_url}")

    if callback_url:
        ticket = callback_url.split('ticket=')[-1].split('&')[0]
        print(f"Ticket: {ticket}")

        # 智慧珞珈测试
        service = "https://zhlj.whu.edu.cn/casLogin"
        resp = client.access_service(service)
        print("最终地址:", resp.url)
        print("响应内容:", resp.text[:500])
