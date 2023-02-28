from flask import Blueprint, render_template, request, url_for, jsonify, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

from apps.user.models import User
from apps.user.smssend import SmsSendAPIDemo
from exts import db

user_bp1 = Blueprint('user', __name__, url_prefix='/user')

# 首页
@user_bp1.route('/')
def index():
    # 1.cookie获取方式
    # uid = request.cookies.get('uid', None)
    # 2.session的获取,session底层默认获取
    uid = session.get('uid', None)
    if uid:     # 登录成功
        user = User.query.get(uid)
        return render_template('user/index.html', user=user)
    else:       # 登录不成功
        return render_template('user/index.html')


# 注册
@user_bp1.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        repassword = request.form.get('repassword')
        phone = request.form.get('phone')
        email = request.form.get('email')
        if password == repassword:
            # 注册用户
            user = User()
            user.username = username
            user.password = generate_password_hash(password)
            user.phone = phone
            user.email = email
            # 添加并提交
            db.session.add(user)
            db.session.commit()
            return '注册成功'
    return render_template('user/register.html')


# 检查手机号码
@user_bp1.route('/checkphone', methods=['GET', 'POST'])
def check_phone():
    phone = request.args.get('phone')
    user = User.query.filter(User.phone == phone).all()  # 列表
    print(user)
    # code: 400 不能用   200 可以用
    if len(user) > 0:
        return jsonify(code=400, msg='此号码已被注册')
    else:
        return jsonify(code=200, msg='此号码可用')


# 用户登录
@user_bp1.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        f = request.args.get('f')
        if f == 1:    # 密码
            username = request.form.get('username')
            password = request.form.get('password')
            users = User.query.filter(User.username == username).all()
            for user in users:
                # 是否是登录 如果flag=True表示匹配,否则密码不匹配
                flag = check_password_hash(user.password, password)
                if flag:
                    # 1.cookie
                    # response = redirect(url_for('user.index'))
                    # response.set_cookie('uid', str(user.id), max_age=1800)
                    # return response
                    # 2.session
                    session['uid'] = user.id
                    return redirect(url_for('user.index'))
            else:
                return render_template('user/login.html', msg='用户名或者有误')
        elif f == 2:  # 验证码
            pass

    return render_template('user/login.html')


# 发送短信息
@user_bp1.route('/sendMsg')
def send_message():
    phone = request.args.get('phone')
    SECRET_ID = "xxx"  # 产品密钥ID，产品标识
    SECRET_KEY = "xxx"  # 产品私有密钥，服务端生成签名信息使用，请严格保管，避免泄露
    BUSINESS_ID = "xxx"  # 业务ID，易盾根据产品业务特点分配
    api = SmsSendAPIDemo(SECRET_ID, SECRET_KEY, BUSINESS_ID)
    SmsSendAPIDemo()

# 退出 删除cookie
@user_bp1.route('/logout')
def logout():
    # 1. cookie的方式
    # response = redirect(url_for('user.index'))
    # 通过response对象的delete_cookie(key),key就是要删除的cookie的key
    # response.delete_cookie('uid')   # 删除谁放谁
    # 2. session的方式
    # del session['uid']
    session.clear()
    return redirect(url_for('user.index'))
