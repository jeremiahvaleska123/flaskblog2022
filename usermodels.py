from datetime import datetime

from exts import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(100), nullable=False)  # 64->100
    phone = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(30))
    icon = db.Column(db.String(100))
    isdelete = db.Column(db.Boolean, default=False)
    rdatetime = db.Column(db.DateTime, default=datetime.now)
    # 增加一个字段 不是数据库层面不用迁移
    articles = db.relationship('Article', backref='user') # 通过文章找user

    def __str__(self):
        return self.username
