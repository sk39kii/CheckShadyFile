# -*- coding: utf-8 -*-

u"""通知用メソッドを集めたユーティリティ."""


class NoticeUtil(object):
    u"""通知ユーティリティクラス."""

    # * 通知データの受け取り
    # * 通知方法(メール)

    # 自クラスのインスタンス
    _instance = None

    @classmethod
    def __new__(cls, *args, **kwargs):
        u"""自クラスのインスタンス生成."""
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self):
        u"""__init__ メソッド."""
        pass

    def mail_notice(self):
        u"""メールで通知."""
        pass

    def slack_notice(self):
        u"""Slackに通知."""
        pass


def main():
    u"""処理呼び出し."""
    pass

if __name__ == '__main__':
    main()
