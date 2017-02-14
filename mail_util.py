# -*- coding: utf-8 -*-

u"""メール送信ユーティリティ."""

import smtplib

from email.Header import Header
from email.MIMEText import MIMEText
from email.Utils import formatdate


class MailUtil(object):
    u"""メール送信ユーティリティクラス."""

    SMTP_OP25B_PORT = 587

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
        self.default_encode = "utf-8"
        self.msgbody_encode = "ISO-2022-JP"

    def __create_message_info(self, from_addr, to_addr, subject, text):
        u"""メッセージ情報を作成する.

        Args:
            from_addr: 送信元アドレス
            to_addr: 送信先アドレス(複数の場合はカンマ区切り)
            subject: 件名
            text: メッセージ内容
        Returns:
            to_addr_list: 送信先アドレスのリスト
            msg_string: メッセージ
        """
        # 件名がstrデータの場合unicode化する
        subject = self.if_str_to_unicode(subject, self.default_encode)

        # 改行・タブを変換
        text = text.replace(r'\n', '\n')
        text = text.replace(r'\t', '\t')
        text = self.if_str_to_unicode(text, self.default_encode)

        # charset = "ISO-2022-JP"
        charset = self.msgbody_encode
        msg = MIMEText(text.encode(charset), "plain", charset)
        msg["Subject"] = Header(subject, charset)
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Date"] = formatdate(localtime=True)

        to_addr_list = to_addr
        if to_addr.find(',') > -1:
            to_addr_list = to_addr.split(',')

        return to_addr_list, msg.as_string()

    def send(self, *args):
        u"""メール通知.

        Args:
            *args: メール送信情報のリスト
            [smtpsvr、from_addr, to_addr, subject, text]
        Returns:
        """
        try:
            smtpsvr, from_addr, to_addr, subject, text = args

            # メッセージ情報の作成
            to_addr_list, msg_string = self.__create_message_info(
                from_addr, to_addr, subject, text
            )
            smtp = smtplib.SMTP(smtpsvr)
            smtp.sendmail(from_addr, to_addr_list, msg_string)
            smtp.close()
        except Exception:
            raise

    def send_op25b(self, *args):
        u"""OP25Bでサブミッションポート(587)を利用している環境でメール送信する.

        Args:
            *args: メール送信情報のリスト
            [port, user, pass, smtp, from_addr, to_addr, sbj, text]
        Returns:
        """
        try:
            port, login, passwd, smtp, from_addr, to_addr, sbj, text = args

            # メッセージ情報の作成
            to_addr_list, msg_string = self.__create_message_info(
                from_addr, to_addr, sbj, text
            )

            # ポート587指定
            if port is None or port == 0:
                port = self.SMTP_OP25B_PORT

            smtp = smtplib.SMTP(smtp, port)
            smtp.ehlo()
            # SSL開始
            smtp.starttls()
            smtp.ehlo()
            # ログイン
            smtp.login(login, passwd)
            smtp.sendmail(from_addr, to_addr_list, msg_string)
            smtp.close()
        except Exception:
            raise

    @staticmethod
    def if_str_to_unicode(value, encode):
        u"""値がstrの場合unicodeに変換する.

        Args:
            value: 対象の値
            encode: unicodeに変換する際に使用するエンコード
        Returns:
            変換後にunicodeデータ
        """
        if isinstance(value, str):
            value = unicode(value, encode)
        return value


def main():
    u"""処理呼び出し."""
    import sys
    param = sys.argv
    paramcnt = len(param)
    if paramcnt >= 5:
        smtpsvr = param[1]
        from_addr = param[2]
        to_addr = param[3]
        subject = param[4]
        text = param[5]
        obj = MailUtil()
        obj.send(smtpsvr, from_addr, to_addr, subject, text)

if __name__ == "__main__":
    main()
